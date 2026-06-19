// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package compiler

import (
	"sort"
	"strings"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/policy"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const (
	schedulerGuardOnMissingRun             = "run"
	schedulerGuardOperatorCIDRContains     = policyruntime.Operator("cidr_contains")
	schedulerGuardOperatorEQ               = policyruntime.Operator("eq")
	schedulerGuardOperatorExists           = policyruntime.Operator("exists")
	schedulerGuardOperatorIn               = policyruntime.Operator("in")
	schedulerGuardOperatorIs               = policyruntime.Operator("is")
	schedulerGuardOperatorNE               = policyruntime.Operator("ne")
	schedulerGuardOperatorNotIn            = policyruntime.Operator("not_in")
	schedulerGuardOperatorWithinTimeWindow = policyruntime.Operator("within_time_window")
)

type schedulerGuardCriterionPath struct {
	hasUserControlled bool
	hasServerDerived  bool
}

func compileSchedulerGuards(
	configs map[string]config.PolicySchedulerGuardConfig,
	attributes map[string]policyregistry.AttributeDefinition,
	sets policyruntime.CompiledSets,
) (map[string]policyruntime.CompiledSchedulerGuard, error) {
	if len(configs) == 0 {
		return nil, nil
	}

	guards := make(map[string]policyruntime.CompiledSchedulerGuard, len(configs))
	for _, name := range sortedSchedulerGuardNames(configs) {
		path := childPath("auth.policy.scheduler_guards", name)

		guard, err := compileSchedulerGuard(name, configs[name], path, attributes, sets)
		if err != nil {
			return nil, err
		}

		guards[name] = guard
	}

	return guards, nil
}

func sortedSchedulerGuardNames(configs map[string]config.PolicySchedulerGuardConfig) []string {
	names := make([]string, 0, len(configs))
	for name := range configs {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}

func compileSchedulerGuard(
	name string,
	guardConfig config.PolicySchedulerGuardConfig,
	path string,
	attributes map[string]policyregistry.AttributeDefinition,
	sets policyruntime.CompiledSets,
) (policyruntime.CompiledSchedulerGuard, error) {
	if !simpleIdentifierPattern.MatchString(name) {
		return policyruntime.CompiledSchedulerGuard{}, configPathError(path, "must be a simple scheduler guard name")
	}

	onMissingAttribute, err := compileSchedulerGuardOnMissingAttribute(guardConfig.OnMissingAttribute, childPath(path, "on_missing_attribute"))
	if err != nil {
		return policyruntime.CompiledSchedulerGuard{}, err
	}

	root, err := compileConditionWithOptions(guardConfig.If, childPath(path, "if"), schedulerGuardTypeCheckContext(attributes, sets), schedulerGuardConditionOptions())
	if err != nil {
		return policyruntime.CompiledSchedulerGuard{}, err
	}

	if err := validateSchedulerGuardUserControlledCriteria(root, childPath(path, "if")); err != nil {
		return policyruntime.CompiledSchedulerGuard{}, err
	}

	return policyruntime.CompiledSchedulerGuard{
		Root:               root,
		OnMissingAttribute: onMissingAttribute,
	}, nil
}

func compileSchedulerGuardOnMissingAttribute(value string, path string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return schedulerGuardOnMissingRun, nil
	}

	if value != schedulerGuardOnMissingRun {
		return "", configPathError(path, "must be run")
	}

	return value, nil
}

func schedulerGuardTypeCheckContext(
	attributes map[string]policyregistry.AttributeDefinition,
	sets policyruntime.CompiledSets,
) typeCheckContext {
	return typeCheckContext{
		sets:       sets,
		stage:      policy.StagePreAuth,
		operations: schedulerGuardOperations(),
		attributes: attributes,
	}
}

func schedulerGuardOperations() []policy.Operation {
	return []policy.Operation{
		policy.OperationAuthenticate,
		policy.OperationLookupIdentity,
		policy.OperationListAccounts,
	}
}

func schedulerGuardConditionOptions() conditionCompileOptions {
	return conditionCompileOptions{
		validateAttribute: validateSchedulerGuardAttribute,
		validateOperator:  validateSchedulerGuardOperator,
	}
}

func validateSchedulerGuardAttribute(
	_ config.PolicyConditionConfig,
	definition policyregistry.AttributeDefinition,
	path string,
	_ typeCheckContext,
) error {
	if definition.Source == policyregistry.SourceLua || schedulerGuardLuaProducedAttribute(definition.ID) {
		return configPathError(path, "must not reference Lua-produced attributes")
	}

	if definition.ProducerCheck != "" || len(definition.ProducerTypes) > 0 {
		return configPathError(path, "must not reference check-produced attributes")
	}

	if !schedulerGuardRequestAttribute(definition.ID) {
		return configPathError(path, "must reference a request attribute")
	}

	return nil
}

func schedulerGuardRequestAttribute(attributeID string) bool {
	return strings.HasPrefix(attributeID, "request.")
}

func schedulerGuardLuaProducedAttribute(attributeID string) bool {
	return strings.HasPrefix(attributeID, "auth.lua.")
}

func validateSchedulerGuardOperator(
	operator policyruntime.Operator,
	valueType policyregistry.AttributeType,
	path string,
) error {
	switch operator {
	case schedulerGuardOperatorExists:
		return nil
	case schedulerGuardOperatorIs,
		schedulerGuardOperatorEQ,
		schedulerGuardOperatorNE,
		schedulerGuardOperatorIn,
		schedulerGuardOperatorNotIn:
		if valueType == policyregistry.AttributeTypeBool || valueType == policyregistry.AttributeTypeString {
			return nil
		}

		return configPathError(childPath(path, string(operator)), "requires a boolean or string scheduler guard attribute")
	case schedulerGuardOperatorCIDRContains:
		if valueType == policyregistry.AttributeTypeIP || valueType == policyregistry.AttributeTypeCIDR {
			return nil
		}

		return configPathError(childPath(path, string(operator)), "requires an IP or CIDR scheduler guard attribute")
	case schedulerGuardOperatorWithinTimeWindow:
		if valueType == policyregistry.AttributeTypeDateTime {
			return nil
		}

		return configPathError(childPath(path, string(operator)), "requires a datetime scheduler guard attribute")
	default:
		return configPathError(childPath(path, string(operator)), "is not supported for scheduler guards")
	}
}

func validateSchedulerGuardUserControlledCriteria(root policyruntime.CompiledExpr, path string) error {
	for _, criterionPath := range schedulerGuardCriterionPaths(root) {
		if criterionPath.hasUserControlled && !criterionPath.hasServerDerived {
			return configPathError(path, "must combine user-controlled request values with a server-derived scheduler criterion")
		}
	}

	return nil
}

func schedulerGuardCriterionPaths(expr policyruntime.CompiledExpr) []schedulerGuardCriterionPath {
	switch expr.Kind {
	case policyruntime.ExprKindAttribute:
		if schedulerGuardUserControlledAttribute(expr.AttributeID) {
			return []schedulerGuardCriterionPath{{hasUserControlled: true}}
		}

		return []schedulerGuardCriterionPath{{hasServerDerived: true}}
	case policyruntime.ExprKindAll:
		return schedulerGuardAllCriterionPaths(expr.Children)
	case policyruntime.ExprKindAny:
		return schedulerGuardAnyCriterionPaths(expr.Children)
	case policyruntime.ExprKindNot:
		if len(expr.Children) == 0 {
			return []schedulerGuardCriterionPath{{}}
		}

		return schedulerGuardCriterionPaths(expr.Children[0])
	default:
		return []schedulerGuardCriterionPath{{}}
	}
}

func schedulerGuardAllCriterionPaths(children []policyruntime.CompiledExpr) []schedulerGuardCriterionPath {
	paths := []schedulerGuardCriterionPath{{}}
	for _, child := range children {
		paths = combineSchedulerGuardCriterionPaths(paths, schedulerGuardCriterionPaths(child))
	}

	return paths
}

func schedulerGuardAnyCriterionPaths(children []policyruntime.CompiledExpr) []schedulerGuardCriterionPath {
	paths := make([]schedulerGuardCriterionPath, 0, len(children))
	for _, child := range children {
		paths = append(paths, schedulerGuardCriterionPaths(child)...)
	}

	return paths
}

func combineSchedulerGuardCriterionPaths(
	left []schedulerGuardCriterionPath,
	right []schedulerGuardCriterionPath,
) []schedulerGuardCriterionPath {
	combined := make([]schedulerGuardCriterionPath, 0, len(left)*len(right))
	for _, leftPath := range left {
		for _, rightPath := range right {
			combined = append(combined, schedulerGuardCriterionPath{
				hasUserControlled: leftPath.hasUserControlled || rightPath.hasUserControlled,
				hasServerDerived:  leftPath.hasServerDerived || rightPath.hasServerDerived,
			})
		}
	}

	return combined
}

func schedulerGuardUserControlledAttribute(attributeID string) bool {
	return strings.HasPrefix(attributeID, "request.header.") ||
		strings.HasPrefix(attributeID, "request.local.") ||
		strings.HasPrefix(attributeID, "request.metadata.") ||
		attributeID == policy.AttributeRequestIDPClientID ||
		attributeID == policy.AttributeRequestSAMLServiceProviderID
}

func validateCheckSchedulerGuards(
	checks []policyruntime.CompiledCheck,
	guards map[string]policyruntime.CompiledSchedulerGuard,
) error {
	if err := validateKnownCheckSchedulerGuards(checks, guards); err != nil {
		return err
	}

	return validateAfterSchedulerGuardCompatibility(checks)
}

func validateKnownCheckSchedulerGuards(
	checks []policyruntime.CompiledCheck,
	guards map[string]policyruntime.CompiledSchedulerGuard,
) error {
	for checkIndex, check := range checks {
		for guardIndex, guardName := range check.SkipIf {
			if _, ok := guards[guardName]; !ok {
				path := indexedPath(childPath(indexedPath("auth.policy.checks", checkIndex), "skip_if"), guardIndex)

				return configPathError(path, "references unknown scheduler guard")
			}
		}
	}

	return nil
}

func validateAfterSchedulerGuardCompatibility(checks []policyruntime.CompiledCheck) error {
	byName := make(map[string]policyruntime.CompiledCheck, len(checks))
	for _, check := range checks {
		byName[check.Name] = check
	}

	for _, check := range checks {
		for index, dependencyName := range check.After {
			dependency, ok := byName[dependencyName]
			if !ok {
				continue
			}

			if err := validateDependencySchedulerGuards(check, dependency, indexedPath("auth.policy.checks."+check.Name+".after", index)); err != nil {
				return err
			}
		}
	}

	return nil
}

func validateDependencySchedulerGuards(
	check policyruntime.CompiledCheck,
	dependency policyruntime.CompiledCheck,
	path string,
) error {
	for _, guardName := range dependency.SkipIf {
		if !stringsContain(check.SkipIf, guardName) {
			return configPathError(path, "must include scheduler guards used by the dependency")
		}
	}

	return nil
}
