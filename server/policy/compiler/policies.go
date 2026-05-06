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
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/policy"
	policyregistry "github.com/croessner/nauthilus/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"
)

type compilePolicyInput struct {
	sets        policyruntime.CompiledSets
	configs     []config.PolicyRuleConfig
	checks      []policyruntime.CompiledCheck
	attributes  map[string]policyregistry.AttributeDefinition
	fsmEvents   map[string]policyruntime.FSMEventDefinition
	responses   map[string]policyruntime.ResponseDefinition
	obligations map[string]policyruntime.EffectDefinition
	advice      map[string]policyruntime.EffectDefinition
}

func compilePolicies(input compilePolicyInput) ([]policyruntime.CompiledPolicy, error) {
	policies := make([]policyruntime.CompiledPolicy, 0, len(input.configs))
	for index, policyConfig := range input.configs {
		path := indexedPath("auth.policy.policies", index)
		compiled, err := compilePolicy(policyConfig, path, input)
		if err != nil {
			return nil, err
		}

		policies = append(policies, compiled)
	}

	return policies, nil
}

func compilePolicy(
	policyConfig config.PolicyRuleConfig,
	path string,
	input compilePolicyInput,
) (policyruntime.CompiledPolicy, error) {
	if strings.TrimSpace(policyConfig.Name) == "" {
		return policyruntime.CompiledPolicy{}, configPathError(childPath(path, "name"), "must not be empty")
	}

	stage := policy.Stage(policyConfig.Stage)
	if !stageValid(stage) {
		return policyruntime.CompiledPolicy{}, configPathError(childPath(path, "stage"), "is invalid")
	}

	operations, err := compileOperations(policyConfig.Operations, []policy.Operation{policy.OperationAuthenticate}, childPath(path, "operations"))
	if err != nil {
		return policyruntime.CompiledPolicy{}, err
	}

	checksByName := checksByName(input.checks)
	if err := validateRequiredChecks(policyConfig.RequireChecks, operations, stage, checksByName, childPath(path, "require_checks")); err != nil {
		return policyruntime.CompiledPolicy{}, err
	}

	root, err := compileCondition(policyConfig.If, childPath(path, "if"), typeCheckContext{
		stage:         stage,
		operations:    operations,
		requireChecks: policyConfig.RequireChecks,
		checksByName:  checksByName,
		attributes:    input.attributes,
		sets:          input.sets,
	})
	if err != nil {
		return policyruntime.CompiledPolicy{}, err
	}

	then, err := compileDecision(policyConfig.Then, stage, childPath(path, "then"), input)
	if err != nil {
		return policyruntime.CompiledPolicy{}, err
	}

	return policyruntime.CompiledPolicy{
		Name:          policyConfig.Name,
		Stage:         stage,
		Operations:    operations,
		RequireChecks: append([]string(nil), policyConfig.RequireChecks...),
		Root:          root,
		Then:          then,
	}, nil
}

func checksByName(checks []policyruntime.CompiledCheck) map[string]policyruntime.CompiledCheck {
	byName := make(map[string]policyruntime.CompiledCheck, len(checks))
	for _, check := range checks {
		byName[check.Name] = check
	}

	return byName
}

func validateRequiredChecks(
	requireChecks []string,
	operations []policy.Operation,
	stage policy.Stage,
	checks map[string]policyruntime.CompiledCheck,
	path string,
) error {
	for index, checkName := range requireChecks {
		check, ok := checks[checkName]
		if !ok {
			return configPathError(indexedPath(path, index), fmt.Sprintf("references unknown check %q", checkName))
		}

		if stageOrder(check.Stage) > stageOrder(stage) {
			return configPathError(indexedPath(path, index), "references a future-stage check")
		}

		if !operationsIntersect(operations, check.Operations) {
			return configPathError(indexedPath(path, index), "is not enabled for this policy operation")
		}
	}

	return nil
}

type typeCheckContext struct {
	sets          policyruntime.CompiledSets
	stage         policy.Stage
	operations    []policy.Operation
	requireChecks []string
	checksByName  map[string]policyruntime.CompiledCheck
	attributes    map[string]policyregistry.AttributeDefinition
}

func compileCondition(
	condition config.PolicyConditionConfig,
	path string,
	ctx typeCheckContext,
) (policyruntime.CompiledExpr, error) {
	kind, err := conditionKind(condition, path)
	if err != nil {
		return policyruntime.CompiledExpr{}, err
	}

	switch kind {
	case policyruntime.ExprKindAttribute:
		return compileAttributeCondition(condition, path, ctx)
	case policyruntime.ExprKindAll:
		children := make([]policyruntime.CompiledExpr, 0, len(condition.All))
		for index, child := range condition.All {
			compiled, err := compileCondition(child, indexedPath(childPath(path, "all"), index), ctx)
			if err != nil {
				return policyruntime.CompiledExpr{}, err
			}

			children = append(children, compiled)
		}

		return policyruntime.CompiledExpr{Kind: policyruntime.ExprKindAll, Children: children}, nil
	case policyruntime.ExprKindAny:
		children := make([]policyruntime.CompiledExpr, 0, len(condition.Any))
		for index, child := range condition.Any {
			compiled, err := compileCondition(child, indexedPath(childPath(path, "any"), index), ctx)
			if err != nil {
				return policyruntime.CompiledExpr{}, err
			}

			children = append(children, compiled)
		}

		return policyruntime.CompiledExpr{Kind: policyruntime.ExprKindAny, Children: children}, nil
	case policyruntime.ExprKindNot:
		compiled, err := compileCondition(*condition.Not, childPath(path, "not"), ctx)
		if err != nil {
			return policyruntime.CompiledExpr{}, err
		}

		return policyruntime.CompiledExpr{Kind: policyruntime.ExprKindNot, Children: []policyruntime.CompiledExpr{compiled}}, nil
	case policyruntime.ExprKindAlways:
		return policyruntime.CompiledExpr{Kind: policyruntime.ExprKindAlways}, nil
	default:
		return policyruntime.CompiledExpr{}, configPathError(path, "must contain exactly one expression node")
	}
}

func conditionKind(condition config.PolicyConditionConfig, path string) (policyruntime.ExprKind, error) {
	count := 0
	var kind policyruntime.ExprKind

	if condition.Attribute != "" {
		count++
		kind = policyruntime.ExprKindAttribute
	}

	if condition.All != nil {
		if len(condition.All) == 0 {
			return "", configPathError(childPath(path, "all"), "must contain at least one child")
		}

		count++
		kind = policyruntime.ExprKindAll
	}

	if condition.Any != nil {
		if len(condition.Any) == 0 {
			return "", configPathError(childPath(path, "any"), "must contain at least one child")
		}

		count++
		kind = policyruntime.ExprKindAny
	}

	if condition.Not != nil {
		count++
		kind = policyruntime.ExprKindNot
	}

	if condition.Always != nil {
		if !*condition.Always {
			return "", configPathError(childPath(path, "always"), "must be true")
		}

		count++
		kind = policyruntime.ExprKindAlways
	}

	if condition.Detail != "" && condition.Attribute == "" {
		return "", configPathError(childPath(path, "detail"), "may only appear with attribute")
	}

	if count != 1 {
		return "", configPathError(path, "must contain exactly one expression node")
	}

	return kind, nil
}

func compileAttributeCondition(
	condition config.PolicyConditionConfig,
	path string,
	ctx typeCheckContext,
) (policyruntime.CompiledExpr, error) {
	definition, ok := ctx.attributes[condition.Attribute]
	if !ok {
		return policyruntime.CompiledExpr{}, configPathError(childPath(path, "attribute"), "references unknown attribute")
	}

	valueType := definition.Type
	if condition.Detail != "" {
		detail, ok := definition.Details[condition.Detail]
		if !ok {
			return policyruntime.CompiledExpr{}, configPathError(childPath(path, "detail"), "references unknown detail")
		}

		valueType = detail.Type
	}

	if stageOrder(definition.Stage) > stageOrder(ctx.stage) {
		return policyruntime.CompiledExpr{}, configPathError(childPath(path, "attribute"), "references a future-stage attribute")
	}

	if !operationsIntersect(ctx.operations, definition.Operations) {
		return policyruntime.CompiledExpr{}, configPathError(childPath(path, "attribute"), "cannot be emitted for this policy operation")
	}

	if err := validateProducerPlan(definition, ctx, childPath(path, "attribute")); err != nil {
		return policyruntime.CompiledExpr{}, err
	}

	operator, rawValue, err := selectedOperator(condition, path)
	if err != nil {
		return policyruntime.CompiledExpr{}, err
	}

	expected, err := compileExpectedValue(operator, rawValue, valueType, ctx.sets, path)
	if err != nil {
		return policyruntime.CompiledExpr{}, err
	}

	return policyruntime.CompiledExpr{
		Kind:        policyruntime.ExprKindAttribute,
		AttributeID: condition.Attribute,
		Detail:      condition.Detail,
		Operator:    operator,
		Expected:    expected,
		ValueType:   valueType,
	}, nil
}

func validateProducerPlan(
	definition policyregistry.AttributeDefinition,
	ctx typeCheckContext,
	path string,
) error {
	if definition.ProducerCheck != "" {
		check, ok := ctx.checksByName[definition.ProducerCheck]
		if !ok || !operationsIntersect(ctx.operations, check.Operations) {
			return configPathError(path, "requires the producing check in the active check plan")
		}

		if definition.Stage == ctx.stage && !stringsContain(ctx.requireChecks, definition.ProducerCheck) {
			return configPathError(path, "requires the producing check in require_checks")
		}

		return nil
	}

	if len(definition.ProducerTypes) == 0 {
		return nil
	}

	hasActiveProducer := false
	hasRequiredProducer := false
	for _, checkName := range ctx.requireChecks {
		check, ok := ctx.checksByName[checkName]
		if !ok {
			continue
		}

		if check.Stage == definition.Stage && stringsContain(definition.ProducerTypes, check.Type) && operationsIntersect(ctx.operations, check.Operations) {
			hasRequiredProducer = true

			break
		}
	}

	for _, check := range ctx.checksByName {
		if check.Stage == definition.Stage && stringsContain(definition.ProducerTypes, check.Type) && operationsIntersect(ctx.operations, check.Operations) {
			hasActiveProducer = true

			break
		}
	}

	if !hasActiveProducer {
		return configPathError(path, "requires a producing check in the active check plan")
	}

	if definition.Stage == ctx.stage && !hasRequiredProducer {
		return configPathError(path, "requires a producing check in require_checks")
	}

	return nil
}

func selectedOperator(
	condition config.PolicyConditionConfig,
	path string,
) (policyruntime.Operator, any, error) {
	candidates := []struct {
		name    string
		value   any
		present bool
	}{
		{name: "is", value: condition.Is, present: condition.Is != nil},
		{name: "eq", value: condition.Eq, present: condition.Eq != nil},
		{name: "ne", value: condition.Ne, present: condition.Ne != nil},
		{name: "in", value: condition.In, present: condition.In != nil},
		{name: "not_in", value: condition.NotIn, present: condition.NotIn != nil},
		{name: "matches", value: condition.Matches, present: condition.Matches != ""},
		{name: "exists", value: condition.Exists, present: condition.Exists != nil},
		{name: "contains", value: condition.Contains, present: condition.Contains != nil},
		{name: "contains_any", value: condition.ContainsAny, present: condition.ContainsAny != nil},
		{name: "contains_all", value: condition.ContainsAll, present: condition.ContainsAll != nil},
		{name: "contains_none", value: condition.ContainsNone, present: condition.ContainsNone != nil},
		{name: "gt", value: condition.GT, present: condition.GT != nil},
		{name: "gte", value: condition.GTE, present: condition.GTE != nil},
		{name: "lt", value: condition.LT, present: condition.LT != nil},
		{name: "lte", value: condition.LTE, present: condition.LTE != nil},
		{name: "cidr_contains", value: condition.CIDRContains, present: condition.CIDRContains != ""},
		{name: "within_time_window", value: condition.WithinTimeWindow, present: condition.WithinTimeWindow != ""},
	}

	var selected string
	var value any
	count := 0
	for _, candidate := range candidates {
		if !candidate.present {
			continue
		}

		count++
		selected = candidate.name
		value = candidate.value
	}

	if count != 1 {
		return "", nil, configPathError(path, "must contain exactly one operator")
	}

	if selected == "exists" {
		if ptr, ok := value.(*bool); ok {
			value = *ptr
		}
	}

	return policyruntime.Operator(selected), value, nil
}

func compileExpectedValue(
	operator policyruntime.Operator,
	rawValue any,
	valueType policyregistry.AttributeType,
	sets policyruntime.CompiledSets,
	path string,
) (policyruntime.TypedValue, error) {
	switch operator {
	case "exists":
		return compileExistsValue(operator, rawValue, path)
	case "matches":
		return compilePatternValue(operator, rawValue, valueType, path)
	case "in", "not_in":
		return compileMembershipValue(operator, rawValue, valueType, path)
	case "contains":
		return compileContainsValue(operator, rawValue, valueType, path)
	case "contains_any", "contains_all", "contains_none":
		return compileContainsListValue(operator, rawValue, valueType, path)
	case "cidr_contains":
		if valueType != policyregistry.AttributeTypeIP && valueType != policyregistry.AttributeTypeCIDR {
			return policyruntime.TypedValue{}, configPathError(childPath(path, string(operator)), "requires an IP or CIDR attribute")
		}

		return compileNetworkOperand(rawValue, sets, childPath(path, string(operator)))
	case "within_time_window":
		if valueType != policyregistry.AttributeTypeDateTime {
			return policyruntime.TypedValue{}, configPathError(childPath(path, string(operator)), "requires a datetime attribute")
		}

		return compileTimeWindowOperand(rawValue, sets, childPath(path, string(operator)))
	case "gt", "gte", "lt", "lte":
		if valueType != policyregistry.AttributeTypeNumber && valueType != policyregistry.AttributeTypeDateTime {
			return policyruntime.TypedValue{}, configPathError(childPath(path, string(operator)), "requires a comparable attribute")
		}
	}

	return compileScalarValue(operator, rawValue, valueType, path)
}

func compileExistsValue(operator policyruntime.Operator, rawValue any, path string) (policyruntime.TypedValue, error) {
	value, ok := rawValue.(bool)
	if !ok {
		return policyruntime.TypedValue{}, configPathError(childPath(path, string(operator)), "must be a boolean")
	}

	return policyruntime.TypedValue{Value: value}, nil
}

func compilePatternValue(
	operator policyruntime.Operator,
	rawValue any,
	valueType policyregistry.AttributeType,
	path string,
) (policyruntime.TypedValue, error) {
	if valueType != policyregistry.AttributeTypeString {
		return policyruntime.TypedValue{}, configPathError(childPath(path, string(operator)), "requires a string attribute")
	}

	pattern, ok := rawValue.(string)
	if !ok {
		return policyruntime.TypedValue{}, configPathError(childPath(path, string(operator)), "must be a string")
	}

	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return policyruntime.TypedValue{}, configPathError(childPath(path, string(operator)), "must compile as a regular expression")
	}

	return policyruntime.TypedValue{Value: compiled}, nil
}

func compileMembershipValue(
	operator policyruntime.Operator,
	rawValue any,
	valueType policyregistry.AttributeType,
	path string,
) (policyruntime.TypedValue, error) {
	if valueType == policyregistry.AttributeTypeStringList {
		return policyruntime.TypedValue{}, configPathError(childPath(path, string(operator)), "requires a scalar attribute")
	}

	values, ok := rawValue.([]any)
	if !ok {
		return policyruntime.TypedValue{}, configPathError(childPath(path, string(operator)), "must be a list")
	}

	return compileListValue(operator, values, valueType, path)
}

func compileContainsValue(
	operator policyruntime.Operator,
	rawValue any,
	valueType policyregistry.AttributeType,
	path string,
) (policyruntime.TypedValue, error) {
	if valueType != policyregistry.AttributeTypeStringList {
		return policyruntime.TypedValue{}, configPathError(childPath(path, string(operator)), "requires a list attribute")
	}

	value, ok := rawValue.(string)
	if !ok {
		return policyruntime.TypedValue{}, configPathError(childPath(path, string(operator)), "must be a string")
	}

	return policyruntime.TypedValue{Value: value}, nil
}

func compileContainsListValue(
	operator policyruntime.Operator,
	rawValue any,
	valueType policyregistry.AttributeType,
	path string,
) (policyruntime.TypedValue, error) {
	if valueType != policyregistry.AttributeTypeStringList {
		return policyruntime.TypedValue{}, configPathError(childPath(path, string(operator)), "requires a list attribute")
	}

	values, ok := rawValue.([]any)
	if !ok {
		return policyruntime.TypedValue{}, configPathError(childPath(path, string(operator)), "must be a list")
	}

	return compileStringList(operator, values, path)
}

func compileScalarValue(
	operator policyruntime.Operator,
	rawValue any,
	valueType policyregistry.AttributeType,
	path string,
) (policyruntime.TypedValue, error) {
	return compileScalarValueAtPath(rawValue, valueType, childPath(path, string(operator)))
}

func compileScalarValueAtPath(
	rawValue any,
	valueType policyregistry.AttributeType,
	path string,
) (policyruntime.TypedValue, error) {
	switch valueType {
	case policyregistry.AttributeTypeBool:
		return compileBoolValue(rawValue, path)
	case policyregistry.AttributeTypeString:
		return compileStringValue(rawValue, path)
	case policyregistry.AttributeTypeNumber:
		return compileNumberValue(rawValue, path)
	case policyregistry.AttributeTypeIP:
		return compileIPValue(rawValue, path)
	case policyregistry.AttributeTypeCIDR:
		return compileCIDRValue(rawValue, path)
	case policyregistry.AttributeTypeDateTime:
		return compileDateTimeValue(rawValue, path)
	case policyregistry.AttributeTypeStringList:
		return compileStringListAtPath(rawValue, path)
	default:
		return policyruntime.TypedValue{}, configPathError(path, "has unsupported attribute type")
	}
}

func compileBoolValue(rawValue any, path string) (policyruntime.TypedValue, error) {
	value, ok := rawValue.(bool)
	if !ok {
		return policyruntime.TypedValue{}, configPathError(path, "must be a boolean")
	}

	return policyruntime.TypedValue{Value: value}, nil
}

func compileStringValue(rawValue any, path string) (policyruntime.TypedValue, error) {
	value, ok := rawValue.(string)
	if !ok {
		return policyruntime.TypedValue{}, configPathError(path, "must be a string")
	}

	return policyruntime.TypedValue{Value: value}, nil
}

func compileNumberValue(rawValue any, path string) (policyruntime.TypedValue, error) {
	value, ok := rawValue.(float64)
	if ok {
		return policyruntime.TypedValue{Value: value}, nil
	}

	intValue, ok := rawValue.(int)
	if !ok {
		return policyruntime.TypedValue{}, configPathError(path, "must be a number")
	}

	return policyruntime.TypedValue{Value: float64(intValue)}, nil
}

func compileIPValue(rawValue any, path string) (policyruntime.TypedValue, error) {
	value, ok := rawValue.(string)
	if !ok {
		return policyruntime.TypedValue{}, configPathError(path, "must be an IP address string")
	}

	addr, err := netip.ParseAddr(value)
	if err != nil {
		return policyruntime.TypedValue{}, configPathError(path, "must be an IP address")
	}

	return policyruntime.TypedValue{Value: addr}, nil
}

func compileCIDRValue(rawValue any, path string) (policyruntime.TypedValue, error) {
	value, ok := rawValue.(string)
	if !ok {
		return policyruntime.TypedValue{}, configPathError(path, "must be a CIDR string")
	}

	prefix, err := parseNetworkPrefix(value)
	if err != nil {
		return policyruntime.TypedValue{}, configPathError(path, "must be a CIDR")
	}

	return policyruntime.TypedValue{Value: prefix}, nil
}

func compileDateTimeValue(rawValue any, path string) (policyruntime.TypedValue, error) {
	value, ok := rawValue.(string)
	if !ok {
		return policyruntime.TypedValue{}, configPathError(path, "must be a datetime string")
	}

	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return policyruntime.TypedValue{}, configPathError(path, "must be an RFC3339 timestamp")
	}

	return policyruntime.TypedValue{Value: parsed}, nil
}

func compileListValue(
	operator policyruntime.Operator,
	values []any,
	valueType policyregistry.AttributeType,
	path string,
) (policyruntime.TypedValue, error) {
	compiled := make([]any, 0, len(values))
	for index, value := range values {
		itemPath := indexedPath(childPath(path, string(operator)), index)
		item, err := compileScalarValueAtPath(value, valueType, itemPath)
		if err != nil {
			return policyruntime.TypedValue{}, err
		}

		compiled = append(compiled, item.Value)
	}

	return policyruntime.TypedValue{Value: compiled}, nil
}

func compileStringList(
	operator policyruntime.Operator,
	rawValue any,
	path string,
) (policyruntime.TypedValue, error) {
	return compileStringListAtPath(rawValue, childPath(path, string(operator)))
}

func compileStringListAtPath(rawValue any, path string) (policyruntime.TypedValue, error) {
	values, ok := rawValue.([]any)
	if !ok {
		return policyruntime.TypedValue{}, configPathError(path, "must be a list")
	}

	compiled := make([]string, 0, len(values))
	for index, value := range values {
		stringValue, ok := value.(string)
		if !ok {
			return policyruntime.TypedValue{}, configPathError(indexedPath(path, index), "must be a string")
		}

		compiled = append(compiled, stringValue)
	}

	return policyruntime.TypedValue{Value: compiled}, nil
}

func compileNetworkOperand(
	rawValue any,
	sets policyruntime.CompiledSets,
	path string,
) (policyruntime.TypedValue, error) {
	value, ok := rawValue.(string)
	if !ok {
		return policyruntime.TypedValue{}, configPathError(path, "must be a string")
	}

	if strings.HasPrefix(value, "@network.") {
		name := strings.TrimPrefix(value, "@network.")
		prefixes, ok := sets.Networks[name]
		if !ok {
			return policyruntime.TypedValue{}, configPathError(path, "references unknown network set")
		}

		return policyruntime.TypedValue{Value: append([]netip.Prefix(nil), prefixes...)}, nil
	}

	prefix, err := parseNetworkPrefix(value)
	if err != nil {
		return policyruntime.TypedValue{}, configPathError(path, "must be an IP address, CIDR, or network set reference")
	}

	return policyruntime.TypedValue{Value: []netip.Prefix{prefix}}, nil
}

func compileTimeWindowOperand(
	rawValue any,
	sets policyruntime.CompiledSets,
	path string,
) (policyruntime.TypedValue, error) {
	value, ok := rawValue.(string)
	if !ok {
		return policyruntime.TypedValue{}, configPathError(path, "must be a string")
	}

	if !strings.HasPrefix(value, "@time_window.") {
		return policyruntime.TypedValue{}, configPathError(path, "must reference a time-window set")
	}

	name := strings.TrimPrefix(value, "@time_window.")
	window, ok := sets.TimeWindows[name]
	if !ok {
		return policyruntime.TypedValue{}, configPathError(path, "references unknown time-window set")
	}

	return policyruntime.TypedValue{Value: window}, nil
}

func compileDecision(
	then config.PolicyThenConfig,
	stage policy.Stage,
	path string,
	input compilePolicyInput,
) (policyruntime.DecisionPlan, error) {
	decision := policy.Decision(then.Decision)
	if !decisionValid(decision) {
		return policyruntime.DecisionPlan{}, configPathError(childPath(path, "decision"), "is invalid")
	}

	if stage == policy.StagePreAuth && decision == policy.DecisionPermit {
		return policyruntime.DecisionPlan{}, configPathError(childPath(path, "decision"), "is not allowed in pre_auth")
	}

	fsmEventMarker := then.FSMEventMarker
	if fsmEventMarker == "" {
		fsmEventMarker = defaultFSMEventMarker(stage, decision)
	}

	if err := validateFSMMarker(fsmEventMarker, stage, input.fsmEvents, childPath(path, "fsm_event_marker")); err != nil {
		return policyruntime.DecisionPlan{}, err
	}

	responseMarker := then.ResponseMarker
	if responseMarker == "" {
		responseMarker = defaultResponseMarker(decision)
	}

	if err := validateResponseMarker(responseMarker, decision, input.responses, childPath(path, "response_marker")); err != nil {
		return policyruntime.DecisionPlan{}, err
	}

	responseMessage, err := compileResponseMessage(then.ResponseMessage, input.attributes, childPath(path, "response_message"))
	if err != nil {
		return policyruntime.DecisionPlan{}, err
	}

	obligations, err := compileEffectRequests(then.Obligations, input.obligations, childPath(path, "obligations"))
	if err != nil {
		return policyruntime.DecisionPlan{}, err
	}

	advice, err := compileEffectRequests(then.Advice, input.advice, childPath(path, "advice"))
	if err != nil {
		return policyruntime.DecisionPlan{}, err
	}

	return policyruntime.DecisionPlan{
		Decision:        decision,
		Reason:          then.Reason,
		OutcomeMarker:   then.OutcomeMarker,
		FSMEventMarker:  fsmEventMarker,
		ResponseMarker:  responseMarker,
		ResponseMessage: responseMessage,
		Obligations:     obligations,
		Advice:          advice,
		Control: policyruntime.DecisionControl{
			SkipRemainingStageChecks: then.Control.SkipRemainingStageChecks,
		},
	}, nil
}

func decisionValid(decision policy.Decision) bool {
	switch decision {
	case policy.DecisionNeutral,
		policy.DecisionDeny,
		policy.DecisionPermit,
		policy.DecisionTempFail:
		return true
	default:
		return false
	}
}

func defaultFSMEventMarker(stage policy.Stage, decision policy.Decision) string {
	switch stage {
	case policy.StagePreAuth:
		switch decision {
		case policy.DecisionNeutral:
			return policy.FSMEventMarkerPreAuthOK
		case policy.DecisionDeny:
			return policy.FSMEventMarkerPreAuthDeny
		case policy.DecisionTempFail:
			return policy.FSMEventMarkerPreAuthTempFail
		}
	case policy.StageAuthDecision:
		switch decision {
		case policy.DecisionPermit:
			return policy.FSMEventMarkerAuthPermit
		case policy.DecisionDeny:
			return policy.FSMEventMarkerAuthDeny
		case policy.DecisionTempFail:
			return policy.FSMEventMarkerAuthTempFail
		}
	}

	return ""
}

func defaultResponseMarker(decision policy.Decision) string {
	switch decision {
	case policy.DecisionPermit:
		return "auth.response.ok"
	case policy.DecisionDeny:
		return "auth.response.fail"
	case policy.DecisionTempFail:
		return "auth.response.tempfail"
	default:
		return ""
	}
}

func validateFSMMarker(
	marker string,
	stage policy.Stage,
	registry map[string]policyruntime.FSMEventDefinition,
	path string,
) error {
	if marker == "" {
		return nil
	}

	definition, ok := registry[marker]
	if !ok {
		return configPathError(path, "references unknown FSM event marker")
	}

	if !definition.PolicyVisible {
		return configPathError(path, "references an internal FSM event marker")
	}

	if definition.AllowedStage != stage {
		return configPathError(path, "is not valid for this policy stage")
	}

	return nil
}

func validateResponseMarker(
	marker string,
	decision policy.Decision,
	registry map[string]policyruntime.ResponseDefinition,
	path string,
) error {
	if marker == "" {
		return nil
	}

	definition, ok := registry[marker]
	if !ok {
		return configPathError(path, "references unknown response marker")
	}

	if definition.Effect != decision {
		return configPathError(path, "is not compatible with the selected decision")
	}

	if len(definition.Profiles) == 0 {
		return configPathError(path, "has no response profiles")
	}

	return nil
}

func compileResponseMessage(
	responseMessage config.PolicyResponseMessageConfig,
	attributes map[string]policyregistry.AttributeDefinition,
	path string,
) (policyruntime.ResponseMessagePlan, error) {
	source := strings.TrimSpace(responseMessage.From)
	if source == "" {
		if responseMessage.Text == "" && responseMessage.Attribute == "" && responseMessage.Detail == "" && responseMessage.Fallback == "" {
			return policyruntime.ResponseMessagePlan{Source: "default"}, nil
		}

		return policyruntime.ResponseMessagePlan{}, configPathError(path, "must set from when message fields are configured")
	}

	switch source {
	case "default":
		if responseMessage.Text != "" || responseMessage.Attribute != "" || responseMessage.Detail != "" || responseMessage.Fallback != "" {
			return policyruntime.ResponseMessagePlan{}, configPathError(path, "must not combine default with message fields")
		}

		return policyruntime.ResponseMessagePlan{Source: source}, nil
	case "literal":
		if responseMessage.Text == "" || responseMessage.Attribute != "" || responseMessage.Detail != "" {
			return policyruntime.ResponseMessagePlan{}, configPathError(path, "must contain only text for literal")
		}

		return policyruntime.ResponseMessagePlan{Source: source, Literal: responseMessage.Text}, nil
	case "attribute_detail":
		return compileAttributeResponseMessage(responseMessage, attributes, path)
	default:
		return policyruntime.ResponseMessagePlan{}, configPathError(childPath(path, "from"), "is invalid")
	}
}

func compileAttributeResponseMessage(
	responseMessage config.PolicyResponseMessageConfig,
	attributes map[string]policyregistry.AttributeDefinition,
	path string,
) (policyruntime.ResponseMessagePlan, error) {
	if responseMessage.Attribute == "" || responseMessage.Detail == "" || responseMessage.Text != "" {
		return policyruntime.ResponseMessagePlan{}, configPathError(path, "must contain attribute, detail, and optional fallback")
	}

	definition, ok := attributes[responseMessage.Attribute]
	if !ok {
		return policyruntime.ResponseMessagePlan{}, configPathError(childPath(path, "attribute"), "references unknown attribute")
	}

	detail, ok := definition.Details[responseMessage.Detail]
	if !ok {
		return policyruntime.ResponseMessagePlan{}, configPathError(childPath(path, "detail"), "references unknown detail")
	}

	if detail.Type != policyregistry.AttributeTypeString ||
		detail.Sensitivity != policyregistry.DetailSensitivityPublic ||
		detail.Purpose != policyregistry.DetailPurposeResponseMessage {
		return policyruntime.ResponseMessagePlan{}, configPathError(childPath(path, "detail"), "must be a public response_message string detail")
	}

	return policyruntime.ResponseMessagePlan{
		Source:      "attribute_detail",
		AttributeID: responseMessage.Attribute,
		Detail:      responseMessage.Detail,
		Fallback:    responseMessage.Fallback,
		MaxLength:   detail.MaxLength,
	}, nil
}

func compileEffectRequests(
	configs []config.PolicyEffectConfig,
	registry map[string]policyruntime.EffectDefinition,
	path string,
) ([]policyruntime.EffectRequest, error) {
	requests := make([]policyruntime.EffectRequest, 0, len(configs))
	for index, effectConfig := range configs {
		effectPath := indexedPath(path, index)
		if _, ok := registry[effectConfig.ID]; !ok {
			return nil, configPathError(childPath(effectPath, "id"), "references unknown registered effect")
		}

		args, err := compileEffectArgs(effectConfig.ID, effectConfig.Args, childPath(effectPath, "args"))
		if err != nil {
			return nil, err
		}

		requests = append(requests, policyruntime.EffectRequest{
			ID:   effectConfig.ID,
			Args: args,
		})
	}

	return requests, nil
}

func compileEffectArgs(id string, input map[string]any, path string) (map[string]any, error) {
	if id == policy.ObligationLuaActionDispatch {
		return compileLuaActionDispatchArgs(input, path)
	}

	args := make(map[string]any, len(input))
	for key, value := range input {
		args[key] = value
	}

	return args, nil
}

func compileLuaActionDispatchArgs(input map[string]any, path string) (map[string]any, error) {
	args := make(map[string]any, len(input))
	for key, value := range input {
		switch key {
		case policy.ObligationArgAction:
			actionName, ok := value.(string)
			if !ok {
				return nil, configPathError(childPath(path, key), "must be a string")
			}

			if !policy.LuaActionDispatchActionAllowed(actionName) {
				return nil, configPathError(childPath(path, key), "must be an allowed Lua action")
			}

			args[key] = actionName
		case policy.ObligationArgFeature:
			featureName, ok := value.(string)
			if !ok {
				return nil, configPathError(childPath(path, key), "must be a string")
			}

			args[key] = featureName
		case policy.ObligationArgWait:
			wait, ok := value.(bool)
			if !ok {
				return nil, configPathError(childPath(path, key), "must be a boolean")
			}

			args[key] = wait
		default:
			return nil, configPathError(childPath(path, key), "is not supported")
		}
	}

	if _, ok := args[policy.ObligationArgAction]; !ok {
		return nil, configPathError(childPath(path, policy.ObligationArgAction), "is required")
	}

	return args, nil
}
