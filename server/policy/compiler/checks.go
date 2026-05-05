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
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/policy"
	policyregistry "github.com/croessner/nauthilus/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"
)

func compileChecks(
	configChecks []config.PolicyCheckConfig,
	checkTypes map[string]policyruntime.CheckTypeDefinition,
	attributeRegistry *policyregistry.AttributeRegistry,
) ([]policyruntime.CompiledCheck, error) {
	checks := make([]policyruntime.CompiledCheck, 0, len(configChecks))
	seenNames := make(map[string]struct{}, len(configChecks))
	seenOutputs := make(map[string]struct{}, len(configChecks))

	for index, checkConfig := range configChecks {
		path := indexedPath("auth.policy.checks", index)
		check, err := compileCheck(checkConfig, path, checkTypes)
		if err != nil {
			return nil, err
		}

		if _, exists := seenNames[check.Name]; exists {
			return nil, configPathError(childPath(path, "name"), "must be unique")
		}
		seenNames[check.Name] = struct{}{}

		if check.Output != "" {
			if _, exists := seenOutputs[check.Output]; exists {
				return nil, configPathError(childPath(path, "output"), "must be unique")
			}

			seenOutputs[check.Output] = struct{}{}
		}

		if err := registerGeneratedLuaAttributes(check, attributeRegistry); err != nil {
			return nil, err
		}

		checks = append(checks, check)
	}

	if err := validateCheckDependencies(checks); err != nil {
		return nil, err
	}

	return checks, nil
}

func compileCheck(
	checkConfig config.PolicyCheckConfig,
	path string,
	checkTypes map[string]policyruntime.CheckTypeDefinition,
) (policyruntime.CompiledCheck, error) {
	if strings.TrimSpace(checkConfig.Name) == "" {
		return policyruntime.CompiledCheck{}, configPathError(childPath(path, "name"), "must not be empty")
	}

	definition, ok := checkTypes[checkConfig.Type]
	if !ok {
		return policyruntime.CompiledCheck{}, configPathError(childPath(path, "type"), "is invalid")
	}

	stage := policy.Stage(checkConfig.Stage)
	if !stageValid(stage) {
		return policyruntime.CompiledCheck{}, configPathError(childPath(path, "stage"), "is invalid")
	}

	if stage != definition.Stage {
		return policyruntime.CompiledCheck{}, configPathError(childPath(path, "stage"), "does not match the check type")
	}

	operations, err := compileOperations(checkConfig.Operations, definition.Operations, childPath(path, "operations"))
	if err != nil {
		return policyruntime.CompiledCheck{}, err
	}

	runIfAuthState := strings.TrimSpace(checkConfig.RunIf.AuthState)
	if runIfAuthState == "" {
		runIfAuthState = runIfAny
	}

	if !runIfAuthStateValid(runIfAuthState) {
		return policyruntime.CompiledCheck{}, configPathError(childPath(path, "run_if.auth_state"), "is invalid")
	}

	if checkConfig.ObserveSafe != nil && *checkConfig.ObserveSafe && !definition.ObserveSafeDefault && !definition.AllowsObserveSafeAssertion {
		return policyruntime.CompiledCheck{}, configPathError(childPath(path, "observe_safe"), "cannot be asserted for this check type")
	}

	if definition.ConfigRefPrefix != "" && checkConfig.ConfigRef != "" && !strings.HasPrefix(checkConfig.ConfigRef, definition.ConfigRefPrefix) {
		if checkConfig.ConfigRef != definition.ConfigRefPrefix {
			return policyruntime.CompiledCheck{}, configPathError(childPath(path, "config_ref"), "does not match the check type")
		}
	}

	return policyruntime.CompiledCheck{
		Name:       checkConfig.Name,
		Type:       checkConfig.Type,
		Stage:      stage,
		Operations: operations,
		RunIf:      policyruntime.RunIfPlan{AuthState: runIfAuthState},
		After:      append([]string(nil), checkConfig.After...),
		ConfigRef:  checkConfig.ConfigRef,
		Output:     checkConfig.Output,
	}, nil
}

func compileOperations(
	configured []string,
	defaults []policy.Operation,
	path string,
) ([]policy.Operation, error) {
	if configured == nil {
		return append([]policy.Operation(nil), defaults...), nil
	}

	if len(configured) == 0 {
		return nil, configPathError(path, "must not be empty")
	}

	operations := make([]policy.Operation, 0, len(configured))
	seen := make(map[policy.Operation]struct{}, len(configured))
	for index, value := range configured {
		operation := policy.Operation(strings.TrimSpace(value))
		if !operationValid(operation) {
			return nil, configPathError(indexedPath(path, index), "is invalid")
		}

		if _, exists := seen[operation]; exists {
			return nil, configPathError(indexedPath(path, index), "must be unique")
		}

		seen[operation] = struct{}{}
		operations = append(operations, operation)
	}

	return operations, nil
}

func runIfAuthStateValid(value string) bool {
	switch value {
	case runIfAny, runIfAuthenticated, runIfUnauthenticated:
		return true
	default:
		return false
	}
}

func validateCheckDependencies(checks []policyruntime.CompiledCheck) error {
	byName := make(map[string]policyruntime.CompiledCheck, len(checks))
	for _, check := range checks {
		byName[check.Name] = check
	}

	for _, check := range checks {
		for index, dependencyName := range check.After {
			dependency, ok := byName[dependencyName]
			if !ok {
				return configPathError(indexedPath("auth.policy.checks."+check.Name+".after", index), "references unknown check")
			}

			if dependency.Stage != check.Stage || !operationsCover(dependency.Operations, check.Operations) {
				return configPathError(indexedPath("auth.policy.checks."+check.Name+".after", index), "is not scheduler-compatible")
			}
		}
	}

	for operation := range operationSetFromChecks(checks) {
		for stage := range stageSetFromChecks(checks) {
			if err := sortChecksForPlan(checksForPlan(checks, operation, stage)); err != nil {
				return err
			}
		}
	}

	return nil
}

func operationsCover(left []policy.Operation, right []policy.Operation) bool {
	for _, operation := range right {
		if !operationsContain(left, operation) {
			return false
		}
	}

	return true
}

func operationSetFromChecks(checks []policyruntime.CompiledCheck) map[policy.Operation]struct{} {
	operations := make(map[policy.Operation]struct{})
	for _, check := range checks {
		for _, operation := range check.Operations {
			operations[operation] = struct{}{}
		}
	}

	return operations
}

func stageSetFromChecks(checks []policyruntime.CompiledCheck) map[policy.Stage]struct{} {
	stages := make(map[policy.Stage]struct{})
	for _, check := range checks {
		stages[check.Stage] = struct{}{}
	}

	return stages
}

func checksForPlan(
	checks []policyruntime.CompiledCheck,
	operation policy.Operation,
	stage policy.Stage,
) []policyruntime.CompiledCheck {
	selected := make([]policyruntime.CompiledCheck, 0)
	for _, check := range checks {
		if check.Stage == stage && operationsContain(check.Operations, operation) {
			selected = append(selected, check)
		}
	}

	return selected
}

func sortChecksForPlan(checks []policyruntime.CompiledCheck) error {
	temporary := make(map[string]bool, len(checks))
	permanent := make(map[string]bool, len(checks))
	byName := make(map[string]policyruntime.CompiledCheck, len(checks))
	for _, check := range checks {
		byName[check.Name] = check
	}

	var visit func(policyruntime.CompiledCheck) error
	visit = func(check policyruntime.CompiledCheck) error {
		if permanent[check.Name] {
			return nil
		}

		if temporary[check.Name] {
			return configPathError("auth.policy.checks", "contains cyclic after dependencies")
		}

		temporary[check.Name] = true
		for _, dependencyName := range check.After {
			dependency, ok := byName[dependencyName]
			if !ok {
				continue
			}

			if err := visit(dependency); err != nil {
				return err
			}
		}

		temporary[check.Name] = false
		permanent[check.Name] = true

		return nil
	}

	for _, check := range checks {
		if err := visit(check); err != nil {
			return err
		}
	}

	return nil
}

func registerGeneratedLuaAttributes(check policyruntime.CompiledCheck, registry *policyregistry.AttributeRegistry) error {
	switch check.Type {
	case checkTypeLuaControl:
		name := normalizeIdentifierFromConfigRef("auth.controls.lua.controls.", check.ConfigRef, check.Name)
		return registerLuaControlAttributes(name, check, registry)
	case checkTypeLuaFilter:
		name := normalizeIdentifierFromConfigRef("auth.controls.lua.filters.", check.ConfigRef, check.Name)
		return registerLuaFilterAttributes(name, check, registry)
	default:
		return nil
	}
}

func registerLuaControlAttributes(
	name string,
	check policyruntime.CompiledCheck,
	registry *policyregistry.AttributeRegistry,
) error {
	if name == "" {
		return configPathError("auth.policy.checks."+check.Name+".config_ref", "must identify a named Lua control")
	}

	return registerGeneratedAttributes(registry, []policyregistry.AttributeDefinition{
		generatedLuaAttribute(fmt.Sprintf("auth.lua.control.%s.triggered", name), policy.StagePreAuth, check, true),
		generatedLuaAttribute(fmt.Sprintf("auth.lua.control.%s.abort", name), policy.StagePreAuth, check, false),
		generatedLuaErrorAttribute(fmt.Sprintf("auth.lua.control.%s.error", name), policy.StagePreAuth, check),
	})
}

func registerLuaFilterAttributes(
	name string,
	check policyruntime.CompiledCheck,
	registry *policyregistry.AttributeRegistry,
) error {
	if name == "" {
		return configPathError("auth.policy.checks."+check.Name+".config_ref", "must identify a named Lua filter")
	}

	return registerGeneratedAttributes(registry, []policyregistry.AttributeDefinition{
		generatedLuaAttribute(fmt.Sprintf("auth.lua.filter.%s.rejected", name), policy.StageAuthFilters, check, true),
		generatedLuaErrorAttribute(fmt.Sprintf("auth.lua.filter.%s.error", name), policy.StageAuthFilters, check),
	})
}

func generatedLuaAttribute(
	id string,
	stage policy.Stage,
	check policyruntime.CompiledCheck,
	withStatusMessage bool,
) policyregistry.AttributeDefinition {
	definition := policyregistry.AttributeDefinition{
		ID:            id,
		Description:   id,
		Stage:         stage,
		Operations:    append([]policy.Operation(nil), check.Operations...),
		ProducerCheck: check.Name,
		Category:      policyregistry.AttributeCategoryEnvironment,
		Type:          policyregistry.AttributeTypeBool,
		Source:        policyregistry.SourceBuiltin,
	}

	if withStatusMessage {
		definition.Details = map[string]policyregistry.DetailDefinition{
			"status_message": {
				Type:        policyregistry.AttributeTypeString,
				Sensitivity: "public",
				Purpose:     "response_message",
				MaxLength:   256,
			},
		}
	}

	return definition
}

func generatedLuaErrorAttribute(
	id string,
	stage policy.Stage,
	check policyruntime.CompiledCheck,
) policyregistry.AttributeDefinition {
	return policyregistry.AttributeDefinition{
		ID:            id,
		Description:   id,
		Stage:         stage,
		Operations:    append([]policy.Operation(nil), check.Operations...),
		ProducerCheck: check.Name,
		Category:      policyregistry.AttributeCategoryEnvironment,
		Type:          policyregistry.AttributeTypeBool,
		Source:        policyregistry.SourceBuiltin,
		Details: map[string]policyregistry.DetailDefinition{
			"reason_code": {Type: policyregistry.AttributeTypeString, Sensitivity: "internal"},
		},
	}
}

func registerGeneratedAttributes(registry *policyregistry.AttributeRegistry, definitions []policyregistry.AttributeDefinition) error {
	for _, definition := range definitions {
		if err := registry.Register(definition); err != nil {
			return err
		}
	}

	return nil
}
