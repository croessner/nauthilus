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

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/lualib/pipeline"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
	"github.com/croessner/nauthilus/v3/server/policy"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

var standardAuthSourceOperations = []policy.Operation{
	policy.OperationAuthenticate,
	policy.OperationLookupIdentity,
}

// registerStandardAuthSourceAttributes captures sources that run without configured policy checks.
func registerStandardAuthSourceAttributes(
	file config.File,
	registry *policyregistry.AttributeRegistry,
) error {
	if file == nil || registry == nil {
		return nil
	}

	if err := registerStandardAuthLuaSourceAttributes(file.GetLua(), registry); err != nil {
		return err
	}

	return registerStandardAuthPluginSourceAttributes(registry)
}

// registerStandardAuthLuaSourceAttributes declares default Lua environment and subject outcomes.
func registerStandardAuthLuaSourceAttributes(
	luaConfig *config.LuaSection,
	registry *policyregistry.AttributeRegistry,
) error {
	for _, source := range luaConfig.GetEnvironmentSources() {
		name := strings.TrimSpace(source.Name)
		check := standardAuthSourceCheck(
			"lua_environment_"+name,
			policy.CheckTypeLuaEnvironment,
			policy.StagePreAuth,
		)
		definitions := []policyregistry.AttributeDefinition{
			generatedLuaAttribute(fmt.Sprintf("auth.lua.environment.%s.triggered", name), policy.StagePreAuth, check, true),
			generatedLuaAttribute(fmt.Sprintf("auth.lua.environment.%s.abort", name), policy.StagePreAuth, check, false),
			generatedLuaErrorAttribute(fmt.Sprintf("auth.lua.environment.%s.error", name), policy.StagePreAuth, check),
		}

		if err := registerMissingGeneratedAttributes(registry, definitions); err != nil {
			return err
		}
	}

	for _, source := range luaConfig.GetSubjectSources() {
		name := strings.TrimSpace(source.Name)
		check := standardAuthSourceCheck(
			"lua_subject_"+name,
			policy.CheckTypeLuaSubjectSource,
			policy.StageSubjectAnalysis,
		)
		definitions := []policyregistry.AttributeDefinition{
			generatedExecutionAttribute(
				fmt.Sprintf("auth.lua.subject.%s.rejected", name),
				policy.StageSubjectAnalysis,
				policyregistry.AttributeCategorySubject,
				check,
				executionAttributeDetailStatus,
			),
			generatedExecutionAttribute(
				fmt.Sprintf("auth.lua.subject.%s.error", name),
				policy.StageSubjectAnalysis,
				policyregistry.AttributeCategorySubject,
				check,
				executionAttributeDetailError,
			),
		}

		if err := registerMissingGeneratedAttributes(registry, definitions); err != nil {
			return err
		}
	}

	return nil
}

// registerStandardAuthPluginSourceAttributes declares every registered native source outcome.
func registerStandardAuthPluginSourceAttributes(registry *policyregistry.AttributeRegistry) error {
	state, ok := pluginloader.DefaultState()
	if !ok {
		return nil
	}

	environmentSources := state.Registry().EnvironmentSources()

	environmentOrders, err := standardAuthPluginSourceOrders(environmentSources)
	if err != nil {
		return fmt.Errorf("plan standard-auth plugin environment sources: %w", err)
	}

	for _, component := range environmentSources {
		check := standardAuthSourceCheck(
			policy.PluginEnvironmentCheckName(component.ModuleName),
			policy.CheckTypePluginEnvironment,
			policy.StagePreAuth,
		)
		definitions := []policyregistry.AttributeDefinition{
			generatedPluginEnvironmentAttribute(policy.PluginEnvironmentAttributeID(component.ModuleName, component.LocalName, "triggered"), check, true, false),
			generatedPluginEnvironmentAttribute(policy.PluginEnvironmentAttributeID(component.ModuleName, component.LocalName, "abort"), check, false, false),
			generatedPluginEnvironmentAttribute(policy.PluginEnvironmentAttributeID(component.ModuleName, component.LocalName, "error"), check, false, true),
		}
		setGeneratedAttributeProducerOrder(definitions, environmentOrders[component.QualifiedName])

		if err := registerMissingGeneratedAttributes(registry, definitions); err != nil {
			return err
		}
	}

	subjectSources := state.Registry().SubjectSources()

	subjectOrders, err := standardAuthPluginSourceOrders(subjectSources)
	if err != nil {
		return fmt.Errorf("plan standard-auth plugin subject sources: %w", err)
	}

	for _, component := range subjectSources {
		check := standardAuthSourceCheck(
			policy.PluginSubjectCheckName(component.ModuleName, component.LocalName),
			policy.CheckTypePluginSubjectSource,
			policy.StageSubjectAnalysis,
		)
		definitions := []policyregistry.AttributeDefinition{
			generatedPluginSubjectAttribute(policy.PluginSubjectAttributeID(component.ModuleName, component.LocalName, "rejected"), check, true),
			generatedPluginSubjectAttribute(policy.PluginSubjectAttributeID(component.ModuleName, component.LocalName, "error"), check, false),
		}
		setGeneratedAttributeProducerOrder(definitions, subjectOrders[component.QualifiedName])

		if err := registerMissingGeneratedAttributes(registry, definitions); err != nil {
			return err
		}
	}

	return nil
}

// standardAuthPluginSourceOrders flattens the shared dependency plan into application order.
func standardAuthPluginSourceOrders(components []pluginregistry.Component) (map[string]uint32, error) {
	plan, err := pluginregistry.BuildSourcePlan(
		components,
		pipeline.ModeAuthenticated|pipeline.ModeUnauthenticated|pipeline.ModeNoAuth,
	)
	if err != nil {
		return nil, err
	}

	orders := make(map[string]uint32, len(components))
	order := uint32(0)

	for _, level := range plan.Levels {
		for _, node := range level {
			order++
			orders[node.Name] = order
		}
	}

	return orders, nil
}

// setGeneratedAttributeProducerOrder applies one immutable host order to related result facts.
func setGeneratedAttributeProducerOrder(
	definitions []policyregistry.AttributeDefinition,
	order uint32,
) {
	for index := range definitions {
		definitions[index].ProducerOrder = order
	}
}

// standardAuthSourceCheck supplies stable producer identity for an always-running legacy source.
func standardAuthSourceCheck(name string, checkType string, stage policy.Stage) policyruntime.CompiledCheck {
	return policyruntime.CompiledCheck{
		Name:       name,
		Type:       checkType,
		Stage:      stage,
		Operations: append([]policy.Operation(nil), standardAuthSourceOperations...),
	}
}

// registerMissingGeneratedAttributes retains a configured check definition when one already exists.
func registerMissingGeneratedAttributes(
	registry *policyregistry.AttributeRegistry,
	definitions []policyregistry.AttributeDefinition,
) error {
	for _, definition := range definitions {
		if _, exists := registry.Lookup(definition.ID); exists {
			if definition.ProducerOrder > 0 {
				registry.SetProducerOrder(definition.ID, definition.ProducerOrder)
			}

			continue
		}

		if err := registry.Register(definition); err != nil {
			return err
		}
	}

	return nil
}
