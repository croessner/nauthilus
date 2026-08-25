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

package policyprovider

import (
	"errors"
	"fmt"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

var (
	// ErrInvalidContribution identifies a Lua descriptor that cannot enter the internal catalog candidate.
	ErrInvalidContribution = errors.New("invalid Lua policy provider contribution")
)

// DefinitionAdapter converts Lua capability descriptors into the sole internal contribution DTO.
type DefinitionAdapter struct {
	ownership registry.NamespaceOwnership
	authority string
}

// NewDefinitionAdapter binds one adapter to host-assigned namespaces and Lua fact authority.
func NewDefinitionAdapter(
	ownership registry.NamespaceOwnership,
	authority string,
) (DefinitionAdapter, error) {
	owned, err := registry.NewNamespaceOwnership(ownership.Owner(), ownership.Namespaces())
	if err != nil {
		return DefinitionAdapter{}, invalidContribution("namespace ownership must be constructor validated: %v", err)
	}

	if err = validateLuaAuthority(authority); err != nil {
		return DefinitionAdapter{}, err
	}

	expectedOwner := "lua." + authority
	if owned.Owner() != expectedOwner {
		return DefinitionAdapter{}, invalidContribution(
			"Lua authority %q requires contributor owner %q, got %q",
			authority,
			expectedOwner,
			owned.Owner(),
		)
	}

	return DefinitionAdapter{ownership: owned, authority: authority}, nil
}

// Adapt validates and deeply owns provider/effect definitions without catalog activation.
func (a DefinitionAdapter) Adapt(
	factProviders []FactProviderDescriptor,
	effectProviders []EffectProviderDescriptor,
) (registry.DefinitionContribution, error) {
	providers := make([]registry.ExtensionProviderDefinition, 0, len(factProviders)+len(effectProviders))
	effects := make([]registry.EffectDefinition, 0)

	for _, descriptor := range factProviders {
		provider, err := a.adaptFactProvider(descriptor)
		if err != nil {
			return registry.DefinitionContribution{}, err
		}

		providers = append(providers, provider)
	}

	for _, descriptor := range effectProviders {
		provider, providerEffects, err := a.adaptEffectProvider(descriptor)
		if err != nil {
			return registry.DefinitionContribution{}, err
		}

		providers = append(providers, provider)
		effects = append(effects, providerEffects...)
	}

	if len(providers) == 0 {
		return registry.DefinitionContribution{}, invalidContribution("definition set must not be empty")
	}

	contribution, err := registry.NewExtensionDefinitionContribution(registry.ExtensionDefinitionContributionInput{
		Ownership: a.ownership,
		Providers: providers,
		Effects:   effects,
	})
	if err != nil {
		return registry.DefinitionContribution{}, invalidContribution("internal contribution rejected: %v", err)
	}

	return contribution, nil
}

// adaptFactProvider converts one fact descriptor and derives host-owned identities.
func (a DefinitionAdapter) adaptFactProvider(
	descriptor FactProviderDescriptor,
) (registry.ExtensionProviderDefinition, error) {
	if err := descriptor.Validate(); err != nil {
		return registry.ExtensionProviderDefinition{}, invalidContribution("fact provider descriptor rejected: %v", err)
	}

	if !a.ownership.Owns(descriptor.Namespace) {
		return registry.ExtensionProviderDefinition{}, invalidContribution(
			"fact provider namespace %q is not host-assigned to %q",
			descriptor.Namespace,
			a.ownership.Owner(),
		)
	}

	targets, err := adaptTargets(descriptor.Targets)
	if err != nil {
		return registry.ExtensionProviderDefinition{}, err
	}

	outputs, err := a.adaptFactOutputs(descriptor.Outputs)
	if err != nil {
		return registry.ExtensionProviderDefinition{}, err
	}

	definition, err := registry.NewProviderDefinition(registry.ProviderDefinitionInput{
		ID:      a.providerID(descriptor.Namespace, descriptor.Name),
		Targets: targets,
		Outputs: outputs,
		Failure: registry.ProviderFailureIndeterminate,
		Timeout: descriptor.Timeout,
	})
	if err != nil {
		return registry.ExtensionProviderDefinition{}, invalidContribution("fact provider definition rejected: %v", err)
	}

	return registry.ExtensionProviderDefinition{
		Definition:         definition,
		ProducedFactPrefix: a.factPrefix(),
	}, nil
}

// adaptFactOutputs qualifies and reconstructs every typed Lua fact capability inward.
func (a DefinitionAdapter) adaptFactOutputs(
	descriptors []FactOutputDescriptor,
) ([]registry.ProviderFactOutput, error) {
	outputs := make([]registry.ProviderFactOutput, 0, len(descriptors))
	for _, descriptor := range descriptors {
		output, err := registry.NewProviderFactOutput(registry.ProviderFactOutputInput{
			ID:        a.factID(descriptor.Name),
			Category:  descriptor.Category,
			Kind:      descriptor.Kind,
			MaxLength: descriptor.MaxLength,
			MaxItems:  descriptor.MaxItems,
			MaxBytes:  descriptor.MaxBytes,
		})
		if err != nil {
			return nil, invalidContribution("fact output %q rejected: %v", descriptor.Name, err)
		}

		outputs = append(outputs, output)
	}

	return outputs, nil
}

// adaptEffectProvider converts one effect capability and its selected effect definitions.
func (a DefinitionAdapter) adaptEffectProvider(
	descriptor EffectProviderDescriptor,
) (registry.ExtensionProviderDefinition, []registry.EffectDefinition, error) {
	if err := descriptor.Validate(); err != nil {
		return registry.ExtensionProviderDefinition{}, nil, invalidContribution("effect provider descriptor rejected: %v", err)
	}

	if !a.ownership.Owns(descriptor.Namespace) {
		return registry.ExtensionProviderDefinition{}, nil, invalidContribution(
			"effect provider namespace %q is not host-assigned to %q",
			descriptor.Namespace,
			a.ownership.Owner(),
		)
	}

	providerID := a.providerID(descriptor.Namespace, descriptor.Name)

	targets, executions, effects, err := adaptEffects(descriptor.Namespace, providerID, descriptor.Effects)
	if err != nil {
		return registry.ExtensionProviderDefinition{}, nil, err
	}

	definition, err := registry.NewProviderDefinition(registry.ProviderDefinitionInput{
		ID:         providerID,
		Targets:    targets,
		Executions: executions,
	})
	if err != nil {
		return registry.ExtensionProviderDefinition{}, nil, invalidContribution("effect provider definition rejected: %v", err)
	}

	return registry.ExtensionProviderDefinition{Definition: definition}, effects, nil
}

// adaptEffects derives effect identities and the provider capability union.
func adaptEffects(
	namespace string,
	providerID string,
	descriptors []EffectDescriptor,
) ([]decision.Target, []registry.ExecutionClass, []registry.EffectDefinition, error) {
	targets := make([]decision.Target, 0)
	executions := make([]registry.ExecutionClass, 0, 2)
	effects := make([]registry.EffectDefinition, 0, len(descriptors))
	targetSeen := make(map[string]struct{})
	executionSeen := make(map[registry.ExecutionClass]struct{}, 2)

	for _, descriptor := range descriptors {
		effectTargets, err := adaptTargets(descriptor.Targets)
		if err != nil {
			return nil, nil, nil, err
		}

		targets = appendUniqueTargets(targets, effectTargets, targetSeen)

		execution := adaptExecution(descriptor.Execution)
		if _, exists := executionSeen[execution]; !exists {
			executionSeen[execution] = struct{}{}
			executions = append(executions, execution)
		}

		parameters, err := adaptParameters(descriptor.Parameters)
		if err != nil {
			return nil, nil, nil, err
		}

		effect, err := registry.NewEffectDefinition(registry.EffectDefinitionInput{
			ID:         namespace + "/" + descriptor.Name,
			Provider:   providerID,
			Targets:    effectTargets,
			Parameters: parameters,
			Kind:       registry.EffectKindObligation,
			Execution:  execution,
		})
		if err != nil {
			return nil, nil, nil, invalidContribution("effect definition %q rejected: %v", descriptor.Name, err)
		}

		effects = append(effects, effect)
	}

	return targets, executions, effects, nil
}

// adaptTargets constructs detached exact internal target values.
func adaptTargets(selectors []TargetSelector) ([]decision.Target, error) {
	targets := make([]decision.Target, 0, len(selectors))
	for _, selector := range selectors {
		target, err := decision.NewTarget(selector.Namespace, selector.Action)
		if err != nil {
			return nil, invalidContribution("target %q/%q rejected: %v", selector.Namespace, selector.Action, err)
		}

		targets = append(targets, target)
	}

	return targets, nil
}

// appendUniqueTargets appends exact targets once while preserving descriptor order.
func appendUniqueTargets(
	result []decision.Target,
	values []decision.Target,
	seen map[string]struct{},
) []decision.Target {
	for _, target := range values {
		if _, exists := seen[target.String()]; exists {
			continue
		}

		seen[target.String()] = struct{}{}
		result = append(result, target)
	}

	return result
}

// adaptParameters constructs detached internal typed parameter schemas.
func adaptParameters(descriptors []ParameterDescriptor) ([]registry.ParameterSchema, error) {
	parameters := make([]registry.ParameterSchema, 0, len(descriptors))
	for _, descriptor := range descriptors {
		parameter, err := registry.NewParameterSchema(registry.ParameterSchemaInput{
			Name:           descriptor.Name,
			Kind:           descriptor.Kind,
			MaxLength:      descriptor.MaxLength,
			MaxItems:       descriptor.MaxItems,
			MaxBytes:       descriptor.MaxBytes,
			AllowedStrings: descriptor.AllowedStrings,
			NonEmpty:       descriptor.NonEmpty,
			Required:       descriptor.Required,
		})
		if err != nil {
			return nil, invalidContribution("effect parameter %q rejected: %v", descriptor.Name, err)
		}

		parameters = append(parameters, parameter)
	}

	return parameters, nil
}

// adaptExecution maps the closed Lua execution vocabulary inward.
func adaptExecution(execution EffectExecution) registry.ExecutionClass {
	if execution == EffectExecutionHostPostAction {
		return registry.ExecutionHostPostAction
	}

	return registry.ExecutionHostSync
}

// validateLuaAuthority verifies one exact provider-owner segment through fact ownership.
func validateLuaAuthority(authority string) error {
	provenance, err := decision.NewProvenance(decision.FactSourceLua, authority, "policyprovider")
	if err != nil {
		return invalidContribution("Lua authority %q is not canonical: %v", authority, err)
	}

	value := true

	strictValue, err := decision.NewValue(decision.ValueInput{Boolean: &value})
	if err != nil {
		return invalidContribution("Lua authority validation value rejected: %v", err)
	}

	if _, err = decision.NewFact(
		"lua."+authority+".value",
		decision.FactCategoryEnvironment,
		strictValue,
		provenance,
	); err != nil {
		return invalidContribution("Lua authority %q is not canonical: %v", authority, err)
	}

	return nil
}

// providerID derives one exact host-owned internal provider identity.
func (a DefinitionAdapter) providerID(namespace string, name string) string {
	return namespace + "/lua." + a.authority + "." + name
}

// factPrefix returns the exact host-assigned fact authority prefix.
func (a DefinitionAdapter) factPrefix() string {
	return "lua." + a.authority + "."
}

// factID derives one exact host-owned fact identity from a local output name.
func (a DefinitionAdapter) factID(name string) string {
	return a.factPrefix() + name
}

// invalidContribution constructs one stable inward-adaptation error.
func invalidContribution(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidContribution, fmt.Sprintf(format, arguments...))
}
