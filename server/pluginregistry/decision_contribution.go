// Copyright (C) 2026 Christian Roessner
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

package pluginregistry

import (
	"fmt"
	"slices"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	policyregistry "github.com/croessner/nauthilus/v4/server/policy/registry"
)

const nativeDecisionFactSource = "plugin"

var _ pluginapi.DecisionRegistrar = (*Registrar)(nil)

// DecisionFactProviders returns committed generic fact-provider components.
func (r *Registry) DecisionFactProviders() []Component {
	return r.ComponentsByKind(ComponentKindDecisionFactProvider)
}

// DecisionEffectProviders returns committed generic effect-provider components.
func (r *Registry) DecisionEffectProviders() []Component {
	return r.ComponentsByKind(ComponentKindDecisionEffectProvider)
}

// RegisterDecisionFactProvider stages one target-aware generic fact provider.
func (r *Registrar) RegisterDecisionFactProvider(provider pluginapi.DecisionFactProvider) error {
	if provider == nil {
		return ErrNilComponent
	}

	descriptor := provider.Descriptor()
	if err := pluginapi.ValidateDecisionFactProviderDescriptor(descriptor); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidDescriptor, err)
	}

	return r.registerDecisionComponent(decisionComponentRegistration{
		value:                  provider,
		factProviderDescriptor: cloneDecisionFactProviderDescriptor(descriptor),
		localName:              descriptor.Name,
		kind:                   ComponentKindDecisionFactProvider,
	})
}

// RegisterDecisionEffectProvider stages one target-aware policy-selected effect provider.
func (r *Registrar) RegisterDecisionEffectProvider(provider pluginapi.DecisionEffectProvider) error {
	if provider == nil {
		return ErrNilComponent
	}

	descriptor := provider.Descriptor()
	if err := pluginapi.ValidateDecisionEffectProviderDescriptor(descriptor); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidDescriptor, err)
	}

	return r.registerDecisionComponent(decisionComponentRegistration{
		value:                    provider,
		effectProviderDescriptor: cloneDecisionEffectProviderDescriptor(descriptor),
		localName:                descriptor.Name,
		kind:                     ComponentKindDecisionEffectProvider,
	})
}

// decisionComponentRegistration carries one validated generic component into shared staging.
type decisionComponentRegistration struct {
	value                    any
	factProviderDescriptor   pluginapi.DecisionFactProviderDescriptor
	effectProviderDescriptor pluginapi.DecisionEffectProviderDescriptor
	localName                string
	kind                     ComponentKind
}

// registerDecisionComponent stages validated generic metadata through the shared registry path.
func (r *Registrar) registerDecisionComponent(input decisionComponentRegistration) error {
	return r.registerComponent(Component{
		Value:                            input.value,
		DecisionFactProviderDescriptor:   input.factProviderDescriptor,
		DecisionEffectProviderDescriptor: input.effectProviderDescriptor,
		ModuleName:                       r.module.Name,
		LocalName:                        input.localName,
		Kind:                             input.kind,
		Origin:                           ComponentOriginNative,
	})
}

// NewNativeDecisionContribution adapts one module's committed generic declarations inward.
func NewNativeDecisionContribution(
	registry *Registry,
	moduleName string,
	ownership policyregistry.NamespaceOwnership,
) (policyregistry.DefinitionContribution, error) {
	if registry == nil {
		return policyregistry.DefinitionContribution{}, fmt.Errorf("%w: registry is nil", ErrInvalidDescriptor)
	}

	if err := pluginapi.ValidateModuleName(moduleName); err != nil {
		return policyregistry.DefinitionContribution{}, fmt.Errorf("%w: %w", ErrInvalidDescriptor, err)
	}

	expectedOwner := nativeDecisionOwner(moduleName)
	if ownership.Owner() != expectedOwner {
		return policyregistry.DefinitionContribution{}, fmt.Errorf(
			"%w: native module %q requires contributor owner %q, got %q",
			policyregistry.ErrNamespaceOwnership,
			moduleName,
			expectedOwner,
			ownership.Owner(),
		)
	}

	builder := nativeDecisionContributionBuilder{
		moduleName: moduleName,
		ownership:  ownership,
	}

	if err := builder.addFactProviders(registry.DecisionFactProviders()); err != nil {
		return policyregistry.DefinitionContribution{}, err
	}

	if err := builder.addEffectProviders(registry.DecisionEffectProviders()); err != nil {
		return policyregistry.DefinitionContribution{}, err
	}

	return policyregistry.NewExtensionDefinitionContribution(policyregistry.ExtensionDefinitionContributionInput{
		Ownership: builder.ownership,
		Providers: builder.providers,
		Effects:   builder.effects,
	})
}

// nativeDecisionContributionBuilder translates public capability descriptors without retaining them.
type nativeDecisionContributionBuilder struct {
	ownership  policyregistry.NamespaceOwnership
	providers  []policyregistry.ExtensionProviderDefinition
	effects    []policyregistry.EffectDefinition
	moduleName string
}

// addFactProviders converts fact-provider components owned by the selected module.
func (b *nativeDecisionContributionBuilder) addFactProviders(components []Component) error {
	for _, component := range components {
		if component.ModuleName != b.moduleName {
			continue
		}

		descriptor := component.DecisionFactProviderDescriptor
		if err := pluginapi.ValidateDecisionFactProviderDescriptor(descriptor); err != nil {
			return fmt.Errorf("%w: module %q fact provider %q: %w", ErrInvalidDescriptor, b.moduleName, component.LocalName, err)
		}

		if err := b.requireOwnedDefinitionNamespace(descriptor.Namespace, component.LocalName); err != nil {
			return err
		}

		definition, err := b.newFactProviderDefinition(descriptor)
		if err != nil {
			return err
		}

		b.providers = append(b.providers, definition)
	}

	return nil
}

// addEffectProviders converts effect-provider components owned by the selected module.
func (b *nativeDecisionContributionBuilder) addEffectProviders(components []Component) error {
	for _, component := range components {
		if component.ModuleName != b.moduleName {
			continue
		}

		descriptor := component.DecisionEffectProviderDescriptor
		if err := pluginapi.ValidateDecisionEffectProviderDescriptor(descriptor); err != nil {
			return fmt.Errorf("%w: module %q effect provider %q: %w", ErrInvalidDescriptor, b.moduleName, component.LocalName, err)
		}

		if err := b.requireOwnedDefinitionNamespace(descriptor.Namespace, component.LocalName); err != nil {
			return err
		}

		provider, effects, err := b.newEffectProviderDefinitions(descriptor)
		if err != nil {
			return err
		}

		b.providers = append(b.providers, provider)
		b.effects = append(b.effects, effects...)
	}

	return nil
}

// requireOwnedDefinitionNamespace enforces the host-assigned exact definition namespace.
func (b nativeDecisionContributionBuilder) requireOwnedDefinitionNamespace(namespace string, component string) error {
	if b.ownership.Owns(namespace) {
		return nil
	}

	return fmt.Errorf(
		"%w: native module %q component %q cannot contribute namespace %q",
		policyregistry.ErrNamespaceOwnership,
		b.moduleName,
		component,
		namespace,
	)
}

// newFactProviderDefinition derives host-owned provider and fact identities.
func (b nativeDecisionContributionBuilder) newFactProviderDefinition(
	descriptor pluginapi.DecisionFactProviderDescriptor,
) (policyregistry.ExtensionProviderDefinition, error) {
	targets, err := nativeDecisionTargets(descriptor.Targets)
	if err != nil {
		return policyregistry.ExtensionProviderDefinition{}, err
	}

	outputs, err := nativeDecisionFactOutputs(b.moduleName, descriptor.Outputs)
	if err != nil {
		return policyregistry.ExtensionProviderDefinition{}, err
	}

	provider, err := policyregistry.NewProviderDefinition(policyregistry.ProviderDefinitionInput{
		ID:      nativeDecisionProviderID(descriptor.Namespace, b.moduleName, descriptor.Name),
		Targets: targets,
		Outputs: outputs,
		Failure: policyregistry.ProviderFailureIndeterminate,
		Timeout: descriptor.Timeout,
	})
	if err != nil {
		return policyregistry.ExtensionProviderDefinition{}, err
	}

	return policyregistry.ExtensionProviderDefinition{
		Definition:         provider,
		ProducedFactPrefix: nativeDecisionFactPrefix(b.moduleName),
	}, nil
}

// nativeDecisionFactOutputs preserves public value shapes under host-derived fact identities.
func nativeDecisionFactOutputs(
	moduleName string,
	descriptors []pluginapi.DecisionFactOutputDescriptor,
) ([]policyregistry.ProviderFactOutput, error) {
	outputs := make([]policyregistry.ProviderFactOutput, 0, len(descriptors))
	for _, descriptor := range descriptors {
		output, err := policyregistry.NewProviderFactOutput(policyregistry.ProviderFactOutputInput{
			ID:        nativeDecisionFactPrefix(moduleName) + descriptor.Name,
			Category:  decision.FactCategory(descriptor.Category),
			Kind:      decision.ValueKind(descriptor.Kind),
			MaxLength: descriptor.MaxLength,
			MaxItems:  descriptor.MaxItems,
			MaxBytes:  descriptor.MaxBytes,
		})
		if err != nil {
			return nil, err
		}

		outputs = append(outputs, output)
	}

	return outputs, nil
}

// newEffectProviderDefinitions derives one host provider and its policy-selectable effects.
func (b nativeDecisionContributionBuilder) newEffectProviderDefinitions(
	descriptor pluginapi.DecisionEffectProviderDescriptor,
) (policyregistry.ExtensionProviderDefinition, []policyregistry.EffectDefinition, error) {
	providerID := nativeDecisionProviderID(descriptor.Namespace, b.moduleName, descriptor.Name)

	targets, executions, err := nativeDecisionEffectCapabilities(descriptor.Effects)
	if err != nil {
		return policyregistry.ExtensionProviderDefinition{}, nil, err
	}

	provider, err := policyregistry.NewProviderDefinition(policyregistry.ProviderDefinitionInput{
		ID:         providerID,
		Targets:    targets,
		Executions: executions,
	})
	if err != nil {
		return policyregistry.ExtensionProviderDefinition{}, nil, err
	}

	effects := make([]policyregistry.EffectDefinition, 0, len(descriptor.Effects))
	for _, publicEffect := range descriptor.Effects {
		effect, effectErr := newNativeDecisionEffectDefinition(descriptor.Namespace, providerID, publicEffect)
		if effectErr != nil {
			return policyregistry.ExtensionProviderDefinition{}, nil, effectErr
		}

		effects = append(effects, effect)
	}

	return policyregistry.ExtensionProviderDefinition{Definition: provider}, effects, nil
}

// nativeDecisionTargets reconstructs exact selectors through the internal target constructor.
func nativeDecisionTargets(selectors []pluginapi.DecisionTargetSelector) ([]decision.Target, error) {
	targets := make([]decision.Target, 0, len(selectors))
	for _, selector := range selectors {
		target, err := decision.NewTarget(selector.Namespace, selector.Action)
		if err != nil {
			return nil, err
		}

		targets = append(targets, target)
	}

	return targets, nil
}

// nativeDecisionEffectCapabilities collects unique exact targets and execution classes.
func nativeDecisionEffectCapabilities(
	effects []pluginapi.DecisionEffectDescriptor,
) ([]decision.Target, []policyregistry.ExecutionClass, error) {
	var (
		targets    []decision.Target
		executions []policyregistry.ExecutionClass
	)

	for _, effect := range effects {
		convertedTargets, err := nativeDecisionTargets(effect.Targets)
		if err != nil {
			return nil, nil, err
		}

		for _, target := range convertedTargets {
			if !slices.ContainsFunc(targets, func(candidate decision.Target) bool {
				return candidate.String() == target.String()
			}) {
				targets = append(targets, target)
			}
		}

		execution, err := nativeDecisionExecution(effect.Execution)
		if err != nil {
			return nil, nil, err
		}

		if !slices.Contains(executions, execution) {
			executions = append(executions, execution)
		}
	}

	return targets, executions, nil
}

// newNativeDecisionEffectDefinition converts one effect through internal typed constructors.
func newNativeDecisionEffectDefinition(
	namespace string,
	providerID string,
	publicEffect pluginapi.DecisionEffectDescriptor,
) (policyregistry.EffectDefinition, error) {
	targets, err := nativeDecisionTargets(publicEffect.Targets)
	if err != nil {
		return policyregistry.EffectDefinition{}, err
	}

	execution, err := nativeDecisionExecution(publicEffect.Execution)
	if err != nil {
		return policyregistry.EffectDefinition{}, err
	}

	parameters, err := nativeDecisionParameters(publicEffect.Parameters)
	if err != nil {
		return policyregistry.EffectDefinition{}, err
	}

	return policyregistry.NewEffectDefinition(policyregistry.EffectDefinitionInput{
		ID:         namespace + "/" + publicEffect.Name,
		Provider:   providerID,
		Targets:    targets,
		Parameters: parameters,
		Kind:       policyregistry.EffectKindObligation,
		Execution:  execution,
	})
}

// nativeDecisionParameters reconstructs public parameters through internal schemas.
func nativeDecisionParameters(
	input []pluginapi.DecisionEffectParameterDescriptor,
) ([]policyregistry.ParameterSchema, error) {
	parameters := make([]policyregistry.ParameterSchema, 0, len(input))
	for _, parameter := range input {
		schema, err := policyregistry.NewParameterSchema(policyregistry.ParameterSchemaInput{
			Name:           parameter.Name,
			Kind:           decision.ValueKind(parameter.Kind),
			MaxLength:      parameter.MaxLength,
			MaxItems:       parameter.MaxItems,
			MaxBytes:       parameter.MaxBytes,
			AllowedStrings: append([]string(nil), parameter.AllowedStrings...),
			NonEmpty:       parameter.NonEmpty,
			Required:       parameter.Required,
		})
		if err != nil {
			return nil, err
		}

		parameters = append(parameters, schema)
	}

	return parameters, nil
}

// nativeDecisionExecution maps the closed public effect class inward.
func nativeDecisionExecution(input pluginapi.DecisionEffectExecution) (policyregistry.ExecutionClass, error) {
	switch input {
	case pluginapi.DecisionEffectExecutionHostSync:
		return policyregistry.ExecutionHostSync, nil
	case pluginapi.DecisionEffectExecutionHostPostAction:
		return policyregistry.ExecutionHostPostAction, nil
	default:
		return "", fmt.Errorf("%w: unsupported decision effect execution %q", ErrInvalidDescriptor, input)
	}
}

// nativeDecisionProviderID derives one exact internal provider identity from host and public local identity.
func nativeDecisionProviderID(namespace string, moduleName string, componentName string) string {
	return namespace + "/" + nativeDecisionFactSource + "." + moduleName + "." + componentName
}

// nativeDecisionFactPrefix returns the host-assigned fact authority prefix for one module.
func nativeDecisionFactPrefix(moduleName string) string {
	return nativeDecisionFactSource + "." + moduleName + "."
}

// nativeDecisionOwner returns the exact host authority for one native module.
func nativeDecisionOwner(moduleName string) string {
	return nativeDecisionFactSource + "." + moduleName
}

// cloneDecisionFactProviderDescriptor detaches all mutable public fact-provider metadata.
func cloneDecisionFactProviderDescriptor(input pluginapi.DecisionFactProviderDescriptor) pluginapi.DecisionFactProviderDescriptor {
	input.Targets = append([]pluginapi.DecisionTargetSelector(nil), input.Targets...)
	input.Outputs = append([]pluginapi.DecisionFactOutputDescriptor(nil), input.Outputs...)

	return input
}

// cloneDecisionEffectProviderDescriptor detaches all mutable public effect-provider metadata.
func cloneDecisionEffectProviderDescriptor(input pluginapi.DecisionEffectProviderDescriptor) pluginapi.DecisionEffectProviderDescriptor {
	input.Effects = append([]pluginapi.DecisionEffectDescriptor(nil), input.Effects...)
	for effectIndex := range input.Effects {
		effect := &input.Effects[effectIndex]
		effect.Targets = append([]pluginapi.DecisionTargetSelector(nil), effect.Targets...)
		effect.Parameters = append([]pluginapi.DecisionEffectParameterDescriptor(nil), effect.Parameters...)

		for parameterIndex := range effect.Parameters {
			parameter := &effect.Parameters[parameterIndex]
			parameter.AllowedStrings = append([]string(nil), parameter.AllowedStrings...)
		}
	}

	return input
}
