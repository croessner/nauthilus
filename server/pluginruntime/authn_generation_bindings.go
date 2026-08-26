// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package pluginruntime

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

var (
	// ErrInvalidAuthenticationBinding identifies an auth-shaped native component outside one exact candidate selection.
	ErrInvalidAuthenticationBinding = errors.New("invalid native authentication binding")
)

const (
	authnNativeEnvironmentExtension = "environment_source"
	authnNativeSubjectExtension     = "subject_source"
	authnNativeObligationExtension  = "obligation_target"
	authnNativePostActionExtension  = "post_action_target"
	authnEvaluateMethod             = "Evaluate"
	authnStatusMessageDetail        = "status_message"
	authnExecutionSuffixError       = "error"
	authnExecutionSuffixRejected    = "rejected"
	authnExecutionSuffixTriggered   = "triggered"
)

// AuthenticationSourceKind identifies the two public native authn source families.
type AuthenticationSourceKind string

const (
	// AuthenticationSourceEnvironment binds one configured pre-auth source.
	AuthenticationSourceEnvironment AuthenticationSourceKind = "environment"

	// AuthenticationSourceSubject binds one configured post-backend source.
	AuthenticationSourceSubject AuthenticationSourceKind = "subject"
)

// AuthenticationSourceBindingInput selects one exact public native source from a configured authn plan.
type AuthenticationSourceBindingInput struct {
	InstanceNames []string
	Operations    []policy.Operation
	ProviderID    string
	ModuleName    string
	ComponentName string
	Kind          AuthenticationSourceKind
	Order         uint32
}

// AuthenticationBindingInput carries candidate source selections and effect ownership dependencies.
type AuthenticationBindingInput struct {
	PostActionAcceptance effectsupervisor.Acceptor
	Observer             Observer
	Sources              []AuthenticationSourceBindingInput
}

// AuthenticationBindings owns all public auth extension adapters prepared for one generation.
type AuthenticationBindings struct {
	hostProviders    map[string]policyruntime.AuthnHostProvider
	syncEffects      map[string]policyruntime.SyncEffectProvider
	postActions      map[string]policyruntime.PostActionProvider
	policyAttributes map[string]policyregistry.AttributeDefinition
	definitions      []policyregistry.DefinitionContribution
}

type nativeAuthnEnvironmentProvider struct {
	provider     pluginapi.EnvironmentSource
	capabilities []pluginapi.Capability
	descriptor   pluginapi.SourceDescriptor
	call         nativeAuthnComponentCall
	id           string
}

type nativeAuthnSubjectProvider struct {
	provider     pluginapi.SubjectSource
	capabilities []pluginapi.Capability
	descriptor   pluginapi.SourceDescriptor
	call         nativeAuthnComponentCall
	id           string
}

type nativeAuthnObligationProvider struct {
	target pluginapi.ObligationTarget
	call   nativeAuthnComponentCall
	id     string
}

type nativeAuthnPostActionProvider struct {
	target       pluginapi.PostActionTarget
	capabilities []pluginapi.Capability
	call         nativeAuthnComponentCall
	id           string
}

type nativeAuthnComponentCall struct {
	observer Observer
	spec     invokeSpec
}

type authenticationExecutionAttributeSpec struct {
	identity       func(string, string, string) string
	suffixes       []string
	detailedSuffix string
	producerType   string
	stage          policy.Stage
	category       policyregistry.AttributeCategory
}

// PrepareAuthenticationBindings resolves auth-shaped public extension contracts from immutable generation captures.
func (b *GenerationBindings) PrepareAuthenticationBindings(
	ctx context.Context,
	input AuthenticationBindingInput,
) (*AuthenticationBindings, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	prepared := &AuthenticationBindings{
		hostProviders:    make(map[string]policyruntime.AuthnHostProvider),
		syncEffects:      make(map[string]policyruntime.SyncEffectProvider),
		postActions:      make(map[string]policyruntime.PostActionProvider),
		policyAttributes: make(map[string]policyregistry.AttributeDefinition),
	}

	if b == nil {
		if len(input.Sources) == 0 {
			return prepared, nil
		}

		return nil, invalidAuthenticationBinding("native generation is unavailable")
	}

	for _, source := range input.Sources {
		if err := prepared.addSource(b, input.Observer, source); err != nil {
			return nil, err
		}
	}

	if err := prepared.addRegisteredPolicyAttributes(b, input.Sources); err != nil {
		return nil, err
	}

	if err := prepared.addEffectTargets(b, input); err != nil {
		return nil, err
	}

	return prepared, nil
}

// AuthenticationPostActionProviderIDs returns exact implicit authn post-action identities before supervisor creation.
func (b *GenerationBindings) AuthenticationPostActionProviderIDs() ([]string, error) {
	if b == nil {
		return nil, nil
	}

	identities := make([]string, 0)
	seen := make(map[string]struct{})

	for _, module := range b.modules {
		for _, component := range module.components {
			if component.Kind != pluginregistry.ComponentKindPostActionTarget {
				continue
			}

			identity, err := policyconfig.AuthnPluginEffectID(module.moduleName, component.LocalName)
			if err != nil {
				return nil, invalidAuthenticationBinding("native post-action identity is invalid")
			}

			if _, duplicate := seen[identity]; duplicate {
				return nil, invalidAuthenticationBinding("native post-action identity is ambiguous")
			}

			seen[identity] = struct{}{}
			identities = append(identities, identity)
		}
	}

	sort.Strings(identities)

	return identities, nil
}

// AuthnHostProviders returns a detached exact source-owner map.
func (b *AuthenticationBindings) AuthnHostProviders() map[string]policyruntime.AuthnHostProvider {
	if b == nil {
		return nil
	}

	return cloneAuthenticationMap(b.hostProviders)
}

// SyncEffects returns detached generation-owned public obligation owners.
func (b *AuthenticationBindings) SyncEffects() map[string]policyruntime.SyncEffectProvider {
	if b == nil {
		return nil
	}

	return cloneAuthenticationMap(b.syncEffects)
}

// PostActions returns detached generation-owned public post-action owners.
func (b *AuthenticationBindings) PostActions() map[string]policyruntime.PostActionProvider {
	if b == nil {
		return nil
	}

	return cloneAuthenticationMap(b.postActions)
}

// PolicyAttributes returns detached source metadata used to compile the authn schema and standard rules.
func (b *AuthenticationBindings) PolicyAttributes() map[string]policyregistry.AttributeDefinition {
	if b == nil {
		return nil
	}

	result := make(map[string]policyregistry.AttributeDefinition, len(b.policyAttributes))
	for id, definition := range b.policyAttributes {
		result[id] = policyregistry.CloneDefinition(definition)
	}

	return result
}

// Definitions returns implicit authn-only selected-effect metadata for public native targets.
func (b *AuthenticationBindings) Definitions() []policyregistry.DefinitionContribution {
	if b == nil {
		return nil
	}

	return append([]policyregistry.DefinitionContribution(nil), b.definitions...)
}

// addSource resolves one exact configured source and records its generated execution facts.
func (b *AuthenticationBindings) addSource(
	generation *GenerationBindings,
	observer Observer,
	input AuthenticationSourceBindingInput,
) error {
	if err := validateAuthenticationSourceInput(input); err != nil {
		return err
	}

	if _, duplicate := b.hostProviders[input.ProviderID]; duplicate {
		return invalidAuthenticationBinding("native authn source identity is ambiguous")
	}

	kind := pluginregistry.ComponentKindEnvironmentSource
	if input.Kind == AuthenticationSourceSubject {
		kind = pluginregistry.ComponentKindSubjectSource
	}

	component, capabilities, err := generation.resolveAuthenticationComponent(input.ModuleName, input.ComponentName, kind)
	if err != nil {
		return err
	}

	switch input.Kind {
	case AuthenticationSourceEnvironment:
		provider, ok := component.Value.(pluginapi.EnvironmentSource)
		if !ok || nilDecisionDependency(provider) {
			return invalidAuthenticationBinding("captured environment component has an invalid owner")
		}

		b.hostProviders[input.ProviderID] = &nativeAuthnEnvironmentProvider{
			provider: provider, capabilities: capabilities,
			descriptor: component.SourceDescriptor, id: input.ProviderID,
			call: newNativeAuthnComponentCall(
				observer, input.ModuleName, input.ComponentName, authnNativeEnvironmentExtension, authnEvaluateMethod,
			),
		}
		b.addEnvironmentExecutionAttributes(input)
	case AuthenticationSourceSubject:
		provider, ok := component.Value.(pluginapi.SubjectSource)
		if !ok || nilDecisionDependency(provider) {
			return invalidAuthenticationBinding("captured subject component has an invalid owner")
		}

		b.hostProviders[input.ProviderID] = &nativeAuthnSubjectProvider{
			provider: provider, capabilities: capabilities,
			descriptor: component.SourceDescriptor, id: input.ProviderID,
			call: newNativeAuthnComponentCall(
				observer, input.ModuleName, input.ComponentName, authnNativeSubjectExtension, authnEvaluateMethod,
			),
		}
		b.addSubjectExecutionAttributes(input)
	default:
		return invalidAuthenticationBinding("native authn source kind is unsupported")
	}

	return nil
}

// resolveAuthenticationComponent selects one captured component and its module capability grant.
func (b *GenerationBindings) resolveAuthenticationComponent(
	moduleName string,
	componentName string,
	kind pluginregistry.ComponentKind,
) (pluginregistry.Component, []pluginapi.Capability, error) {
	if err := pluginapi.ValidateModuleName(moduleName); err != nil {
		return pluginregistry.Component{}, nil, invalidAuthenticationBinding("native authn module identity is invalid")
	}

	if err := pluginapi.ValidateComponentName(componentName); err != nil {
		return pluginregistry.Component{}, nil, invalidAuthenticationBinding("native authn component identity is invalid")
	}

	for _, module := range b.modules {
		if module.moduleName != moduleName {
			continue
		}

		for _, component := range module.components {
			if component.LocalName != componentName {
				continue
			}

			if component.Kind != kind {
				return pluginregistry.Component{}, nil, invalidAuthenticationBinding("native authn component kind does not match")
			}

			return component.Clone(), slices.Clone(module.capabilities), nil
		}
	}

	return pluginregistry.Component{}, nil, invalidAuthenticationBinding("native authn component was not captured")
}

// addEnvironmentExecutionAttributes binds the standard result vocabulary to one scheduled environment source.
func (b *AuthenticationBindings) addEnvironmentExecutionAttributes(input AuthenticationSourceBindingInput) {
	b.addExecutionAttributes(input, authenticationExecutionAttributeSpec{
		identity:       policy.PluginEnvironmentAttributeID,
		suffixes:       []string{authnExecutionSuffixTriggered, "abort", authnExecutionSuffixError},
		detailedSuffix: authnExecutionSuffixTriggered,
		producerType:   policy.CheckTypePluginEnvironment,
		stage:          policy.StagePreAuth,
		category:       policyregistry.AttributeCategoryEnvironment,
	})
}

// addSubjectExecutionAttributes binds the standard result vocabulary to one scheduled subject source.
func (b *AuthenticationBindings) addSubjectExecutionAttributes(input AuthenticationSourceBindingInput) {
	b.addExecutionAttributes(input, authenticationExecutionAttributeSpec{
		identity:       policy.PluginSubjectAttributeID,
		suffixes:       []string{authnExecutionSuffixRejected, authnExecutionSuffixError},
		detailedSuffix: authnExecutionSuffixRejected,
		producerType:   policy.CheckTypePluginSubjectSource,
		stage:          policy.StageSubjectAnalysis,
		category:       policyregistry.AttributeCategorySubject,
	})
}

// addExecutionAttributes binds one source-specific result vocabulary through the shared fact contract.
func (b *AuthenticationBindings) addExecutionAttributes(
	input AuthenticationSourceBindingInput,
	spec authenticationExecutionAttributeSpec,
) {
	for _, suffix := range spec.suffixes {
		definition := policyregistry.AttributeDefinition{
			ID:    spec.identity(input.ModuleName, input.ComponentName, suffix),
			Stage: spec.stage, Operations: slices.Clone(input.Operations),
			ProducerTypes: []string{spec.producerType},
			ProducerCheck: input.InstanceNames[0],
			ProducerOrder: input.Order, Category: spec.category,
			Type: policyregistry.AttributeTypeBool, Source: policyregistry.SourceBuiltin,
		}
		if suffix == spec.detailedSuffix {
			definition.Details = authenticationStatusDetails()
		}

		b.policyAttributes[definition.ID] = definition
	}
}

// authenticationStatusDetails returns detached public response-message metadata for one execution fact.
func authenticationStatusDetails() map[string]policyregistry.DetailDefinition {
	return map[string]policyregistry.DetailDefinition{
		authnStatusMessageDetail: {
			Type: policyregistry.AttributeTypeString, Sensitivity: policyregistry.DetailSensitivityPublic,
			Purpose: policyregistry.DetailPurposeResponseMessage, MaxLength: 256,
		},
	}
}

// addRegisteredPolicyAttributes selects only metadata owned by scheduled native authn sources.
func (b *AuthenticationBindings) addRegisteredPolicyAttributes(
	generation *GenerationBindings,
	sources []AuthenticationSourceBindingInput,
) error {
	for _, module := range generation.modules {
		for _, definition := range module.policyAttributes {
			activation, selected := authenticationAttributeActivationFor(module, definition, sources)
			if !selected {
				continue
			}

			if definition.Source != policyregistry.SourcePlugin {
				return invalidAuthenticationBinding("native policy attribute does not match its selected source")
			}

			if _, duplicate := b.policyAttributes[definition.ID]; duplicate {
				return invalidAuthenticationBinding("native policy attribute identity collides")
			}

			definition.ProducerOrder = activation.order

			definition.Operations = activation.operations
			if len(definition.Operations) == 0 {
				return invalidAuthenticationBinding("native policy attribute has no selected authn operation")
			}

			b.policyAttributes[definition.ID] = policyregistry.CloneDefinition(definition)
		}
	}

	return nil
}

type authenticationAttributeActivation struct {
	operations []policy.Operation
	order      uint32
}

// authenticationAttributeActivationFor resolves optional producer checks against active auth extension owners.
func authenticationAttributeActivationFor(
	module GenerationModuleBinding,
	definition policyregistry.AttributeDefinition,
	sources []AuthenticationSourceBindingInput,
) (authenticationAttributeActivation, bool) {
	activation := authenticationAttributeActivation{}

	for _, producerType := range definition.ProducerTypes {
		switch producerType {
		case policy.CheckTypePluginEnvironment:
			activation.addSources(definition, module.moduleName, AuthenticationSourceEnvironment, sources)
		case policy.CheckTypePluginSubjectSource:
			activation.addSources(definition, module.moduleName, AuthenticationSourceSubject, sources)
		case policy.CheckTypePluginBackend, policy.CheckTypeAccountProvider:
			if definition.ProducerCheck == "" && moduleHasComponent(module, pluginregistry.ComponentKindBackend) {
				activation.addOperations(definition.Operations, 0)
			}
		}
	}

	if len(activation.operations) > 0 {
		return activation, true
	}

	if len(definition.ProducerTypes) == 0 && definition.ProducerCheck == "" &&
		definition.Stage == policy.StageAuthDecision &&
		moduleHasComponent(module, pluginregistry.ComponentKindObligationTarget) {
		activation.addOperations(definition.Operations, 0)
	}

	return activation, len(activation.operations) > 0
}

// addSources merges selected source operations that satisfy the optional exact instance restriction.
func (a *authenticationAttributeActivation) addSources(
	definition policyregistry.AttributeDefinition,
	moduleName string,
	kind AuthenticationSourceKind,
	sources []AuthenticationSourceBindingInput,
) {
	for _, source := range sources {
		if source.ModuleName != moduleName || source.Kind != kind ||
			definition.ProducerCheck != "" && !slices.Contains(source.InstanceNames, definition.ProducerCheck) {
			continue
		}

		a.addOperations(intersectPolicyOperations(definition.Operations, source.Operations), source.Order)
	}
}

// addOperations appends unique activated operations and retains the earliest source order.
func (a *authenticationAttributeActivation) addOperations(operations []policy.Operation, order uint32) {
	for _, operation := range operations {
		if !slices.Contains(a.operations, operation) {
			a.operations = append(a.operations, operation)
		}
	}

	if order > 0 && (a.order == 0 || order < a.order) {
		a.order = order
	}
}

// moduleHasComponent reports whether one immutable module capture owns a public auth extension family.
func moduleHasComponent(module GenerationModuleBinding, kind pluginregistry.ComponentKind) bool {
	for _, component := range module.components {
		if component.Kind == kind {
			return true
		}
	}

	return false
}

// intersectPolicyOperations narrows registered metadata to actions activated by the configured source.
func intersectPolicyOperations(left []policy.Operation, right []policy.Operation) []policy.Operation {
	result := make([]policy.Operation, 0, len(left))
	for _, operation := range left {
		if slices.Contains(right, operation) && !slices.Contains(result, operation) {
			result = append(result, operation)
		}
	}

	return result
}

// addEffectTargets registers every captured public auth effect under its narrow canonical identity.
func (b *AuthenticationBindings) addEffectTargets(
	generation *GenerationBindings,
	input AuthenticationBindingInput,
) error {
	for _, module := range generation.modules {
		providers := make([]policyregistry.ProviderDefinition, 0)
		effects := make([]policyregistry.EffectDefinition, 0)

		for _, component := range module.components {
			if component.Kind != pluginregistry.ComponentKindObligationTarget &&
				component.Kind != pluginregistry.ComponentKindPostActionTarget {
				continue
			}

			provider, effect, err := b.addEffectTarget(module, component, input)
			if err != nil {
				return err
			}

			providers = append(providers, provider)
			effects = append(effects, effect)
		}

		if len(providers) == 0 {
			continue
		}

		ownership, err := policyregistry.NewNamespaceOwnership("plugin.authn."+module.moduleName, []string{policy.AuthnNamespace})
		if err != nil {
			return invalidAuthenticationBinding("native authn effect ownership is invalid")
		}

		contribution, err := policyregistry.NewExtensionDefinitionContribution(
			policyregistry.ExtensionDefinitionContributionInput{
				Ownership: ownership,
				Providers: authenticationExtensionProviders(providers),
				Effects:   effects,
			},
		)
		if err != nil {
			return fmt.Errorf("%w: native authn effect metadata: %v", ErrInvalidAuthenticationBinding, err)
		}

		b.definitions = append(b.definitions, contribution)
	}

	return nil
}

// addEffectTarget prepares one public obligation or post-action owner and its exact catalog definition.
func (b *AuthenticationBindings) addEffectTarget(
	module GenerationModuleBinding,
	component pluginregistry.Component,
	input AuthenticationBindingInput,
) (policyregistry.ProviderDefinition, policyregistry.EffectDefinition, error) {
	identity, err := b.validateEffectTargetIdentity(module, component)
	if err != nil {
		return policyregistry.ProviderDefinition{}, policyregistry.EffectDefinition{}, err
	}

	execution := authenticationEffectExecution(component.Kind)

	provider, effect, err := newAuthenticationEffectDefinitions(identity, execution, input.PostActionAcceptance)
	if err != nil {
		return policyregistry.ProviderDefinition{}, policyregistry.EffectDefinition{}, err
	}

	if err := b.bindAuthenticationEffectOwner(identity, module, component, input); err != nil {
		return policyregistry.ProviderDefinition{}, policyregistry.EffectDefinition{}, err
	}

	return provider, effect, nil
}

// validateEffectTargetIdentity closes canonical identity uniqueness before catalog construction.
func (b *AuthenticationBindings) validateEffectTargetIdentity(
	module GenerationModuleBinding,
	component pluginregistry.Component,
) (string, error) {
	identity, err := policyconfig.AuthnPluginEffectID(module.moduleName, component.LocalName)
	if err != nil {
		return "", invalidAuthenticationBinding("native authn effect identity is invalid")
	}

	if _, duplicate := b.syncEffects[identity]; duplicate {
		return "", invalidAuthenticationBinding("native authn effect identity collides")
	}

	if _, duplicate := b.postActions[identity]; duplicate {
		return "", invalidAuthenticationBinding("native authn effect identity collides")
	}

	return identity, nil
}

// authenticationEffectExecution maps the two public target families to their immutable host execution class.
func authenticationEffectExecution(kind pluginregistry.ComponentKind) policyregistry.ExecutionClass {
	if kind == pluginregistry.ComponentKindPostActionTarget {
		return policyregistry.ExecutionHostPostAction
	}

	return policyregistry.ExecutionHostSync
}

// newAuthenticationEffectDefinitions constructs one matching provider/effect pair for an exact public target.
func newAuthenticationEffectDefinitions(
	identity string,
	execution policyregistry.ExecutionClass,
	acceptance effectsupervisor.Acceptor,
) (policyregistry.ProviderDefinition, policyregistry.EffectDefinition, error) {
	targets, err := authnNativeEffectTargets()
	if err != nil {
		return policyregistry.ProviderDefinition{}, policyregistry.EffectDefinition{}, err
	}

	provider, err := policyregistry.NewProviderDefinition(policyregistry.ProviderDefinitionInput{
		PostActionAcceptance: acceptance,
		ID:                   identity, Targets: targets, Executions: []policyregistry.ExecutionClass{execution},
	})
	if err != nil {
		return policyregistry.ProviderDefinition{}, policyregistry.EffectDefinition{}, err
	}

	effect, err := policyregistry.NewEffectDefinition(policyregistry.EffectDefinitionInput{
		ID: identity, Provider: identity, Targets: targets,
		Kind: policyregistry.EffectKindObligation, Execution: execution,
	})

	return provider, effect, err
}

// bindAuthenticationEffectOwner captures the exact public implementation behind a prepared definition pair.
func (b *AuthenticationBindings) bindAuthenticationEffectOwner(
	identity string,
	module GenerationModuleBinding,
	component pluginregistry.Component,
	input AuthenticationBindingInput,
) error {
	switch component.Kind {
	case pluginregistry.ComponentKindObligationTarget:
		target, ok := component.Value.(pluginapi.ObligationTarget)
		if !ok || nilDecisionDependency(target) {
			return invalidAuthenticationBinding("captured obligation target has an invalid owner")
		}

		b.syncEffects[identity] = &nativeAuthnObligationProvider{
			target: target, id: identity,
			call: newNativeAuthnComponentCall(
				input.Observer, module.moduleName, component.LocalName, authnNativeObligationExtension, "Execute",
			),
		}
	case pluginregistry.ComponentKindPostActionTarget:
		if nilDecisionDependency(input.PostActionAcceptance) {
			return invalidAuthenticationBinding("native authn post-action acceptance is unavailable")
		}

		target, ok := component.Value.(pluginapi.PostActionTarget)
		if !ok || nilDecisionDependency(target) {
			return invalidAuthenticationBinding("captured post-action target has an invalid owner")
		}

		b.postActions[identity] = &nativeAuthnPostActionProvider{
			target: target, capabilities: slices.Clone(module.capabilities), id: identity,
			call: newNativeAuthnComponentCall(
				input.Observer, module.moduleName, component.LocalName, authnNativePostActionExtension, "Enqueue",
			),
		}
	}

	return nil
}

// newNativeAuthnComponentCall captures immutable observation metadata for one public component method.
func newNativeAuthnComponentCall(
	observer Observer,
	moduleName string,
	componentName string,
	extensionPoint string,
	method string,
) nativeAuthnComponentCall {
	return nativeAuthnComponentCall{observer: observer, spec: invokeSpec{
		moduleName: moduleName, componentName: componentName, extensionPoint: extensionPoint, method: method,
	}}
}

// authenticationExtensionProviders wraps effect-only owners without a produced-fact authority.
func authenticationExtensionProviders(
	definitions []policyregistry.ProviderDefinition,
) []policyregistry.ExtensionProviderDefinition {
	result := make([]policyregistry.ExtensionProviderDefinition, 0, len(definitions))
	for _, definition := range definitions {
		result = append(result, policyregistry.ExtensionProviderDefinition{Definition: definition})
	}

	return result
}

// authnNativeEffectTargets returns the immutable authn operations available to public auth effects.
func authnNativeEffectTargets() ([]decision.Target, error) {
	result := make([]decision.Target, 0, 2)

	for _, operation := range []policy.Operation{policy.OperationAuthenticate, policy.OperationLookupIdentity} {
		target, err := decision.NewTarget(policy.AuthnNamespace, string(operation))
		if err != nil {
			return nil, err
		}

		result = append(result, target)
	}

	return result, nil
}

// validateAuthenticationSourceInput closes identity, operation, and ordering metadata before component lookup.
func validateAuthenticationSourceInput(input AuthenticationSourceBindingInput) error {
	module, family, component, ok := policyconfig.ParseAuthnPluginProviderLocal(
		strings.TrimPrefix(input.ProviderID, policy.AuthnNamespace+"/"),
	)
	if err := validateAuthenticationSourceIdentity(input, module, component, ok); err != nil {
		return err
	}

	if err := validateAuthenticationSourceFamily(input.Kind, family); err != nil {
		return err
	}

	if err := validateAuthenticationSourceInstances(input.InstanceNames); err != nil {
		return err
	}

	return validateAuthenticationSourceOperations(input.Operations)
}

// validateAuthenticationSourceIdentity matches the parsed canonical identity and required schedule order.
func validateAuthenticationSourceIdentity(
	input AuthenticationSourceBindingInput,
	module string,
	component string,
	parsed bool,
) error {
	if !parsed || module != input.ModuleName || component != input.ComponentName || input.Order == 0 {
		return invalidAuthenticationBinding("native authn source identity is inconsistent")
	}

	return nil
}

// validateAuthenticationSourceFamily matches the selected source kind to its canonical provider family.
func validateAuthenticationSourceFamily(kind AuthenticationSourceKind, family string) error {
	if kind == AuthenticationSourceEnvironment && family != "environment" ||
		kind == AuthenticationSourceSubject && family != "subject" {
		return invalidAuthenticationBinding("native authn source family is inconsistent")
	}

	if kind != AuthenticationSourceEnvironment && kind != AuthenticationSourceSubject {
		return invalidAuthenticationBinding("native authn source kind is unsupported")
	}

	return nil
}

// validateAuthenticationSourceInstances closes the nonempty unique scheduled-instance set.
func validateAuthenticationSourceInstances(instanceNames []string) error {
	if len(instanceNames) == 0 {
		return invalidAuthenticationBinding("native authn source has no scheduled instances")
	}

	seenInstances := make(map[string]struct{}, len(instanceNames))
	for _, instanceName := range instanceNames {
		if strings.TrimSpace(instanceName) == "" {
			return invalidAuthenticationBinding("native authn source has an invalid scheduled instance")
		}

		if _, duplicate := seenInstances[instanceName]; duplicate {
			return invalidAuthenticationBinding("native authn source has duplicate scheduled instances")
		}

		seenInstances[instanceName] = struct{}{}
	}

	return nil
}

// validateAuthenticationSourceOperations closes the nonempty authn target-operation set.
func validateAuthenticationSourceOperations(operations []policy.Operation) error {
	if len(operations) == 0 {
		return invalidAuthenticationBinding("native authn source has no target operations")
	}

	for _, operation := range operations {
		if operation != policy.OperationAuthenticate && operation != policy.OperationLookupIdentity {
			return invalidAuthenticationBinding("native authn source target operation is unsupported")
		}
	}

	return nil
}

// invalidAuthenticationBinding returns one stable candidate-rejection class without plugin error content.
func invalidAuthenticationBinding(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidAuthenticationBinding, reason)
}

// cloneAuthenticationMap detaches a binding map while retaining immutable program owners.
func cloneAuthenticationMap[T any](input map[string]T) map[string]T {
	result := make(map[string]T, len(input))
	for id, owner := range input {
		result[id] = owner
	}

	return result
}

// ID returns the exact configured environment provider identity.
func (p *nativeAuthnEnvironmentProvider) ID() string { return p.id }

// Kind returns the closed environment host-source family.
func (*nativeAuthnEnvironmentProvider) Kind() string {
	return policyruntime.AuthnHostProviderKindNativeEnvironment
}

// Capabilities returns the detached module grant used for request credential projection.
func (p *nativeAuthnEnvironmentProvider) Capabilities() []pluginapi.Capability {
	return slices.Clone(p.capabilities)
}

// EvaluateEnvironment calls the captured source through the shared timeout and observation boundary.
func (p *nativeAuthnEnvironmentProvider) EvaluateEnvironment(
	ctx context.Context,
	request pluginapi.EnvironmentRequest,
) (result pluginapi.EnvironmentResult, err error) {
	return invokeTimedAuthenticationComponent(
		ctx, p.descriptor.Timeout, p.call,
		func(callbackCtx context.Context) (pluginapi.EnvironmentResult, error) {
			return p.provider.Evaluate(callbackCtx, request)
		},
	)
}

// ID returns the exact configured subject provider identity.
func (p *nativeAuthnSubjectProvider) ID() string { return p.id }

// Kind returns the closed subject host-source family.
func (*nativeAuthnSubjectProvider) Kind() string {
	return policyruntime.AuthnHostProviderKindNativeSubject
}

// Capabilities returns the detached module grant used for request credential projection.
func (p *nativeAuthnSubjectProvider) Capabilities() []pluginapi.Capability {
	return slices.Clone(p.capabilities)
}

// EvaluateSubject calls the captured source through the shared timeout and observation boundary.
func (p *nativeAuthnSubjectProvider) EvaluateSubject(
	ctx context.Context,
	request pluginapi.SubjectRequest,
) (result pluginapi.SubjectResult, err error) {
	return invokeTimedAuthenticationComponent(
		ctx, p.descriptor.Timeout, p.call,
		func(callbackCtx context.Context) (pluginapi.SubjectResult, error) {
			return p.provider.Evaluate(callbackCtx, request)
		},
	)
}

// ID returns the exact canonical effect and provider identity.
func (p *nativeAuthnObligationProvider) ID() string { return p.id }

// ExecuteObligation calls the unchanged public target through the shared observation boundary.
func (p *nativeAuthnObligationProvider) ExecuteObligation(
	ctx context.Context,
	request pluginapi.ObligationRequest,
) (result pluginapi.ObligationResult, err error) {
	return invokeAuthenticationComponent(
		ctx, p.call,
		func(callbackCtx context.Context) (pluginapi.ObligationResult, error) {
			return p.target.Execute(callbackCtx, request)
		},
	)
}

// Execute delegates selected obligation application to the admitted request-local authn host.
func (p *nativeAuthnObligationProvider) Execute(
	ctx context.Context,
	execution policyruntime.EffectExecution,
) effectsupervisor.Result {
	if p == nil || p.id != execution.EffectID() || p.id != execution.Provider() {
		return effectsupervisor.Failed("native_authn_obligation_binding")
	}

	host, ok := policyruntime.AuthnNativeEffectHostFromContext(ctx)
	if !ok {
		return effectsupervisor.Failed("native_authn_obligation_host")
	}

	return host.ExecuteAuthnNativeObligation(ctx, p, execution)
}

// ID returns the exact canonical effect and provider identity.
func (p *nativeAuthnPostActionProvider) ID() string { return p.id }

// Capabilities returns the detached module grant used for post-action credential projection.
func (p *nativeAuthnPostActionProvider) Capabilities() []pluginapi.Capability {
	return slices.Clone(p.capabilities)
}

// EnqueuePostAction calls the unchanged public target through the shared observation boundary.
func (p *nativeAuthnPostActionProvider) EnqueuePostAction(
	ctx context.Context,
	request pluginapi.PostActionRequest,
) (result pluginapi.PostActionEnqueueResult, err error) {
	return invokeAuthenticationComponent(
		ctx, p.call,
		func(callbackCtx context.Context) (pluginapi.PostActionEnqueueResult, error) {
			return p.target.Enqueue(callbackCtx, request)
		},
	)
}

// invokeTimedAuthenticationComponent applies a captured timeout before the shared native call boundary.
func invokeTimedAuthenticationComponent[T any](
	ctx context.Context,
	timeout time.Duration,
	call nativeAuthnComponentCall,
	callback func(context.Context) (T, error),
) (T, error) {
	callCtx, cancel := authnNativeCallContext(ctx, timeout)
	defer cancel()

	return invokeAuthenticationComponent(callCtx, call, callback)
}

// invokeAuthenticationComponent executes one typed public component through the shared observation boundary.
func invokeAuthenticationComponent[T any](
	ctx context.Context,
	call nativeAuthnComponentCall,
	callback func(context.Context) (T, error),
) (result T, err error) {
	err = invokePluginCall(ctx, call.observer, call.spec, func(callbackCtx context.Context) error {
		result, err = callback(callbackCtx)

		return err
	})

	return result, err
}

// Prepare delegates detached work capture to the admitted request-local authn host.
func (p *nativeAuthnPostActionProvider) Prepare(
	ctx context.Context,
	execution policyruntime.EffectExecution,
) (effectsupervisor.Work, error) {
	if p == nil || p.id != execution.EffectID() || p.id != execution.Provider() {
		return nil, invalidAuthenticationBinding("native authn post-action binding does not match selection")
	}

	host, ok := policyruntime.AuthnNativeEffectHostFromContext(ctx)
	if !ok {
		return nil, invalidAuthenticationBinding("native authn post-action host is unavailable")
	}

	return host.PrepareAuthnNativePostAction(ctx, p, execution)
}

// authnNativeCallContext applies the descriptor bound without inventing an ambient timeout.
func authnNativeCallContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}

	if timeout <= 0 {
		return context.WithCancel(ctx)
	}

	return context.WithTimeout(ctx, timeout)
}

var _ policyruntime.AuthnHostProvider = (*nativeAuthnEnvironmentProvider)(nil)
var _ policyruntime.AuthnHostProvider = (*nativeAuthnSubjectProvider)(nil)
var _ policyruntime.SyncEffectProvider = (*nativeAuthnObligationProvider)(nil)
var _ policyruntime.PostActionProvider = (*nativeAuthnPostActionProvider)(nil)
