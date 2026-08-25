// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"context"
	"fmt"

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/nativebinding"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

// ConfiguredNativeGenerationInput carries static activation and frozen native capabilities into one candidate.
type ConfiguredNativeGenerationInput struct {
	Bindings             nativebinding.DecisionBindingPreparer
	PostActionAcceptance effectsupervisor.Acceptor
	Observer             nativebinding.Observer
	Policy               policyconfig.PolicyConfig
	NativeModules        []policyruntime.NativeModuleBindingInput
}

// configuredNativeGenerationBuilder resolves one static snapshot without ambient plugin lookup.
type configuredNativeGenerationBuilder struct {
	ctx                 context.Context
	bindings            nativebinding.DecisionBindingPreparer
	acceptance          effectsupervisor.Acceptor
	observer            nativebinding.Observer
	policy              policyconfig.PolicyConfig
	definitions         configuredDefinitionIndex
	authorities         map[string]*configuredNativeAuthority
	preparedDefinitions []registry.DefinitionContribution
	factInputs          []nativebinding.DecisionFactBindingInput
	effectInputs        []nativebinding.DecisionEffectBindingInput
	factBindings        map[string]policyruntime.FactProviderBinding
	syncBindings        map[string]policyruntime.SyncEffectProvider
	postBindings        map[string]policyruntime.PostActionProvider
}

// configuredNativeAuthority groups exact configured definitions by one plugin module owner.
type configuredNativeAuthority struct {
	namespaces map[string]struct{}
	providers  []registry.ProviderDefinition
	effects    []registry.EffectDefinition
	moduleName string
}

// PrepareConfiguredNativeGeneration resolves only configured native providers from immutable process bindings.
func PrepareConfiguredNativeGeneration(
	ctx context.Context,
	input ConfiguredNativeGenerationInput,
) (policyruntime.ExtensionPreparation, error) {
	ctx = normalizeConfiguredPreparationContext(ctx)
	if err := ctx.Err(); err != nil {
		return policyruntime.ExtensionPreparation{}, err
	}

	if nilConfiguredPreparationDependency(input.PostActionAcceptance) {
		return policyruntime.ExtensionPreparation{}, invalidNativeGenerationRegistration(
			"post-action acceptance is required",
		)
	}

	if !nilConfiguredPreparationDependency(input.Bindings) {
		if err := input.Bindings.ValidateArtifacts(); err != nil {
			return policyruntime.ExtensionPreparation{}, err
		}
	}

	normalized, err := Normalize(ctx, policyconfig.Document{Policy: input.Policy})
	if err != nil {
		return policyruntime.ExtensionPreparation{}, nativePreparationError(ctx, "policy configuration was rejected")
	}

	builder := newConfiguredNativeGenerationBuilder(ctx, normalized.Policy, input)
	if err = builder.definitions.index(normalized.Definitions, invalidNativeGenerationRegistration); err != nil {
		return policyruntime.ExtensionPreparation{}, err
	}

	if err = builder.prepareProviders(); err != nil {
		return policyruntime.ExtensionPreparation{}, err
	}

	if err = builder.prepareBindings(); err != nil {
		return policyruntime.ExtensionPreparation{}, err
	}

	return builder.extensionPreparation(input.NativeModules)
}

// newConfiguredNativeGenerationBuilder initializes isolated indexes for one native candidate.
func newConfiguredNativeGenerationBuilder(
	ctx context.Context,
	policy policyconfig.PolicyConfig,
	input ConfiguredNativeGenerationInput,
) *configuredNativeGenerationBuilder {
	return &configuredNativeGenerationBuilder{
		ctx: ctx, bindings: input.Bindings, acceptance: input.PostActionAcceptance, observer: input.Observer,
		policy: policy, definitions: newConfiguredDefinitionIndex(policy),
		authorities:  make(map[string]*configuredNativeAuthority),
		factBindings: make(map[string]policyruntime.FactProviderBinding),
		syncBindings: make(map[string]policyruntime.SyncEffectProvider),
		postBindings: make(map[string]policyruntime.PostActionProvider),
	}
}

// prepareProviders resolves configured native entries and builds exact authority-owned inputs.
func (b *configuredNativeGenerationBuilder) prepareProviders() error {
	for _, namespace := range sortedConfiguredKeys(b.policy.Namespaces) {
		if err := b.ctx.Err(); err != nil {
			return err
		}

		configuredNamespace := b.policy.Namespaces[namespace]
		for _, name := range sortedConfiguredKeys(configuredNamespace.Providers) {
			if err := b.ctx.Err(); err != nil {
				return err
			}

			provider := configuredNamespace.Providers[name]
			if provider.Kind != policyconfig.ProviderKindNative {
				continue
			}

			if nilConfiguredPreparationDependency(b.bindings) {
				return invalidNativeGenerationRegistration("configured native module binding is missing")
			}

			if err := b.prepareProvider(namespace, name, provider); err != nil {
				return err
			}
		}
	}

	for _, moduleName := range sortedConfiguredKeys(b.authorities) {
		if err := b.ctx.Err(); err != nil {
			return err
		}

		if err := b.freezeAuthority(b.authorities[moduleName]); err != nil {
			return err
		}
	}

	return nil
}

// prepareProvider classifies one configured native component as a fact or effect owner.
func (b *configuredNativeGenerationBuilder) prepareProvider(
	namespace string,
	name string,
	configured policyconfig.ProviderConfig,
) error {
	providerID := CanonicalProviderID(namespace, name, configured)

	definition, exists := b.definitions.providers[providerID]
	if !exists || definition.ID() != providerID {
		return invalidNativeGenerationRegistration("configured native provider definition is missing")
	}

	effects := b.definitions.effectsByProvider[providerID]
	hasFacts := len(definition.Outputs()) > 0
	hasEffects := len(effects) > 0

	if hasFacts == hasEffects {
		return invalidNativeGenerationRegistration("configured native provider capability is incomplete or ambiguous")
	}

	group := b.authority(configured.Module)
	group.namespaces[namespace] = struct{}{}
	group.providers = append(group.providers, definition)

	if hasFacts {
		if len(definition.Executions()) != 0 {
			return invalidNativeGenerationRegistration("configured native fact provider declares effect execution")
		}

		b.factInputs = append(b.factInputs, nativebinding.DecisionFactBindingInput{
			Definition: definition, ModuleName: configured.Module, ComponentName: name,
		})

		return nil
	}

	if !providerExecutionsMatchEffects(definition.Executions(), effects) {
		return invalidNativeGenerationRegistration("configured native effect capability is incomplete")
	}

	effectDefinition, err := configuredEffectProviderDefinition(definition, b.acceptance)
	if err != nil {
		return invalidNativeGenerationRegistration("configured native effect metadata was rejected")
	}

	b.effectInputs = append(b.effectInputs, nativebinding.DecisionEffectBindingInput{
		Definition: effectDefinition, Effects: effects, ModuleName: configured.Module, ComponentName: name,
	})
	group.effects = append(group.effects, effects...)

	return nil
}

// authority returns one deterministic plugin-module preparation group.
func (b *configuredNativeGenerationBuilder) authority(moduleName string) *configuredNativeAuthority {
	group, exists := b.authorities[moduleName]
	if exists {
		return group
	}

	group = &configuredNativeAuthority{
		moduleName: moduleName,
		namespaces: make(map[string]struct{}),
	}
	b.authorities[moduleName] = group

	return group
}

// freezeAuthority retains exact normalized metadata under one host-assigned plugin owner.
func (b *configuredNativeGenerationBuilder) freezeAuthority(group *configuredNativeAuthority) error {
	ownership, err := registry.NewNamespaceOwnership(
		"plugin."+group.moduleName,
		sortedConfiguredKeys(group.namespaces),
	)
	if err != nil {
		return invalidNativeGenerationRegistration("configured native namespace ownership was rejected")
	}

	providers := make([]registry.ExtensionProviderDefinition, 0, len(group.providers))
	for _, definition := range group.providers {
		configuredDefinition := configuredEffectProviderDefinition
		if len(definition.Outputs()) > 0 {
			configuredDefinition = configuredProviderDefinition
		}

		configured, configuredErr := configuredDefinition(definition, b.acceptance)
		if configuredErr != nil {
			return invalidNativeGenerationRegistration("configured native provider metadata was rejected")
		}

		prefix := ""
		if len(configured.Outputs()) > 0 {
			prefix = "plugin." + group.moduleName + "."
		}

		providers = append(providers, registry.ExtensionProviderDefinition{
			Definition: configured, ProducedFactPrefix: prefix,
		})
	}

	contribution, err := registry.NewExtensionDefinitionContribution(registry.ExtensionDefinitionContributionInput{
		Ownership: ownership, Providers: providers, Effects: group.effects,
	})
	if err != nil {
		return invalidNativeGenerationRegistration("configured native contribution metadata was rejected")
	}

	b.preparedDefinitions = append(b.preparedDefinitions, contribution)

	return nil
}

// prepareBindings adapts exact configured selections through the frozen native runtime boundary.
func (b *configuredNativeGenerationBuilder) prepareBindings() error {
	if len(b.factInputs)+len(b.effectInputs) == 0 {
		return nil
	}

	prepared, err := b.bindings.PrepareDecisionBindings(b.ctx, nativebinding.DecisionBindingInput{
		Observer: b.observer, FactProviders: b.factInputs, EffectProviders: b.effectInputs,
	})
	if err != nil {
		return nativePreparationError(b.ctx, "configured native generation was rejected")
	}

	if err = mergeConfiguredBindings(
		b.factBindings,
		prepared.FactProviders(),
		invalidNativeGenerationRegistration,
	); err != nil {
		return err
	}

	if err = mergeConfiguredBindings(
		b.syncBindings,
		prepared.SyncEffects(),
		invalidNativeGenerationRegistration,
	); err != nil {
		return err
	}

	return mergeConfiguredBindings(
		b.postBindings,
		prepared.PostActions(),
		invalidNativeGenerationRegistration,
	)
}

// extensionPreparation returns only activated native contributions and frozen callback owners.
func (b *configuredNativeGenerationBuilder) extensionPreparation(
	nativeModules []policyruntime.NativeModuleBindingInput,
) (policyruntime.ExtensionPreparation, error) {
	return configuredExtensionPreparation(configuredExtensionPreparationInput{
		acceptance: b.acceptance, definitions: b.preparedDefinitions,
		factBindings: b.factBindings, syncBindings: b.syncBindings, postBindings: b.postBindings,
		nativeModules: nativeModules, reject: invalidNativeGenerationRegistration,
	})
}

// nativePreparationError preserves cancellation and otherwise returns one bounded native class.
func nativePreparationError(ctx context.Context, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	return invalidNativeGenerationRegistration(reason)
}

// invalidNativeGenerationRegistration returns the bounded native binding failure class.
func invalidNativeGenerationRegistration(reason string) error {
	return fmt.Errorf("%w: %s", nativebinding.ErrInvalidDecisionBinding, reason)
}
