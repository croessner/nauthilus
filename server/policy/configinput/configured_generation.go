// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

// configuredExtensionPreparationInput owns one aggregate candidate binding set.
type configuredExtensionPreparationInput struct {
	acceptance    effectsupervisor.Acceptor
	definitions   []registry.DefinitionContribution
	factBindings  map[string]policyruntime.FactProviderBinding
	syncBindings  map[string]policyruntime.SyncEffectProvider
	postBindings  map[string]policyruntime.PostActionProvider
	nativeModules []policyruntime.NativeModuleBindingInput
	reject        func(string) error
}

// configuredDefinitionIndex owns normalized provider and effect metadata for one candidate snapshot.
type configuredDefinitionIndex struct {
	providers         map[string]registry.ProviderDefinition
	effectsByProvider map[string][]registry.EffectDefinition
	effectIDs         map[string]struct{}
	configuredEffects map[string]policyconfig.EffectConfig
	policy            policyconfig.PolicyConfig
}

// newConfiguredDefinitionIndex initializes isolated immutable-definition indexes.
func newConfiguredDefinitionIndex(policy policyconfig.PolicyConfig) configuredDefinitionIndex {
	return configuredDefinitionIndex{
		providers:         make(map[string]registry.ProviderDefinition),
		effectsByProvider: make(map[string][]registry.EffectDefinition),
		effectIDs:         make(map[string]struct{}),
		configuredEffects: make(map[string]policyconfig.EffectConfig),
		policy:            policy,
	}
}

// index retains exact normalized provider and effect contracts by identity.
func (i *configuredDefinitionIndex) index(
	contributions []registry.DefinitionContribution,
	reject func(string) error,
) error {
	for _, contribution := range contributions {
		for _, provider := range contribution.Providers() {
			if _, exists := i.providers[provider.ID()]; exists {
				return reject("normalized provider identity is ambiguous")
			}

			i.providers[provider.ID()] = provider
		}

		for _, effect := range contribution.Effects() {
			if _, exists := i.effectIDs[effect.ID()]; exists {
				return reject("normalized effect identity is ambiguous")
			}

			i.effectIDs[effect.ID()] = struct{}{}

			configured, exists := configuredEffect(i.policy, effect.ID())
			if exists {
				i.configuredEffects[effect.ID()] = configured
			}

			if effect.Provider() != "" {
				i.effectsByProvider[effect.Provider()] = append(i.effectsByProvider[effect.Provider()], effect)
			}
		}
	}

	return nil
}

// configuredExtensionPreparation constructs one immutable aggregate without widening owner authority.
func configuredExtensionPreparation(
	input configuredExtensionPreparationInput,
) (policyruntime.ExtensionPreparation, error) {
	bindings, err := policyruntime.NewBindingSet(policyruntime.BindingSetInput{
		FactProviders: input.factBindings, SyncEffects: input.syncBindings, PostActions: input.postBindings,
		NativeModules: input.nativeModules, PostActionAcceptance: input.acceptance,
	})
	if err != nil {
		return policyruntime.ExtensionPreparation{}, input.reject("configured binding aggregate was rejected")
	}

	return policyruntime.ExtensionPreparation{
		Definitions: append([]registry.DefinitionContribution(nil), input.definitions...),
		Bindings:    bindings,
	}, nil
}
