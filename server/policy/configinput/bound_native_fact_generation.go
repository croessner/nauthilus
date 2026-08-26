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
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/nativebinding"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

// BoundNativeFactGenerationInput joins raw policy selections with real captured generic native capabilities.
type BoundNativeFactGenerationInput struct {
	Bindings             nativebinding.DecisionBindingPreparer
	PostActionAcceptance effectsupervisor.Acceptor
	Observer             nativebinding.Observer
	Policy               policyconfig.PolicyConfig
	Capabilities         []registry.NativeFactProviderCapability
	NativeModules        []policyruntime.NativeModuleBindingInput
	Resources            []policyruntime.CandidateResource
}

// boundNativeFactGenerationBuilder owns descriptor selection for one detached candidate.
type boundNativeFactGenerationBuilder struct {
	ctx          context.Context
	bindings     nativebinding.DecisionBindingPreparer
	acceptance   effectsupervisor.Acceptor
	observer     nativebinding.Observer
	policy       policyconfig.PolicyConfig
	normalizer   *policyNormalizer
	capabilities map[string]registry.NativeFactProviderCapability
	authorities  map[string]*boundNativeFactAuthority
	factInputs   []nativebinding.DecisionFactBindingInput
	modules      map[string]struct{}
}

// boundNativeFactAuthority groups exact selected definitions by captured module owner.
type boundNativeFactAuthority struct {
	namespaces map[string]struct{}
	providers  []registry.ExtensionProviderDefinition
	moduleName string
}

// PrepareBoundNativeFactGeneration resolves descriptor-owned output shapes before catalog normalization.
func PrepareBoundNativeFactGeneration(
	ctx context.Context,
	input BoundNativeFactGenerationInput,
) (policyruntime.ExtensionPreparation, error) {
	ctx = normalizeConfiguredPreparationContext(ctx)
	if err := ctx.Err(); err != nil {
		return policyruntime.ExtensionPreparation{}, err
	}

	if nilConfiguredPreparationDependency(input.PostActionAcceptance) {
		return policyruntime.ExtensionPreparation{}, invalidBoundNativeFactGeneration(
			"post-action acceptance is required",
		)
	}

	document := policyconfig.Normalize(policyconfig.Document{Policy: input.Policy})
	if err := policyconfig.Validate(document); err != nil {
		return policyruntime.ExtensionPreparation{}, err
	}

	if !nilConfiguredPreparationDependency(input.Bindings) {
		if err := input.Bindings.ValidateArtifacts(); err != nil {
			return policyruntime.ExtensionPreparation{}, err
		}
	}

	builder, err := newBoundNativeFactGenerationBuilder(ctx, document.Policy, input)
	if err != nil {
		return policyruntime.ExtensionPreparation{}, err
	}

	if err = builder.prepare(); err != nil {
		return policyruntime.ExtensionPreparation{}, err
	}

	return builder.extensionPreparation(input.NativeModules, input.Resources)
}

// newBoundNativeFactGenerationBuilder validates detached capability identities and target indexes.
func newBoundNativeFactGenerationBuilder(
	ctx context.Context,
	policy policyconfig.PolicyConfig,
	input BoundNativeFactGenerationInput,
) (*boundNativeFactGenerationBuilder, error) {
	normalizer := newPolicyNormalizer(policy, nil)
	if err := normalizer.indexTargets(); err != nil {
		return nil, err
	}

	capabilities, err := indexBoundNativeFactCapabilities(input.Capabilities)
	if err != nil {
		return nil, err
	}

	return &boundNativeFactGenerationBuilder{
		ctx: ctx, bindings: input.Bindings, acceptance: input.PostActionAcceptance, observer: input.Observer,
		policy: policy, normalizer: normalizer, capabilities: capabilities,
		authorities: make(map[string]*boundNativeFactAuthority), modules: make(map[string]struct{}),
	}, nil
}

// indexBoundNativeFactCapabilities validates exact identities and rejects ambiguous descriptor projections.
func indexBoundNativeFactCapabilities(
	input []registry.NativeFactProviderCapability,
) (map[string]registry.NativeFactProviderCapability, error) {
	result := make(map[string]registry.NativeFactProviderCapability, len(input))
	for _, capability := range input {
		if err := capability.Validate(); err != nil {
			return nil, err
		}

		providerID := capability.ProviderID()
		if _, exists := result[providerID]; exists {
			return nil, invalidBoundNativeFactGeneration("captured native fact capability is duplicated")
		}

		result[providerID] = capability
	}

	return result, nil
}

// prepare selects every configured generic native fact provider and resolves real runtime bindings once.
func (b *boundNativeFactGenerationBuilder) prepare() error {
	for _, namespace := range sortedConfiguredKeys(b.policy.Namespaces) {
		if err := b.ctx.Err(); err != nil {
			return err
		}

		configuredNamespace := b.policy.Namespaces[namespace]
		for _, name := range sortedConfiguredKeys(configuredNamespace.Providers) {
			provider := configuredNamespace.Providers[name]
			if provider.Kind != policyconfig.ProviderKindNative || len(provider.ProducedFacts) == 0 {
				continue
			}

			if err := b.prepareProvider(namespace, name, provider); err != nil {
				return err
			}
		}
	}

	if len(b.factInputs) == 0 {
		return nil
	}

	if nilConfiguredPreparationDependency(b.bindings) {
		return invalidBoundNativeFactGeneration("configured native fact binding owner is missing")
	}

	return nil
}

// prepareProvider binds one exact operator schedule to its captured descriptor capability.
func (b *boundNativeFactGenerationBuilder) prepareProvider(
	namespace string,
	name string,
	configured policyconfig.ProviderConfig,
) error {
	if len(configured.Executions) != 0 {
		return invalidBoundNativeFactGeneration("configured native fact provider declares effect execution")
	}

	providerID := CanonicalProviderID(namespace, name, configured)

	capability, exists := b.capabilities[providerID]
	if !exists || capability.ModuleName() != configured.Module ||
		capability.ComponentName() != name || capability.Namespace() != namespace {
		return invalidBoundNativeFactGeneration("configured native fact provider descriptor is missing")
	}

	targets, err := b.configuredProviderTargets(namespace, name, providerID, configured)
	if err != nil {
		return err
	}

	requires := make([]string, 0, len(configured.Requires))
	for _, requirement := range configured.Requires {
		requires = append(requires, b.normalizer.resolveProviderReference(namespace, requirement))
	}

	selected, err := capability.Select(registry.NativeFactProviderSelectionInput{
		Targets: targets, Requires: requires, ProducedFacts: configured.ProducedFacts,
		Failure: registry.ProviderFailureBehavior(configured.Failure), Timeout: configured.Timeout,
		DiagnosticID: configured.Diagnostics.PublicID,
	})
	if err != nil {
		return invalidBoundNativeFactGeneration("configured native fact provider exceeds its captured descriptor")
	}

	authority := b.authority(configured.Module)
	authority.namespaces[namespace] = struct{}{}
	authority.providers = append(authority.providers, selected)
	b.factInputs = append(b.factInputs, nativebinding.DecisionFactBindingInput{
		Definition: selected.Definition, ModuleName: configured.Module, ComponentName: name,
	})
	b.modules[configured.Module] = struct{}{}

	return nil
}

// configuredProviderTargets requires declared targets to equal exact action-filtered plan scheduling.
func (b *boundNativeFactGenerationBuilder) configuredProviderTargets(
	namespace string,
	name string,
	providerID string,
	configured policyconfig.ProviderConfig,
) ([]decision.Target, error) {
	scheduled, err := b.scheduledProviderTargets(namespace, providerID)
	if err != nil {
		return nil, err
	}

	if len(scheduled) == 0 {
		return nil, invalidBoundNativeFactGeneration("configured native fact provider is not used by an active target plan")
	}

	path := "policy.namespaces." + namespace + ".providers." + name + ".targets"

	declared, err := normalizeTargetReferences(path, namespace, configured.Targets)
	if err != nil {
		return nil, err
	}

	if len(declared) == 0 {
		return scheduled, nil
	}

	if !sameBoundNativeTargets(declared, scheduled) {
		return nil, invalidBoundNativeFactGeneration(
			"configured native fact targets do not exactly match active plan scheduling",
		)
	}

	return declared, nil
}

// scheduledProviderTargets derives exact action-filtered uses from configured active domain plans.
func (b *boundNativeFactGenerationBuilder) scheduledProviderTargets(
	namespace string,
	providerID string,
) ([]decision.Target, error) {
	targets := make([]decision.Target, 0)
	for _, target := range b.normalizer.targets {
		if target.target.Namespace() != namespace || target.config.DomainPlan == "" {
			continue
		}

		plan, err := b.normalizer.selectedDomainPlan(target)
		if err != nil {
			return nil, err
		}

		if boundNativePlanSchedulesProvider(b.normalizer, target.target, plan, providerID) {
			targets = append(targets, target.target)
		}
	}

	return targets, nil
}

// boundNativePlanSchedulesProvider checks exact provider identity and instance action applicability.
func boundNativePlanSchedulesProvider(
	normalizer *policyNormalizer,
	target decision.Target,
	plan policyconfig.DomainPlanConfig,
	providerID string,
) bool {
	for _, checkpoint := range plan.Checkpoints {
		for _, instance := range checkpoint.Providers {
			if providerInstanceAllowsAction(instance, target.Action()) &&
				normalizer.resolveProviderReference(target.Namespace(), instance.Use) == providerID {
				return true
			}
		}
	}

	return false
}

// sameBoundNativeTargets compares two duplicate-free target sets without changing configured order.
func sameBoundNativeTargets(left []decision.Target, right []decision.Target) bool {
	if len(left) != len(right) {
		return false
	}

	expected := make(map[string]struct{}, len(right))
	for _, target := range right {
		expected[target.String()] = struct{}{}
	}

	seen := make(map[string]struct{}, len(left))
	for _, target := range left {
		if _, exists := expected[target.String()]; !exists {
			return false
		}

		if _, duplicate := seen[target.String()]; duplicate {
			return false
		}

		seen[target.String()] = struct{}{}
	}

	return len(seen) == len(expected)
}

// authority returns one deterministic module-owned contribution group.
func (b *boundNativeFactGenerationBuilder) authority(moduleName string) *boundNativeFactAuthority {
	group, exists := b.authorities[moduleName]
	if exists {
		return group
	}

	group = &boundNativeFactAuthority{
		moduleName: moduleName,
		namespaces: make(map[string]struct{}),
	}
	b.authorities[moduleName] = group

	return group
}

// definitionContributions freezes selected providers under exact plugin module ownership.
func (b *boundNativeFactGenerationBuilder) definitionContributions() ([]registry.DefinitionContribution, error) {
	definitions := make([]registry.DefinitionContribution, 0, len(b.authorities))
	for _, moduleName := range sortedConfiguredKeys(b.authorities) {
		group := b.authorities[moduleName]

		ownership, err := registry.NewNamespaceOwnership(
			"plugin."+group.moduleName,
			sortedConfiguredKeys(group.namespaces),
		)
		if err != nil {
			return nil, invalidBoundNativeFactGeneration("native fact namespace ownership was rejected")
		}

		contribution, err := registry.NewExtensionDefinitionContribution(
			registry.ExtensionDefinitionContributionInput{
				Ownership: ownership, Providers: group.providers,
			},
		)
		if err != nil {
			return nil, invalidBoundNativeFactGeneration("native fact contribution metadata was rejected")
		}

		definitions = append(definitions, contribution)
	}

	return definitions, nil
}

// extensionPreparation invokes real binding adapters and owns exact module and candidate resource metadata.
func (b *boundNativeFactGenerationBuilder) extensionPreparation(
	nativeModules []policyruntime.NativeModuleBindingInput,
	resources []policyruntime.CandidateResource,
) (policyruntime.ExtensionPreparation, error) {
	if err := b.validateNativeModules(nativeModules); err != nil {
		return policyruntime.ExtensionPreparation{}, err
	}

	definitions, err := b.definitionContributions()
	if err != nil {
		return policyruntime.ExtensionPreparation{}, err
	}

	factBindings := make(map[string]policyruntime.FactProviderBinding)

	if len(b.factInputs) > 0 {
		prepared, prepareErr := b.bindings.PrepareDecisionBindings(b.ctx, nativebinding.DecisionBindingInput{
			Observer: b.observer, FactProviders: b.factInputs,
		})
		if prepareErr != nil {
			return policyruntime.ExtensionPreparation{}, nativePreparationError(
				b.ctx,
				"descriptor-bound native fact generation was rejected",
			)
		}

		if err = mergeConfiguredBindings(
			factBindings,
			prepared.FactProviders(),
			invalidBoundNativeFactGeneration,
		); err != nil {
			return policyruntime.ExtensionPreparation{}, err
		}
	}

	preparation, err := configuredExtensionPreparation(configuredExtensionPreparationInput{
		acceptance: b.acceptance, definitions: definitions, factBindings: factBindings,
		syncBindings:  make(map[string]policyruntime.SyncEffectProvider),
		postBindings:  make(map[string]policyruntime.PostActionProvider),
		nativeModules: nativeModules, reject: invalidBoundNativeFactGeneration,
	})
	if err != nil {
		return policyruntime.ExtensionPreparation{}, err
	}

	preparation.Resources = append([]policyruntime.CandidateResource(nil), resources...)

	return preparation, nil
}

// validateNativeModules requires generation metadata for every selected descriptor authority.
func (b *boundNativeFactGenerationBuilder) validateNativeModules(
	configured []policyruntime.NativeModuleBindingInput,
) error {
	available := make(map[string]struct{}, len(configured))
	for _, module := range configured {
		available[module.ModuleName] = struct{}{}
	}

	for moduleName := range b.modules {
		if _, exists := available[moduleName]; !exists {
			return invalidBoundNativeFactGeneration("selected native fact module metadata is missing")
		}
	}

	return nil
}

// invalidBoundNativeFactGeneration returns the stable inward native binding error class.
func invalidBoundNativeFactGeneration(reason string) error {
	return fmt.Errorf("%w: %s", nativebinding.ErrInvalidDecisionBinding, reason)
}
