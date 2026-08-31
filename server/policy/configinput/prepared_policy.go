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
	"slices"
	"sort"
	"strings"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	policy "github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/admission"
	"github.com/croessner/nauthilus/v4/server/policy/callerauth"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

// AuthnPluginSourceDefinition is one exact scheduled public native authn source selection.
type AuthnPluginSourceDefinition struct {
	InstanceNames []string
	Operations    []policy.Operation
	ProviderID    string
	ModuleName    string
	ComponentName string
	Family        string
	Order         uint32
}

var _ policyruntime.PolicyModel = (*PreparedPolicy)(nil)

// PreparedPolicy is the sole normalized configuration material passed through generation assembly.
type PreparedPolicy struct {
	configured policyconfig.PolicyConfig
	structural UnifiedPolicyInput
	generation uint64
}

// PreparePolicy validates and owns one top-level Policy configuration candidate exactly once.
func PreparePolicy(ctx context.Context, generation uint64, configured policyconfig.PolicyConfig) (*PreparedPolicy, error) {
	if generation == 0 {
		return nil, fmt.Errorf("policy generation identity must be positive")
	}

	if err := validateConfiguredSecretBindings(configured); err != nil {
		return nil, err
	}

	document := policyconfig.Normalize(policyconfig.Document{Policy: configured})
	if err := policyconfig.Validate(document); err != nil {
		return nil, err
	}

	structural, err := Normalize(ctx, policyconfig.Document{Policy: structuralPolicy(document.Policy)})
	if err != nil {
		return nil, err
	}

	return &PreparedPolicy{
		configured: policyconfig.Normalize(document).Policy,
		structural: cloneUnifiedPolicyInput(structural),
		generation: generation,
	}, nil
}

// ClonePolicyModel returns a deeply detached normalized policy material owner.
func (p *PreparedPolicy) ClonePolicyModel() policyruntime.PolicyModel {
	if p == nil {
		return (*PreparedPolicy)(nil)
	}

	return &PreparedPolicy{
		configured: policyconfig.Normalize(policyconfig.Document{Policy: p.configured}).Policy,
		structural: cloneUnifiedPolicyInput(p.structural),
		generation: p.generation,
	}
}

// ValidatePolicyModel revalidates immutable identity and standalone semantic invariants.
func (p *PreparedPolicy) ValidatePolicyModel() error {
	if p == nil || p.generation == 0 {
		return fmt.Errorf("prepared policy is incomplete")
	}

	if err := validateConfiguredSecretBindings(p.configured); err != nil {
		return err
	}

	return policyconfig.Validate(policyconfig.Document{Policy: p.configured})
}

// GenerationID returns the candidate identity owned by this normalized material.
func (p *PreparedPolicy) GenerationID() uint64 {
	if p == nil {
		return 0
	}

	return p.generation
}

// Compile builds the sole target catalog and exact definition material from this candidate.
func (p *PreparedPolicy) Compile(
	ctx context.Context,
	acceptance effectsupervisor.Acceptor,
) (*policyruntime.TargetCatalog, []registry.DefinitionContribution, error) {
	if err := p.ValidatePolicyModel(); err != nil {
		return nil, nil, err
	}

	if configuredExtensionFacts(p.configured) {
		return nil, nil, fmt.Errorf("configured Policy extension facts require real prepared bindings")
	}

	return p.structural.compileMaterial(ctx, acceptance)
}

// CompileWithExtensions builds the catalog only after real extension metadata has been prepared.
func (p *PreparedPolicy) CompileWithExtensions(
	ctx context.Context,
	acceptance effectsupervisor.Acceptor,
	extensions []registry.DefinitionContribution,
) (*policyruntime.TargetCatalog, []registry.DefinitionContribution, error) {
	return p.CompileCandidate(ctx, acceptance, extensions, nil)
}

// CompileCandidate builds the catalog from every real prepared extension and registry-script fact owner.
func (p *PreparedPolicy) CompileCandidate(
	ctx context.Context,
	acceptance effectsupervisor.Acceptor,
	extensions []registry.DefinitionContribution,
	authnLuaFacts []registry.AuthnLuaFactDeclaration,
) (*policyruntime.TargetCatalog, []registry.DefinitionContribution, error) {
	return p.CompileCandidateWithAuthnExtensions(ctx, acceptance, extensions, authnLuaFacts, nil, nil)
}

// CompileCandidateWithAuthnExtensions adds captured public auth metadata and implicit selected-effect owners.
func (p *PreparedPolicy) CompileCandidateWithAuthnExtensions(
	ctx context.Context,
	acceptance effectsupervisor.Acceptor,
	extensions []registry.DefinitionContribution,
	authnLuaFacts []registry.AuthnLuaFactDeclaration,
	authnPolicyAttributes map[string]registry.AttributeDefinition,
	implicitExtensions []registry.DefinitionContribution,
) (*policyruntime.TargetCatalog, []registry.DefinitionContribution, error) {
	if err := p.ValidatePolicyModel(); err != nil {
		return nil, nil, err
	}

	return p.structural.compileMaterialWithExtensions(
		ctx,
		acceptance,
		p.configured,
		extensions,
		authnLuaFacts,
		authnPolicyAttributes,
		implicitExtensions,
	)
}

// CallerAuthentication returns the detached normalized external caller configuration.
func (p *PreparedPolicy) CallerAuthentication() callerauth.Configuration {
	if p == nil {
		return callerauth.Configuration{}
	}

	return projectCallerAuthentication(p.configured.API)
}

// CallerAdmission returns the detached normalized external admission configuration.
func (p *PreparedPolicy) CallerAdmission() admission.Configuration {
	if p == nil {
		return admission.Configuration{}
	}

	return p.structural.CallerAdmission()
}

// Config returns a detached normalized top-level Policy model.
func (p *PreparedPolicy) Config() policyconfig.PolicyConfig {
	if p == nil {
		return policyconfig.PolicyConfig{}
	}

	return policyconfig.Normalize(policyconfig.Document{Policy: p.configured}).Policy
}

// PostActionProviderIDs returns every exact configured or builtin asynchronous effect owner.
func (p *PreparedPolicy) PostActionProviderIDs() []string {
	if p == nil {
		return nil
	}

	identities := make(map[string]struct{})

	for _, contribution := range p.structural.Definitions {
		for _, provider := range contribution.Providers() {
			if slices.Contains(provider.Executions(), registry.ExecutionHostPostAction) {
				identities[provider.ID()] = struct{}{}
			}
		}
	}

	result := make([]string, 0, len(identities))
	for identity := range identities {
		result = append(result, identity)
	}

	sort.Strings(result)

	return result
}

// AuthnPluginSources returns only public native authn sources scheduled by an activated target plan.
func (p *PreparedPolicy) AuthnPluginSources() ([]AuthnPluginSourceDefinition, error) {
	if err := p.ValidatePolicyModel(); err != nil {
		return nil, err
	}

	configured := configuredAuthnPluginProviders(p.configured)
	if len(configured) == 0 {
		return nil, nil
	}

	selections, err := collectAuthnPluginSourceSelections(p.structural.Definitions, configured)
	if err != nil {
		return nil, err
	}

	identities := make([]string, 0, len(selections))
	for identity := range selections {
		identities = append(identities, identity)
	}

	sort.Strings(identities)

	result := make([]AuthnPluginSourceDefinition, 0, len(identities))
	for _, identity := range identities {
		result = append(result, selections[identity])
	}

	return result, nil
}

// configuredAuthnPluginProviders indexes only public native authn source configurations.
func configuredAuthnPluginProviders(configured policyconfig.PolicyConfig) map[string]policyconfig.ProviderConfig {
	result := make(map[string]policyconfig.ProviderConfig)

	authn, exists := configured.Namespaces[policy.AuthnNamespace]
	if !exists {
		return result
	}

	for name, provider := range authn.Providers {
		if provider.Kind == policyconfig.ProviderKindPlugin {
			result[provider.CanonicalID(policy.AuthnNamespace, name)] = provider
		}
	}

	return result
}

// collectAuthnPluginSourceSelections projects every scheduled exact instance into one provider selection.
func collectAuthnPluginSourceSelections(
	definitions []registry.DefinitionContribution,
	configured map[string]policyconfig.ProviderConfig,
) (map[string]AuthnPluginSourceDefinition, error) {
	selections := make(map[string]AuthnPluginSourceDefinition)

	var order uint32

	for _, contribution := range definitions {
		for _, plan := range contribution.Plans() {
			if err := collectAuthnPluginPlanSelections(plan, configured, selections, &order); err != nil {
				return nil, err
			}
		}
	}

	return selections, nil
}

// collectAuthnPluginPlanSelections adds scheduled configured providers from one authn plan.
func collectAuthnPluginPlanSelections(
	plan registry.DomainPlanDefinition,
	configured map[string]policyconfig.ProviderConfig,
	selections map[string]AuthnPluginSourceDefinition,
	order *uint32,
) error {
	if plan.Target().Namespace() != policy.AuthnNamespace {
		return nil
	}

	operation := policy.Operation(plan.Target().Action())
	for _, checkpoint := range plan.Checkpoints() {
		for _, instance := range checkpoint.ProviderInstances() {
			provider, selected := configured[instance.Use()]
			if !selected {
				continue
			}

			*order++
			if err := mergeAuthnPluginSourceSelection(selections, instance, provider, operation, *order); err != nil {
				return err
			}
		}
	}

	return nil
}

// mergeAuthnPluginSourceSelection validates identity and merges one scheduled instance deterministically.
func mergeAuthnPluginSourceSelection(
	selections map[string]AuthnPluginSourceDefinition,
	instance registry.ProviderInstanceDefinition,
	provider policyconfig.ProviderConfig,
	operation policy.Operation,
	order uint32,
) error {
	module, family, component, ok := policyconfig.ParseAuthnPluginProviderLocal(
		strings.TrimPrefix(instance.Use(), policy.AuthnNamespace+"/"),
	)
	if !ok || module != provider.Module {
		return fmt.Errorf("configured authn plugin provider %s has an invalid identity", instance.Use())
	}

	selection := selections[instance.Use()]
	selection.ProviderID = instance.Use()
	selection.ModuleName = module
	selection.ComponentName = component
	selection.Family = family

	if !slices.Contains(selection.InstanceNames, instance.Name()) {
		selection.InstanceNames = append(selection.InstanceNames, instance.Name())
	}

	if selection.Order == 0 || order < selection.Order {
		selection.Order = order
	}

	if !slices.Contains(selection.Operations, operation) {
		selection.Operations = append(selection.Operations, operation)
	}

	selections[instance.Use()] = selection

	return nil
}

// structuralPolicy removes only circular extension fact shapes while preserving their exact scheduled identities.
func structuralPolicy(configured policyconfig.PolicyConfig) policyconfig.PolicyConfig {
	result := policyconfig.Normalize(policyconfig.Document{Policy: configured}).Policy
	for namespace, namespaceConfig := range result.Namespaces {
		for name, provider := range namespaceConfig.Providers {
			if provider.Kind != policyconfig.ProviderKindLua && provider.Kind != policyconfig.ProviderKindNative ||
				len(provider.ProducedFacts) == 0 {
				continue
			}

			provider.ProducedFacts = nil
			if len(provider.Executions) == 0 {
				provider.Executions = []string{string(registry.ExecutionHostSync)}
			}

			namespaceConfig.Providers[name] = provider
		}

		result.Namespaces[namespace] = namespaceConfig
	}

	return result
}

// configuredExtensionFacts reports whether catalog compilation requires real descriptor-derived schemas.
func configuredExtensionFacts(configured policyconfig.PolicyConfig) bool {
	for _, namespace := range configured.Namespaces {
		for _, provider := range namespace.Providers {
			if (provider.Kind == policyconfig.ProviderKindLua || provider.Kind == policyconfig.ProviderKindNative) &&
				len(provider.ProducedFacts) > 0 {
				return true
			}
		}
	}

	return false
}

// cloneUnifiedPolicyInput detaches every mutable normalized projection.
func cloneUnifiedPolicyInput(input UnifiedPolicyInput) UnifiedPolicyInput {
	return UnifiedPolicyInput{
		Policy:               policyconfig.Normalize(policyconfig.Document{Policy: input.Policy}).Policy,
		Definitions:          append([]registry.DefinitionContribution(nil), input.Definitions...),
		Activations:          append([]registry.TargetActivation(nil), input.Activations...),
		Admissions:           append([]registry.ClientAdmissionReference(nil), input.Admissions...),
		AdmissionProfiles:    cloneClientAdmissionProfiles(input.AdmissionProfiles),
		callerAdmission:      cloneCallerAdmission(input.callerAdmission),
		callerAuthentication: cloneCallerAuthentication(input.callerAuthentication),
	}
}

// cloneClientAdmissionProfiles detaches each profile-owned reference batch.
func cloneClientAdmissionProfiles(input []ClientAdmissionProfile) []ClientAdmissionProfile {
	result := make([]ClientAdmissionProfile, len(input))
	for index, profile := range input {
		result[index] = ClientAdmissionProfile{
			Principal:  profile.Principal,
			References: append([]registry.ClientAdmissionReference(nil), profile.References...),
		}
	}

	return result
}
