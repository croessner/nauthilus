// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package configinput projects the standalone unified policy configuration
// into the transport-neutral policy catalog compiler inputs.
package configinput

import (
	"context"
	"fmt"

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/admission"
	"github.com/croessner/nauthilus/v3/server/policy/callerauth"
	"github.com/croessner/nauthilus/v3/server/policy/compiler"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
	"github.com/croessner/nauthilus/v3/server/secret"
)

var builtinAuthnTargets = []struct {
	action policy.Operation
	schema string
}{
	{action: policy.OperationAuthenticate, schema: "authn/authenticate/v1"},
	{action: policy.OperationLookupIdentity, schema: "authn/lookup_identity/v1"},
	{action: policy.OperationListAccounts, schema: "authn/list_accounts/v1"},
}

// UnifiedPolicyInput owns the single standalone transport-neutral compiler envelope.
type UnifiedPolicyInput struct {
	Policy               policyconfig.PolicyConfig
	Definitions          []registry.DefinitionContribution
	Activations          []registry.TargetActivation
	Admissions           []registry.ClientAdmissionReference
	AdmissionProfiles    []ClientAdmissionProfile
	callerAdmission      admission.Configuration
	callerAuthentication callerauth.Configuration
}

// ClientAdmissionProfile preserves profile ownership around exact catalog references.
type ClientAdmissionProfile struct {
	References []registry.ClientAdmissionReference
	Principal  string
}

// Normalize validates and projects one standalone document without touching production configuration.
func Normalize(ctx context.Context, document policyconfig.Document) (UnifiedPolicyInput, error) {
	if err := ctx.Err(); err != nil {
		return UnifiedPolicyInput{}, err
	}

	normalized := policyconfig.Normalize(document)
	if err := policyconfig.Validate(normalized); err != nil {
		return UnifiedPolicyInput{}, err
	}

	material, err := newPolicyNormalizer(normalized.Policy, nil).normalize()
	if err != nil {
		return UnifiedPolicyInput{}, err
	}

	builtin, err := configuredBuiltinAuthnContribution(ctx, normalized.Policy, nil)
	if err != nil {
		return UnifiedPolicyInput{}, err
	}

	definitions := make([]registry.DefinitionContribution, 0, len(material.definitions)+1)
	definitions = append(definitions, builtin)
	definitions = append(definitions, material.definitions...)

	return UnifiedPolicyInput{
		Policy:               normalized.Policy,
		Definitions:          definitions,
		Activations:          material.activations,
		Admissions:           material.admissions,
		AdmissionProfiles:    material.admissionProfiles,
		callerAdmission:      projectCallerAdmission(normalized.Policy.API, material.admissionProfiles),
		callerAuthentication: projectCallerAuthentication(normalized.Policy.API),
	}, nil
}

// CallerAdmission returns a detached caller-admission projection for generation assembly.
func (i UnifiedPolicyInput) CallerAdmission() admission.Configuration {
	return cloneCallerAdmission(i.callerAdmission)
}

// CallerAuthentication returns a detached caller-authentication projection for generation assembly.
func (i UnifiedPolicyInput) CallerAuthentication() callerauth.Configuration {
	return cloneCallerAuthentication(i.callerAuthentication)
}

// projectCallerAdmission joins normalized external profiles with their exact expanded references.
func projectCallerAdmission(
	api policyconfig.APIConfig,
	profiles []ClientAdmissionProfile,
) admission.Configuration {
	configuration := admission.Configuration{
		GlobalLimits: newAdmissionLimits(
			api.Limits.MaxRequestBytes,
			api.Limits.MaxFacts,
			api.Limits.PerClientConcurrency,
			api.Limits.PerClientRequestsPerSecond,
		),
	}
	if api.Clients == nil {
		return configuration
	}

	configuration.Profiles = make([]admission.Profile, len(api.Clients))
	for index, client := range api.Clients {
		configuration.Profiles[index] = admission.Profile{
			References:                   cloneSlice(profiles[index].References),
			AuthenticationKinds:          cloneSlice(client.AuthenticationKinds),
			AllowedSubjectAttributes:     cloneSlice(client.AllowedSubjectAttributes),
			AllowedResourceAttributes:    cloneSlice(client.AllowedResourceAttributes),
			AllowedEnvironmentAttributes: cloneSlice(client.AllowedEnvironmentAttributes),
			AllowedInputAttributes:       cloneSlice(client.AllowedInputAttributes),
			Principal:                    client.Principal,
			Limits: newAdmissionLimits(
				client.MaxRequestBytes,
				client.MaxFacts,
				client.MaxConcurrency,
				client.RequestsPerSecond,
			),
			Diagnostics: client.Diagnostics,
			Internal:    false,
		}
	}

	return configuration
}

// newAdmissionLimits maps the shared four-bound contract without transport-specific policy.
func newAdmissionLimits(
	maxRequestBytes int,
	maxFacts int,
	maxConcurrency int,
	requestsPerSecond int,
) admission.Limits {
	return admission.Limits{
		MaxRequestBytes:   maxRequestBytes,
		MaxFacts:          maxFacts,
		MaxConcurrency:    maxConcurrency,
		RequestsPerSecond: requestsPerSecond,
	}
}

// projectCallerAuthentication captures only operator-owned caller rules from one normalized API snapshot.
func projectCallerAuthentication(api policyconfig.APIConfig) callerauth.Configuration {
	configuration := callerauth.Configuration{RequireGRPCMTLS: api.GRPC.RequireMTLS}
	if api.Clients == nil {
		return configuration
	}

	configuration.ExternalProfiles = make([]callerauth.ExternalProfile, len(api.Clients))
	for index, profile := range api.Clients {
		configuration.ExternalProfiles[index] = callerauth.ExternalProfile{
			Basic:               projectBasicCredential(profile.Authentication.Basic),
			AuthenticationKinds: cloneSlice(profile.AuthenticationKinds),
			Principal:           profile.Principal,
			RequireMTLS:         profile.RequireMTLS,
		}
	}

	return configuration
}

// projectBasicCredential detaches dedicated Policy-Basic material from its configuration owner.
func projectBasicCredential(configured *policyconfig.BasicAuthenticationConfig) *callerauth.BasicCredential {
	if configured == nil {
		return nil
	}

	return &callerauth.BasicCredential{
		Password: cloneSecret(configured.Password),
		Username: configured.Username,
	}
}

// cloneCallerAdmission detaches every mutable caller-admission projection value.
func cloneCallerAdmission(configuration admission.Configuration) admission.Configuration {
	return admission.Configuration{
		Profiles:     cloneAdmissionProfiles(configuration.Profiles),
		GlobalLimits: configuration.GlobalLimits,
	}
}

// cloneAdmissionProfiles owns each external or generation-injected profile independently.
func cloneAdmissionProfiles(profiles []admission.Profile) []admission.Profile {
	if profiles == nil {
		return nil
	}

	cloned := make([]admission.Profile, len(profiles))
	for index, profile := range profiles {
		cloned[index] = admission.Profile{
			References:                   cloneSlice(profile.References),
			AuthenticationKinds:          cloneSlice(profile.AuthenticationKinds),
			AllowedSubjectAttributes:     cloneSlice(profile.AllowedSubjectAttributes),
			AllowedResourceAttributes:    cloneSlice(profile.AllowedResourceAttributes),
			AllowedEnvironmentAttributes: cloneSlice(profile.AllowedEnvironmentAttributes),
			AllowedInputAttributes:       cloneSlice(profile.AllowedInputAttributes),
			Principal:                    profile.Principal,
			Limits:                       profile.Limits,
			Diagnostics:                  profile.Diagnostics,
			Internal:                     profile.Internal,
		}
	}

	return cloned
}

// cloneCallerAuthentication detaches every mutable caller-authentication projection value.
func cloneCallerAuthentication(configuration callerauth.Configuration) callerauth.Configuration {
	cloned := callerauth.Configuration{RequireGRPCMTLS: configuration.RequireGRPCMTLS}
	if configuration.ExternalProfiles == nil {
		return cloned
	}

	cloned.ExternalProfiles = make([]callerauth.ExternalProfile, len(configuration.ExternalProfiles))
	for index, profile := range configuration.ExternalProfiles {
		cloned.ExternalProfiles[index] = callerauth.ExternalProfile{
			Basic:               cloneBasicCredential(profile.Basic),
			AuthenticationKinds: cloneSlice(profile.AuthenticationKinds),
			Principal:           profile.Principal,
			RequireMTLS:         profile.RequireMTLS,
		}
	}

	return cloned
}

// cloneSlice detaches one ordered projection slice while preserving immutable elements.
func cloneSlice[T any](values []T) []T {
	return append([]T(nil), values...)
}

// cloneBasicCredential returns detached Policy-Basic material without converting it to a string.
func cloneBasicCredential(credential *callerauth.BasicCredential) *callerauth.BasicCredential {
	if credential == nil {
		return nil
	}

	return &callerauth.BasicCredential{
		Password: cloneSecret(credential.Password),
		Username: credential.Username,
	}
}

// cloneSecret owns one opaque secret copy through its scoped byte boundary.
func cloneSecret(value secret.Value) secret.Value {
	var cloned secret.Value

	value.WithBytes(func(bytes []byte) {
		cloned = secret.FromBytes(bytes)
	})

	return cloned
}

// Contributors rebuilds capability-bearing definitions at the standalone compile boundary.
func (i UnifiedPolicyInput) Contributors(
	ctx context.Context,
	acceptance effectsupervisor.Acceptor,
) ([]registry.Contributor, error) {
	contributors, _, err := i.materialize(ctx, acceptance)
	if err != nil {
		return nil, err
	}

	return contributors, nil
}

// materialize rebuilds every compiler-owned value from one normalized policy snapshot.
func (i UnifiedPolicyInput) materialize(
	ctx context.Context,
	acceptance effectsupervisor.Acceptor,
) ([]registry.Contributor, normalizedMaterial, error) {
	if err := ctx.Err(); err != nil {
		return nil, normalizedMaterial{}, err
	}

	document := policyconfig.Normalize(policyconfig.Document{Policy: i.Policy})
	if err := policyconfig.Validate(document); err != nil {
		return nil, normalizedMaterial{}, err
	}

	material, err := newPolicyNormalizer(document.Policy, acceptance).normalize()
	if err != nil {
		return nil, normalizedMaterial{}, err
	}

	builtin, err := configuredBuiltinAuthnContribution(ctx, document.Policy, acceptance)
	if err != nil {
		return nil, normalizedMaterial{}, err
	}

	contributors := make([]registry.Contributor, 0, len(material.definitions)+1)
	contributors = append(contributors, staticContributor{definition: builtin})

	for _, definition := range material.definitions {
		contributors = append(contributors, staticContributor{definition: definition})
	}

	return contributors, material, nil
}

// configuredBuiltinAuthnContribution removes only builtin plans explicitly replaced by standalone configuration.
func configuredBuiltinAuthnContribution(
	ctx context.Context,
	configured policyconfig.PolicyConfig,
	acceptance effectsupervisor.Acceptor,
) (registry.DefinitionContribution, error) {
	builtin, err := registry.NewBuiltinTargetContributor(acceptance).Contribute(ctx)
	if err != nil {
		return registry.DefinitionContribution{}, fmt.Errorf("build unified builtin authn definitions: %w", err)
	}

	overrides := configuredAuthnPlanTargets(configured)
	if len(overrides) == 0 {
		return builtin, nil
	}

	plans := make([]registry.DomainPlanDefinition, 0, len(builtin.Plans()))
	for _, plan := range builtin.Plans() {
		if _, replaced := overrides[plan.Target().String()]; replaced {
			continue
		}

		plans = append(plans, plan)
	}

	composed, err := registry.NewCompleteDefinitionContribution(registry.DefinitionContributionInput{
		Ownership:  builtin.Ownership(),
		Targets:    builtin.Targets(),
		Schemas:    builtin.Schemas(),
		PolicySets: builtin.PolicySets(),
		Plans:      plans,
		Providers:  builtin.Providers(),
		Effects:    builtin.Effects(),
	})
	if err != nil {
		return registry.DefinitionContribution{}, fmt.Errorf("compose unified builtin authn definitions: %w", err)
	}

	return composed, nil
}

// configuredAuthnPlanTargets indexes exact builtin targets with an explicit standalone plan selection.
func configuredAuthnPlanTargets(configured policyconfig.PolicyConfig) map[string]struct{} {
	overrides := make(map[string]struct{})

	for _, target := range configured.Targets {
		if target.Namespace != policy.AuthnNamespace || target.DomainPlan == "" {
			continue
		}

		overrides[target.Namespace+"/"+target.Action] = struct{}{}
	}

	return overrides
}

// Compile builds a standalone catalog candidate and validates each client-owned admission batch.
func (i UnifiedPolicyInput) Compile(
	ctx context.Context,
	acceptance effectsupervisor.Acceptor,
) (*policyruntime.TargetCatalog, error) {
	contributors, material, err := i.materialize(ctx, acceptance)
	if err != nil {
		return nil, err
	}

	catalog, err := compiler.NewTargetCatalogCompiler(contributors...).Compile(ctx, material.activations)
	if err != nil {
		return nil, err
	}

	for _, profile := range material.admissionProfiles {
		if err := compiler.ValidateAdmissionReferences(catalog, profile.References); err != nil {
			return nil, fmt.Errorf("policy client %s admission: %w", profile.Principal, err)
		}
	}

	return catalog, nil
}

type staticContributor struct {
	definition registry.DefinitionContribution
}

// Contribute returns one already validated immutable configuration contribution.
func (c staticContributor) Contribute(ctx context.Context) (registry.DefinitionContribution, error) {
	if err := ctx.Err(); err != nil {
		return registry.DefinitionContribution{}, err
	}

	if err := c.definition.Validate(); err != nil {
		return registry.DefinitionContribution{}, err
	}

	return c.definition, nil
}

// builtinActivations constructs the three immutable default authn activations.
func builtinActivations() ([]registry.TargetActivation, error) {
	activations := make([]registry.TargetActivation, 0, len(builtinAuthnTargets))
	report := registry.NewTargetReportSettings(false, true, true, false)

	for index, target := range builtinAuthnTargets {
		path := fmt.Sprintf("policy.defaults.authn[%d]", index)

		activation, err := registry.NewTargetActivation(path, policy.AuthnNamespace, string(target.action), target.schema)
		if err != nil {
			return nil, err
		}

		activation, err = activation.WithPolicy(registry.BuiltinStandardAuthPolicySet, "")
		if err != nil {
			return nil, err
		}

		activation, err = activation.WithAuthorityMode(registry.AuthorityModeEnforce)
		if err != nil {
			return nil, err
		}

		activation, err = activation.WithReport(report)
		if err != nil {
			return nil, err
		}

		activations = append(activations, activation)
	}

	return activations, nil
}
