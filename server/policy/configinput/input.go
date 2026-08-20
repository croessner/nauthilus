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
	"github.com/croessner/nauthilus/v3/server/policy/compiler"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
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
	Policy            policyconfig.PolicyConfig
	Definitions       []registry.DefinitionContribution
	Activations       []registry.TargetActivation
	Admissions        []registry.ClientAdmissionReference
	AdmissionProfiles []ClientAdmissionProfile
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

	builtin, err := registry.NewBuiltinTargetContributor().Contribute(ctx)
	if err != nil {
		return UnifiedPolicyInput{}, fmt.Errorf("build unified builtin authn definitions: %w", err)
	}

	material, err := newPolicyNormalizer(normalized.Policy, nil).normalize()
	if err != nil {
		return UnifiedPolicyInput{}, err
	}

	definitions := make([]registry.DefinitionContribution, 0, len(material.definitions)+1)
	definitions = append(definitions, builtin)
	definitions = append(definitions, material.definitions...)

	return UnifiedPolicyInput{
		Policy:            normalized.Policy,
		Definitions:       definitions,
		Activations:       material.activations,
		Admissions:        material.admissions,
		AdmissionProfiles: material.admissionProfiles,
	}, nil
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

	contributors := make([]registry.Contributor, 0, len(material.definitions)+1)
	contributors = append(contributors, registry.NewBuiltinTargetContributor(acceptance))

	for _, definition := range material.definitions {
		contributors = append(contributors, staticContributor{definition: definition})
	}

	return contributors, material, nil
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

		activations = append(activations, activation)
	}

	return activations, nil
}
