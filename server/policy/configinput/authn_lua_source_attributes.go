// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"maps"
	"strings"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	policy "github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

// authnLuaSourceAttributeSpec describes the result vocabulary one configured Lua source kind records.
type authnLuaSourceAttributeSpec struct {
	identity       func(name string, suffix string) string
	prefix         string
	producerType   string
	detailedSuffix string
	stage          policy.Stage
	category       registry.AttributeCategory
	suffixes       []string
}

// authnLuaSourceAttributeSpecs keys the environment and subject result vocabularies by provider kind. The
// suffixes match the attributes policy/collection records for each callback result.
var authnLuaSourceAttributeSpecs = map[string]authnLuaSourceAttributeSpec{
	policyconfig.ProviderKindLuaEnvironment: {
		identity: policy.LuaEnvironmentAttributeID, prefix: authnLuaEnvironmentPrefix,
		producerType: policy.CheckTypeLuaEnvironment, detailedSuffix: policy.SourceResultTriggered,
		stage: policy.StagePreAuth, category: registry.AttributeCategoryEnvironment,
		suffixes: []string{policy.SourceResultTriggered, policy.SourceResultAbort, policy.SourceResultError},
	},
	policyconfig.ProviderKindLuaSubject: {
		identity: policy.LuaSubjectAttributeID, prefix: authnLuaSubjectPrefix,
		producerType: policy.CheckTypeLuaSubjectSource, detailedSuffix: policy.SourceResultRejected,
		stage: policy.StageSubjectAnalysis, category: registry.AttributeCategorySubject,
		suffixes: []string{policy.SourceResultRejected, policy.SourceResultError},
	},
}

// ConfiguredAuthnLuaSourceAttributes declares the result facts of every scheduled lua_environment and lua_subject
// provider. The standard-auth policy set derives its deny, tempfail, and abort rules from these definitions, and
// configured rules may reference the resulting nauthilus.auth.lua.<kind>.<name>.<suffix> facts.
func ConfiguredAuthnLuaSourceAttributes(configured policyconfig.PolicyConfig) map[string]registry.AttributeDefinition {
	document := policyconfig.Normalize(policyconfig.Document{Policy: configured})
	result := make(map[string]registry.AttributeDefinition)

	authn, exists := document.Policy.Namespaces[policy.AuthnNamespace]
	if !exists {
		return result
	}

	activated := activatedAuthnHostProviderOperations(document.Policy, authn)

	for _, localName := range sortedConfiguredKeys(authn.Providers) {
		provider := authn.Providers[localName]

		spec, supported := authnLuaSourceAttributeSpecs[provider.Kind]
		if !supported {
			continue
		}

		operations := activated[CanonicalProviderID(policy.AuthnNamespace, localName, provider)]
		name := strings.TrimPrefix(localName, spec.prefix)

		if len(operations) == 0 || name == "" || name == localName {
			continue
		}

		maps.Copy(result, spec.definitions(localName, name, operations))
	}

	return result
}

// definitions builds the result facts of one scheduled source; the provider name is the producing check.
func (s authnLuaSourceAttributeSpec) definitions(
	check string,
	name string,
	operations []policy.Operation,
) map[string]registry.AttributeDefinition {
	result := make(map[string]registry.AttributeDefinition, len(s.suffixes))

	for _, suffix := range s.suffixes {
		definition := registry.NewExecutionAttribute(registry.ExecutionAttributeInput{
			ID: s.identity(name, suffix), Stage: s.stage, Operations: operations,
			ProducerType: s.producerType, ProducerCheck: check,
			Category: s.category, StatusMessage: suffix == s.detailedSuffix,
		})

		result[definition.ID] = definition
	}

	return result
}

// WithConfiguredAuthnLuaSourceAttributes adds the scheduled Lua source facts to bound extension definitions. The
// catalog compiler and the request-time decision context both need them, so the generation binding set and every
// compile path use this one merge. Bound definitions win, so an attribute never gets two owners.
func WithConfiguredAuthnLuaSourceAttributes(
	configured policyconfig.PolicyConfig,
	bound map[string]registry.AttributeDefinition,
) map[string]registry.AttributeDefinition {
	result := ConfiguredAuthnLuaSourceAttributes(configured)
	maps.Copy(result, bound)

	return result
}
