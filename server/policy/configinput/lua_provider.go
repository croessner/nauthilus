// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"fmt"
	"slices"
	"strings"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

// LuaProviderOutput is one schema-owned typed output available to generic Lua preparation.
type LuaProviderOutput struct {
	ID        string
	Category  decision.FactCategory
	Kind      decision.ValueKind
	MaxLength int
	MaxItems  int
	MaxBytes  int
}

// CanonicalProviderID maps an authored provider key to its internal host-owned identity.
func CanonicalProviderID(
	namespace string,
	name string,
	provider policyconfig.ProviderConfig,
) string {
	return provider.CanonicalID(namespace, name)
}

// LuaProviderOutputs projects exact schema-owned output metadata for one configured generic Lua provider.
func LuaProviderOutputs(
	configured policyconfig.PolicyConfig,
	namespace string,
	name string,
) ([]LuaProviderOutput, error) {
	document := policyconfig.Normalize(policyconfig.Document{Policy: configured})
	if err := policyconfig.Validate(document); err != nil {
		return nil, err
	}

	configured = document.Policy

	normalizer := newPolicyNormalizer(configured, nil)
	if err := normalizer.indexTargets(); err != nil {
		return nil, err
	}

	provider, err := normalizer.configuredLuaProvider(namespace, name)
	if err != nil {
		return nil, err
	}

	targets, err := normalizer.providerTargets(namespace, name, provider)
	if err != nil {
		return nil, err
	}

	return normalizer.projectProviderOutputs(namespace, name, provider, targets, decision.FactSourceLua)
}

// configuredLuaProvider resolves one exact generic Lua provider definition.
func (n *policyNormalizer) configuredLuaProvider(
	namespace string,
	name string,
) (policyconfig.ProviderConfig, error) {
	path := "policy.namespaces." + namespace + ".providers." + name

	configuredNamespace, exists := n.policy.Namespaces[namespace]
	if !exists {
		return policyconfig.ProviderConfig{}, atPath(path, fmt.Errorf("unknown provider namespace"))
	}

	provider, exists := configuredNamespace.Providers[name]
	if !exists {
		return policyconfig.ProviderConfig{}, atPath(path, fmt.Errorf("unknown provider"))
	}

	if provider.Kind != policyconfig.ProviderKindLua {
		return policyconfig.ProviderConfig{}, atPath(path+".kind", fmt.Errorf("must be lua"))
	}

	return provider, nil
}

// providerTargets resolves explicit targets or derives them from exact plan and effect bindings.
func (n *policyNormalizer) providerTargets(
	namespace string,
	name string,
	provider policyconfig.ProviderConfig,
) ([]decision.Target, error) {
	path := "policy.namespaces." + namespace + ".providers." + name

	targets, err := normalizeTargetReferences(path+".targets", namespace, provider.Targets)
	if err != nil {
		return nil, err
	}

	if len(targets) > 0 {
		return targets, nil
	}

	return n.deriveProviderTargets(CanonicalProviderID(namespace, name, provider)), nil
}

// projectProviderOutputs joins every declared output with every exact target schema and source.
func (n *policyNormalizer) projectProviderOutputs(
	namespace string,
	name string,
	provider policyconfig.ProviderConfig,
	targets []decision.Target,
	source decision.FactSource,
) ([]LuaProviderOutput, error) {
	path := "policy.namespaces." + namespace + ".providers." + name

	if len(provider.ProducedFacts) == 0 {
		return nil, nil
	}

	if len(targets) == 0 {
		return nil, atPath(path+".targets", fmt.Errorf("declared facts require at least one exact configured target"))
	}

	outputs := make([]LuaProviderOutput, 0, len(provider.ProducedFacts))
	for index, factID := range provider.ProducedFacts {
		factPath := fmt.Sprintf("%s.produced_facts[%d]", path, index)

		output, err := n.projectProviderOutput(factPath, factID, targets, source)
		if err != nil {
			return nil, err
		}

		outputs = append(outputs, output)
	}

	return outputs, nil
}

// projectProviderOutput requires one identical source-compatible shape across all target schemas.
func (n *policyNormalizer) projectProviderOutput(
	path string,
	factID string,
	targets []decision.Target,
	source decision.FactSource,
) (LuaProviderOutput, error) {
	var projected LuaProviderOutput

	for index, target := range targets {
		fact, factPath, err := n.configuredTargetFact(target, factID)
		if err != nil {
			return LuaProviderOutput{}, atPath(path, err)
		}

		if !slices.Contains(fact.AllowedSources, string(source)) {
			return LuaProviderOutput{}, atPath(
				factPath+".allowed_sources",
				fmt.Errorf("must allow the %s source", source),
			)
		}

		candidate := newLuaProviderOutput(fact)
		if index > 0 && candidate != projected {
			return LuaProviderOutput{}, atPath(path, fmt.Errorf("must have one identical category, kind, and bounds across every exact target schema"))
		}

		projected = candidate
	}

	return projected, nil
}

// configuredTargetFact resolves one fact and its source path from an exact activated static schema.
func (n *policyNormalizer) configuredTargetFact(
	target decision.Target,
	factID string,
) (policyconfig.StaticFactSchemaConfig, string, error) {
	for _, configuredTarget := range n.targets {
		if configuredTarget.target.String() != target.String() {
			continue
		}

		action, version, ok := splitSchemaReference(configuredTarget.config.Schema)
		if !ok {
			return policyconfig.StaticFactSchemaConfig{}, "", fmt.Errorf("target %s has no exact schema", target.String())
		}

		namespace := n.policy.Namespaces[target.Namespace()]
		facts := namespace.SchemaContributions.Static[action].Versions[version].Facts
		basePath := "policy.namespaces." + target.Namespace() + ".schema_contributions.static." + action + ".versions." + version + ".facts"

		for index, fact := range facts {
			if fact.Attribute == factID {
				return fact, fmt.Sprintf("%s[%d]", basePath, index), nil
			}
		}

		return policyconfig.StaticFactSchemaConfig{}, "", fmt.Errorf("fact %s is not declared by exact target schema %s", factID, configuredTarget.config.Schema)
	}

	return policyconfig.StaticFactSchemaConfig{}, "", fmt.Errorf("target %s has no exact configured schema", target.String())
}

// newLuaProviderOutput owns one static schema shape without its target-specific source list.
func newLuaProviderOutput(fact policyconfig.StaticFactSchemaConfig) LuaProviderOutput {
	return LuaProviderOutput{
		ID:        fact.Attribute,
		Category:  decision.FactCategory(fact.Category),
		Kind:      decision.ValueKind(fact.Type),
		MaxLength: fact.MaxLength,
		MaxItems:  fact.MaxItems,
		MaxBytes:  fact.MaxBytes,
	}
}

// registryProviderOutputs reconstructs immutable registry capabilities from neutral projections.
func registryProviderOutputs(outputs []LuaProviderOutput) ([]registry.ProviderFactOutput, error) {
	result := make([]registry.ProviderFactOutput, 0, len(outputs))
	for _, output := range outputs {
		projected, err := registry.NewProviderFactOutput(registry.ProviderFactOutputInput{
			ID: output.ID, Category: output.Category, Kind: output.Kind,
			MaxLength: output.MaxLength, MaxItems: output.MaxItems, MaxBytes: output.MaxBytes,
		})
		if err != nil {
			return nil, err
		}

		result = append(result, projected)
	}

	return result, nil
}

// resolveProviderReference maps one authored local key while preserving immutable and foreign references.
func (n *policyNormalizer) resolveProviderReference(namespace string, reference string) string {
	owner := namespace
	name := reference

	if qualifiedOwner, qualifiedName, qualified := strings.Cut(reference, "/"); qualified {
		owner = qualifiedOwner
		name = qualifiedName
	}

	configuredNamespace, exists := n.policy.Namespaces[owner]
	if !exists || owner != namespace {
		return qualify(namespace, reference)
	}

	provider, exists := configuredNamespace.Providers[name]
	if !exists {
		return qualify(namespace, reference)
	}

	return CanonicalProviderID(owner, name, provider)
}
