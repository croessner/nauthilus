// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"fmt"
	"sort"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

// PathError preserves the authoritative configuration location around registry failures.
type PathError struct {
	Cause error
	Path  string
}

// Error returns the deterministic path-bearing normalization failure.
func (e *PathError) Error() string {
	return fmt.Sprintf("%s: %v", e.Path, e.Cause)
}

// Unwrap exposes the underlying constructor or compiler error.
func (e *PathError) Unwrap() error {
	return e.Cause
}

type normalizedMaterial struct {
	definitions       []registry.DefinitionContribution
	activations       []registry.TargetActivation
	admissions        []registry.ClientAdmissionReference
	admissionProfiles []ClientAdmissionProfile
}

type normalizedTarget struct {
	config policyconfig.TargetConfig
	target decision.Target
	schema registry.SchemaIdentity
	path   string
}

type namespaceDefinitions struct {
	targets    []registry.TargetDefinition
	schemas    []registry.SchemaDefinition
	policySets []registry.PolicySetDefinition
	plans      []registry.DomainPlanDefinition
	providers  []registry.ProviderDefinition
	effects    []registry.EffectDefinition
}

type policyNormalizer struct {
	policy     policyconfig.PolicyConfig
	acceptance effectsupervisor.Acceptor
	targets    []normalizedTarget
	exports    map[string]registry.ExportContract
}

// newPolicyNormalizer creates one request-local standalone projection owner.
func newPolicyNormalizer(policy policyconfig.PolicyConfig, acceptance effectsupervisor.Acceptor) *policyNormalizer {
	return &policyNormalizer{policy: policy, acceptance: acceptance, exports: make(map[string]registry.ExportContract)}
}

// normalize compiles definitions before exact activation and admission references.
func (n *policyNormalizer) normalize() (normalizedMaterial, error) {
	if err := validateConfiguredActivationSchemas(n.policy); err != nil {
		return normalizedMaterial{}, err
	}

	if err := n.indexTargets(); err != nil {
		return normalizedMaterial{}, err
	}

	if err := n.indexExportContracts(); err != nil {
		return normalizedMaterial{}, err
	}

	definitions, err := n.normalizeDefinitions()
	if err != nil {
		return normalizedMaterial{}, err
	}

	activations, err := n.normalizeActivations()
	if err != nil {
		return normalizedMaterial{}, err
	}

	admissions, profiles, err := n.normalizeAdmissions(activations)
	if err != nil {
		return normalizedMaterial{}, err
	}

	return normalizedMaterial{
		definitions: definitions, activations: activations, admissions: admissions, admissionProfiles: profiles,
	}, nil
}

// indexTargets validates exact target/schema identities without activating them.
func (n *policyNormalizer) indexTargets() error {
	n.targets = make([]normalizedTarget, 0, len(n.policy.Targets))
	seen := make(map[string]string, len(n.policy.Targets))

	for index, configured := range n.policy.Targets {
		path := fmt.Sprintf("policy.targets[%d]", index)

		target, err := decision.NewTarget(configured.Namespace, configured.Action)
		if err != nil {
			return atPath(path, err)
		}

		schema, err := registry.ParseSchemaIdentity(path+".schema", configured.Schema)
		if err != nil {
			return atPath(path+".schema", err)
		}

		if schema.Namespace() != target.Namespace() || schema.Name() != target.Action() {
			return atPath(path+".schema", fmt.Errorf("must belong to exact target %s", target.String()))
		}

		if previous, exists := seen[target.String()]; exists {
			return atPath(path, fmt.Errorf("duplicates exact target already declared at %s", previous))
		}

		seen[target.String()] = path

		n.targets = append(n.targets, normalizedTarget{config: configured, target: target, schema: schema, path: path})
	}

	return nil
}

// indexExportContracts constructs reusable exact cross-namespace capabilities first.
func (n *policyNormalizer) indexExportContracts() error {
	for _, namespace := range sortedKeys(n.policy.Namespaces) {
		configured := n.policy.Namespaces[namespace]

		for _, name := range sortedKeys(configured.PolicySets) {
			set := configured.PolicySets[name]
			if set.ExportContract == nil {
				continue
			}

			path := "policy.namespaces." + namespace + ".policy_sets." + name + ".export_contract"

			contract, err := normalizeExportContract(path, *set.ExportContract)
			if err != nil {
				return err
			}

			n.exports[namespace+"/"+name] = contract
		}
	}

	return nil
}

// normalizeDefinitions builds one deterministic immutable contribution per namespace.
func (n *policyNormalizer) normalizeDefinitions() ([]registry.DefinitionContribution, error) {
	buckets := make(map[string]*namespaceDefinitions)
	for namespace := range n.policy.Namespaces {
		buckets[namespace] = &namespaceDefinitions{}
	}

	if err := n.normalizeStaticSchemaDefinitions(buckets); err != nil {
		return nil, err
	}

	if err := n.normalizeTargetPlans(buckets); err != nil {
		return nil, err
	}

	for _, namespace := range sortedKeys(n.policy.Namespaces) {
		if err := n.normalizeNamespace(namespace, n.policy.Namespaces[namespace], buckets[namespace]); err != nil {
			return nil, err
		}
	}

	definitions := make([]registry.DefinitionContribution, 0, len(buckets))
	for _, namespace := range sortedKeys(buckets) {
		bucket := buckets[namespace]
		if bucket.empty() {
			continue
		}

		ownership, err := registry.NewNamespaceOwnership("config."+namespace, []string{namespace})
		if err != nil {
			return nil, atPath("policy.namespaces."+namespace, err)
		}

		contribution, err := registry.NewCompleteDefinitionContribution(registry.DefinitionContributionInput{
			Ownership: ownership, Targets: bucket.targets, Schemas: bucket.schemas,
			PolicySets: bucket.policySets, Plans: bucket.plans, Providers: bucket.providers, Effects: bucket.effects,
		})
		if err != nil {
			return nil, atPath("policy.namespaces."+namespace, err)
		}

		definitions = append(definitions, contribution)
	}

	return definitions, nil
}

// empty reports whether a namespace has only auxiliary configuration material.
func (d namespaceDefinitions) empty() bool {
	return len(d.targets)+len(d.schemas)+len(d.policySets)+len(d.plans)+len(d.providers)+len(d.effects) == 0
}

// atPath avoids replacing an already more-specific configuration path.
func atPath(path string, err error) error {
	if err == nil {
		return nil
	}

	if _, ok := err.(*PathError); ok {
		return err
	}

	return &PathError{Path: path, Cause: err}
}

// sortedKeys returns deterministic map keys.
func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}
