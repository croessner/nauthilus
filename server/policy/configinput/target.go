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

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

// normalizeTargetPlans instantiates configured plan topology only for explicitly selected targets.
func (n *policyNormalizer) normalizeTargetPlans(buckets map[string]*namespaceDefinitions) error {
	for _, target := range n.targets {
		if target.target.Namespace() == policy.AuthnNamespace {
			if !builtinAuthnSchema(target.schema.String()) {
				return atPath(target.path+".schema", fmt.Errorf("authn accepts only builtin exact v1 schemas"))
			}

			continue
		}

		bucket := buckets[target.target.Namespace()]
		if bucket == nil {
			bucket = &namespaceDefinitions{}
			buckets[target.target.Namespace()] = bucket
		}

		plan, err := n.normalizeDomainPlan(target)
		if err != nil {
			return err
		}

		bucket.plans = append(bucket.plans, plan)
	}

	return nil
}

// normalizeDomainPlan instantiates one named auxiliary plan for its selected exact target.
func (n *policyNormalizer) normalizeDomainPlan(target normalizedTarget) (registry.DomainPlanDefinition, error) {
	configured, err := n.selectedDomainPlan(target)
	if err != nil {
		return registry.DomainPlanDefinition{}, err
	}

	checkpointNames := make(map[string]struct{}, len(target.config.Plans)+len(configured.Checkpoints))
	for name := range target.config.Plans {
		checkpointNames[name] = struct{}{}
	}

	for name := range configured.Checkpoints {
		checkpointNames[name] = struct{}{}
	}

	checkpoints := make([]registry.CheckpointDefinition, 0, len(checkpointNames))
	for _, name := range sortedKeys(checkpointNames) {
		providers := configured.Checkpoints[name].Providers
		providerIDs := make([]string, 0, len(providers))

		for index, provider := range providers {
			path := target.path + ".domain_plan.checkpoints." + name + fmt.Sprintf(".providers[%d].use", index)
			if provider.Use == "" {
				return registry.DomainPlanDefinition{}, atPath(path, fmt.Errorf("provider use is required"))
			}

			providerIDs = append(providerIDs, provider.Use)
		}

		checkpoint, err := registry.NewCheckpointDefinition(name, nil, providerIDs)
		if err != nil {
			return registry.DomainPlanDefinition{}, atPath(target.path+".plans."+name, err)
		}

		checkpoints = append(checkpoints, checkpoint)
	}

	plan, err := registry.NewDomainPlanDefinition(target.target, checkpoints)
	if err != nil {
		return registry.DomainPlanDefinition{}, atPath(target.path+".domain_plan", err)
	}

	return plan, nil
}

// selectedDomainPlan resolves an optional exact qualified namespace-local plan.
func (n *policyNormalizer) selectedDomainPlan(target normalizedTarget) (policyconfig.DomainPlanConfig, error) {
	if target.config.DomainPlan == "" {
		return policyconfig.DomainPlanConfig{}, nil
	}

	namespace, name, ok := strings.Cut(target.config.DomainPlan, "/")
	if !ok || namespace == "" || name == "" || strings.Contains(name, "/") {
		return policyconfig.DomainPlanConfig{}, atPath(target.path+".domain_plan", fmt.Errorf("must use exact namespace/name form"))
	}

	owner, exists := n.policy.Namespaces[namespace]
	if !exists {
		return policyconfig.DomainPlanConfig{}, atPath(target.path+".domain_plan", fmt.Errorf("unknown namespace %s", namespace))
	}

	plan, exists := owner.DomainPlans[name]
	if !exists {
		return policyconfig.DomainPlanConfig{}, atPath(target.path+".domain_plan", fmt.Errorf("unknown plan %s", target.config.DomainPlan))
	}

	return plan, nil
}

// normalizeActivations merges explicit configured selections over builtin authn defaults.
func (n *policyNormalizer) normalizeActivations() ([]registry.TargetActivation, error) {
	defaults, err := builtinActivations()
	if err != nil {
		return nil, err
	}

	authnConfigured := make(map[string]normalizedTarget)

	for _, target := range n.targets {
		if target.target.Namespace() == policy.AuthnNamespace {
			authnConfigured[target.target.String()] = target
		}
	}

	activations := make([]registry.TargetActivation, 0, len(defaults)+len(n.targets))
	for _, activation := range defaults {
		configured, exists := authnConfigured[activation.Target().String()]
		if !exists {
			activations = append(activations, activation)

			continue
		}

		projected, err := n.normalizeActivation(configured)
		if err != nil {
			return nil, err
		}

		activations = append(activations, projected)
	}

	for _, target := range n.targets {
		if target.target.Namespace() == policy.AuthnNamespace {
			continue
		}

		activation, err := n.normalizeActivation(target)
		if err != nil {
			return nil, err
		}

		activations = append(activations, activation)
	}

	return activations, nil
}

// normalizeActivation constructs policy selection and ordered checkpoint bindings.
func (n *policyNormalizer) normalizeActivation(target normalizedTarget) (registry.TargetActivation, error) {
	activation, err := registry.NewTargetActivation(
		target.path, target.target.Namespace(), target.target.Action(), target.schema.String(),
	)
	if err != nil {
		return registry.TargetActivation{}, atPath(target.path, err)
	}

	activation, err = activation.WithPolicy(target.config.DefaultPolicy, target.config.NoMatch)
	if err != nil {
		return registry.TargetActivation{}, atPath(target.path, err)
	}

	activation, err = activation.WithAuthorityMode(registry.AuthorityMode(target.config.Mode))
	if err != nil {
		return registry.TargetActivation{}, atPath(target.path+".mode", err)
	}

	bindings, err := n.normalizeTargetBindings(target)
	if err != nil {
		return registry.TargetActivation{}, err
	}

	activation, err = activation.WithPolicySetBindings(bindings)
	if err != nil {
		return registry.TargetActivation{}, atPath(target.path+".plans", err)
	}

	return activation, nil
}

// normalizeTargetBindings projects each ordered exact set reference with its import contract.
func (n *policyNormalizer) normalizeTargetBindings(target normalizedTarget) ([]registry.PolicySetImport, error) {
	bindings := make([]registry.PolicySetImport, 0)

	for _, checkpoint := range sortedKeys(target.config.Plans) {
		for index, reference := range target.config.Plans[checkpoint].PolicySets {
			path := target.path + ".plans." + checkpoint + fmt.Sprintf(".policy_sets[%d]", index)
			contract := registry.ExportContract{}

			setNamespace, _, ok := strings.Cut(reference, "/")
			if !ok {
				return nil, atPath(path, fmt.Errorf("must use exact namespace/name form"))
			}

			if setNamespace != target.target.Namespace() {
				var exists bool

				contract, exists = n.exports[reference]
				if !exists {
					return nil, atPath(path, fmt.Errorf("cross-namespace set requires a complete export contract"))
				}
			}

			binding, err := registry.NewPolicySetImport(path, reference, target.target, checkpoint, contract)
			if err != nil {
				return nil, atPath(path, err)
			}

			bindings = append(bindings, binding)
		}
	}

	return bindings, nil
}

// normalizeAdmissions expands client action grants against exact activated schemas.
func (n *policyNormalizer) normalizeAdmissions(
	activations []registry.TargetActivation,
) ([]registry.ClientAdmissionReference, []ClientAdmissionProfile, error) {
	byTarget := make(map[string]registry.TargetActivation, len(activations))
	for _, activation := range activations {
		byTarget[activation.Target().String()] = activation
	}

	all := make([]registry.ClientAdmissionReference, 0)
	profiles := make([]ClientAdmissionProfile, 0, len(n.policy.API.Clients))

	for clientIndex, client := range n.policy.API.Clients {
		references := make([]registry.ClientAdmissionReference, 0)

		for targetIndex, grant := range client.Targets {
			for actionIndex, action := range grant.Actions {
				path := fmt.Sprintf("policy.api.clients[%d].targets[%d].actions[%d]", clientIndex, targetIndex, actionIndex)
				identity := grant.Namespace + "/" + action

				activation, exists := byTarget[identity]
				if !exists {
					return nil, nil, atPath(path, fmt.Errorf("target %s is not explicitly activated", identity))
				}

				if len(client.AllowedSchemas) > 0 && !slices.Contains(client.AllowedSchemas, activation.Schema().String()) {
					return nil, nil, atPath(path, fmt.Errorf("schema %s is outside allowed_schemas", activation.Schema().String()))
				}

				reference, err := registry.NewClientAdmissionReference(
					path, grant.Namespace, action, activation.Schema().String(),
				)
				if err != nil {
					return nil, nil, atPath(path, err)
				}

				references = append(references, reference)
				all = append(all, reference)
			}
		}

		profiles = append(profiles, ClientAdmissionProfile{Principal: client.Principal, References: references})
	}

	return all, profiles, nil
}

// builtinAuthnSchema reports whether an exact schema belongs to the immutable v1 catalog.
func builtinAuthnSchema(schema string) bool {
	for _, target := range builtinAuthnTargets {
		if target.schema == schema {
			return true
		}
	}

	return false
}
