// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"fmt"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

const effectKindLuaAction = "lua_action"

// normalizeNamespace maps every catalog-representable namespace-owned definition.
func (n *policyNormalizer) normalizeNamespace(
	namespace string,
	configured policyconfig.NamespaceConfig,
	bucket *namespaceDefinitions,
) error {
	sets, err := n.normalizePolicySets(namespace, configured.PolicySets)
	if err != nil {
		return err
	}

	providers, err := n.normalizeProviders(namespace, configured.Providers)
	if err != nil {
		return err
	}

	effects, err := n.normalizeEffects(namespace, configured.Effects)
	if err != nil {
		return err
	}

	bucket.policySets = append(bucket.policySets, sets...)
	bucket.providers = append(bucket.providers, providers...)
	bucket.effects = append(bucket.effects, effects...)

	return nil
}

// normalizeProviders constructs exact target-aware host provider descriptors.
func (n *policyNormalizer) normalizeProviders(
	namespace string,
	configured map[string]policyconfig.ProviderConfig,
) ([]registry.ProviderDefinition, error) {
	providers := make([]registry.ProviderDefinition, 0, len(configured))

	for _, name := range sortedKeys(configured) {
		path := "policy.namespaces." + namespace + ".providers." + name
		provider := configured[name]

		targets, err := normalizeTargetReferences(path+".targets", namespace, provider.Targets)
		if err != nil {
			return nil, err
		}

		if len(targets) == 0 {
			targets = n.deriveProviderTargets(namespace + "/" + name)
		}

		executions, err := normalizeExecutions(path+".executions", provider.Executions)
		if err != nil {
			return nil, err
		}

		if len(executions) == 0 && len(targets) > 0 {
			executions = []registry.ExecutionClass{registry.ExecutionHostSync}
		}

		timeout := provider.Timeout
		if namespace != policy.AuthnNamespace {
			timeout, err = n.normalizeProviderTimeout(path+".timeout", provider.Timeout, targets)
			if err != nil {
				return nil, err
			}
		}

		requires := make([]string, 0, len(provider.Requires))
		for _, requirement := range provider.Requires {
			requires = append(requires, qualify(namespace, requirement))
		}

		definition, err := registry.NewProviderDefinition(registry.ProviderDefinitionInput{
			PostActionAcceptance: n.acceptance,
			ID:                   namespace + "/" + name,
			Targets:              targets,
			Executions:           executions,
			Requires:             requires,
			ProducedFacts:        provider.ProducedFacts,
			Failure:              registry.ProviderFailureBehavior(provider.Failure),
			Timeout:              timeout,
			DiagnosticID:         provider.Diagnostics.PublicID,
		})
		if err != nil {
			return nil, atPath(path, err)
		}

		providers = append(providers, definition)
	}

	return providers, nil
}

// normalizeProviderTimeout applies the shortest matching target default when a generic provider omits one.
func (n *policyNormalizer) normalizeProviderTimeout(
	path string,
	configured time.Duration,
	targets []decision.Target,
) (time.Duration, error) {
	if configured > 0 {
		return configured, nil
	}

	allowed := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		allowed[target.String()] = struct{}{}
	}

	var resolved time.Duration

	for _, target := range n.targets {
		if _, exists := allowed[target.target.String()]; !exists {
			continue
		}

		candidate := target.config.Timeouts.ProviderDefault
		if candidate > 0 && (resolved == 0 || candidate < resolved) {
			resolved = candidate
		}
	}

	if resolved == 0 && len(targets) > 0 {
		return 0, atPath(path, fmt.Errorf("requires an explicit timeout or a matching generic target default"))
	}

	return resolved, nil
}

// normalizeEffects constructs exact typed effect descriptors while retaining binding metadata in Policy.
func (n *policyNormalizer) normalizeEffects(
	namespace string,
	configured map[string]policyconfig.EffectConfig,
) ([]registry.EffectDefinition, error) {
	effects := make([]registry.EffectDefinition, 0, len(configured))

	for _, name := range sortedKeys(configured) {
		definition, err := normalizeEffect(namespace, name, configured[name])
		if err != nil {
			return nil, err
		}

		effects = append(effects, definition)
	}

	return effects, nil
}

// normalizeEffect constructs one typed effect descriptor with canonical host ownership.
func normalizeEffect(
	namespace string,
	name string,
	effect policyconfig.EffectConfig,
) (registry.EffectDefinition, error) {
	path := "policy.namespaces." + namespace + ".effects." + name

	targets, err := normalizeEffectTargets(path, namespace, effect)
	if err != nil {
		return registry.EffectDefinition{}, err
	}

	parameters, err := normalizeEffectParameters(path+".parameters", effect.Parameters)
	if err != nil {
		return registry.EffectDefinition{}, err
	}

	provider, err := normalizeEffectProvider(path, namespace, effect)
	if err != nil {
		return registry.EffectDefinition{}, err
	}

	definition, err := registry.NewEffectDefinition(registry.EffectDefinitionInput{
		ID:           namespace + "/" + name,
		Provider:     provider,
		DiagnosticID: effect.Diagnostics.PublicID,
		Targets:      targets,
		Parameters:   parameters,
		Kind:         normalizeEffectKind(effect.Kind),
		Execution:    registry.ExecutionClass(effect.Execution),
	})
	if err != nil {
		return registry.EffectDefinition{}, atPath(path, err)
	}

	return definition, nil
}

// normalizeEffectTargets applies immutable authentication surfaces when a Lua action omits targets.
func normalizeEffectTargets(
	path string,
	namespace string,
	effect policyconfig.EffectConfig,
) ([]decision.Target, error) {
	targets, err := normalizeTargetReferences(path+".targets", namespace, effect.Targets)
	if err != nil {
		return nil, err
	}

	if namespace != policy.AuthnNamespace || effect.Kind != effectKindLuaAction || len(targets) > 0 {
		return targets, nil
	}

	targets, err = builtinLuaActionTargets()
	if err != nil {
		return nil, atPath(path+".targets", err)
	}

	return targets, nil
}

// normalizeEffectProvider resolves immutable Lua ownership or qualifies an authored provider reference.
func normalizeEffectProvider(
	path string,
	namespace string,
	effect policyconfig.EffectConfig,
) (string, error) {
	if namespace == policy.AuthnNamespace && effect.Kind == effectKindLuaAction && effect.Provider == "" {
		provider, err := builtinLuaActionProvider(effect.ActionType, registry.ExecutionClass(effect.Execution))
		if err != nil {
			return "", atPath(path+".provider", err)
		}

		return provider, nil
	}

	if effect.Provider != "" {
		return qualify(namespace, effect.Provider), nil
	}

	return "", nil
}

// builtinLuaActionTargets returns the immutable authentication surfaces served by Lua action owners.
func builtinLuaActionTargets() ([]decision.Target, error) {
	actions := []policy.Operation{policy.OperationAuthenticate, policy.OperationLookupIdentity}
	targets := make([]decision.Target, 0, len(actions))

	for _, action := range actions {
		target, err := decision.NewTarget(policy.AuthnNamespace, string(action))
		if err != nil {
			return nil, err
		}

		targets = append(targets, target)
	}

	return targets, nil
}

// builtinLuaActionProvider resolves host ownership without exposing an operator provider field.
func builtinLuaActionProvider(actionType string, execution registry.ExecutionClass) (string, error) {
	selection := policy.ObligationLuaActionDispatch
	if actionType == "post" {
		selection = policy.ObligationLuaPostActionEnqueue
	}

	for _, binding := range registry.BuiltinAuthEffectBindings() {
		if binding.Selection != selection {
			continue
		}

		if binding.Execution != execution {
			return "", fmt.Errorf("action_type %s requires %s execution", actionType, binding.Execution)
		}

		return binding.Provider, nil
	}

	return "", fmt.Errorf("no immutable Lua action host provider for action_type %s", actionType)
}

// normalizeTargetReferences qualifies namespace-owned target action allowlists.
func normalizeTargetReferences(
	path string,
	namespace string,
	references []policyconfig.TargetReferenceConfig,
) ([]decision.Target, error) {
	targets := make([]decision.Target, 0, len(references))

	for index, reference := range references {
		target, err := decision.NewTarget(namespace, reference.Action)
		if err != nil {
			return nil, atPath(fmt.Sprintf("%s[%d].action", path, index), err)
		}

		targets = append(targets, target)
	}

	return targets, nil
}

// normalizeExecutions maps the closed configuration spelling without adding aliases.
func normalizeExecutions(path string, values []string) ([]registry.ExecutionClass, error) {
	executions := make([]registry.ExecutionClass, 0, len(values))

	for index, value := range values {
		execution := registry.ExecutionClass(value)
		if execution != registry.ExecutionHostSync && execution != registry.ExecutionHostPostAction {
			return nil, atPath(fmt.Sprintf("%s[%d]", path, index), fmt.Errorf("provider execution must be host_sync or host_post_action"))
		}

		executions = append(executions, execution)
	}

	return executions, nil
}

// normalizeEffectParameters constructs sorted strict parameter declarations.
func normalizeEffectParameters(
	path string,
	configured map[string]policyconfig.EffectParameterConfig,
) ([]registry.ParameterSchema, error) {
	parameters := make([]registry.ParameterSchema, 0, len(configured))

	for _, name := range sortedKeys(configured) {
		parameter := configured[name]

		definition, err := registry.NewParameterSchema(registry.ParameterSchemaInput{
			Name: name, Kind: decision.ValueKind(parameter.Type), MaxLength: parameter.MaxLength,
			MaxItems: parameter.MaxItems, MaxBytes: parameter.MaxBytes,
			AllowedStrings: parameter.AllowedStrings, NonEmpty: parameter.NonEmpty, Required: parameter.Required,
		})
		if err != nil {
			return nil, atPath(path+"."+name, err)
		}

		parameters = append(parameters, definition)
	}

	return parameters, nil
}

// normalizeEffectKind separates advice from implementation-family kind spellings.
func normalizeEffectKind(kind string) registry.EffectKind {
	if kind == string(registry.EffectKindAdvice) {
		return registry.EffectKindAdvice
	}

	return registry.EffectKindObligation
}

// deriveProviderTargets finds exact plan usages when the descriptor omits a redundant allowlist.
func (n *policyNormalizer) deriveProviderTargets(providerID string) []decision.Target {
	targets := make([]decision.Target, 0)
	seen := make(map[string]struct{})

	for _, target := range n.targets {
		plan, err := n.selectedDomainPlan(target)
		if err != nil {
			continue
		}

		for _, checkpoint := range plan.Checkpoints {
			for _, instance := range checkpoint.Providers {
				if instance.Use != providerID {
					continue
				}

				if _, exists := seen[target.target.String()]; !exists {
					seen[target.target.String()] = struct{}{}
					targets = append(targets, target.target)
				}
			}
		}
	}

	return targets
}

// qualify applies namespace ownership only to local component references.
func qualify(namespace string, reference string) string {
	if strings.Contains(reference, "/") {
		return reference
	}

	return namespace + "/" + reference
}
