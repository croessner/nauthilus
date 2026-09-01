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

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	policy "github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

// normalizePolicySets constructs namespace-qualified reusable set definitions.
func (n *policyNormalizer) normalizePolicySets(
	namespace string,
	configured map[string]policyconfig.PolicySetConfig,
) ([]registry.PolicySetDefinition, error) {
	sets := make([]registry.PolicySetDefinition, 0, len(configured))

	for _, name := range sortedKeys(configured) {
		path := "policy.namespaces." + namespace + ".policy_sets." + name
		set := configured[name]

		identity, err := registry.NewPolicySetID(namespace, name)
		if err != nil {
			return nil, atPath(path, err)
		}

		rules, err := n.normalizePolicyRules(path+".rules", namespace, identity.String(), set.Rules)
		if err != nil {
			return nil, err
		}

		var contract *registry.ExportContract

		if configuredContract, exists := n.exports[identity.String()]; exists {
			contractCopy := configuredContract
			contract = &contractCopy
		}

		definition, err := registry.NewPolicySetDefinition(registry.PolicySetDefinitionInput{
			ExportContract: contract,
			ID:             identity,
			Visibility:     registry.PolicySetVisibility(set.Visibility),
			Rules:          rules,
			DiagnosticID:   set.Diagnostics.PublicID,
		})
		if err != nil {
			return nil, atPath(path, err)
		}

		sets = append(sets, definition)
	}

	return sets, nil
}

// normalizeExportContract constructs one exact typed reusable capability.
func normalizeExportContract(
	path string,
	configured policyconfig.ExportContractConfig,
) (registry.ExportContract, error) {
	facts := make([]registry.FactContract, 0, len(configured.RequiredFacts))
	for index, configuredFact := range configured.RequiredFacts {
		fact, err := registry.NewFactContract(configuredFact.Attribute, decision.ValueKind(configuredFact.Type))
		if err != nil {
			return registry.ExportContract{}, atPath(fmt.Sprintf("%s.required_facts[%d]", path, index), err)
		}

		facts = append(facts, fact)
	}

	decisions := make([]decision.Effect, 0, len(configured.AllowedDecisions))
	for index, configuredDecision := range configured.AllowedDecisions {
		selected, err := normalizeDecision(configuredDecision)
		if err != nil {
			return registry.ExportContract{}, atPath(fmt.Sprintf("%s.allowed_decisions[%d]", path, index), err)
		}

		decisions = append(decisions, selected)
	}

	contract, err := registry.NewExportContractForCheckpoints(
		configured.CompatibleCheckpoints,
		facts,
		decisions,
		configured.AllowedEffects,
	)
	if err != nil {
		return registry.ExportContract{}, atPath(path, err)
	}

	return contract, nil
}

// normalizePolicyRules constructs ordered executable rule descriptors.
func (n *policyNormalizer) normalizePolicyRules(
	path string,
	namespace string,
	setID string,
	configured []policyconfig.PolicyRuleConfig,
) ([]registry.PolicyRule, error) {
	rules := make([]registry.PolicyRule, 0, len(configured))

	for index, rule := range configured {
		rulePath := fmt.Sprintf("%s[%d]", path, index)

		definition, err := n.normalizePolicyRule(rulePath, namespace, setID, rule)
		if err != nil {
			return nil, err
		}

		rules = append(rules, definition)
	}

	return rules, nil
}

// normalizePolicyRule constructs one complete executable rule descriptor.
func (n *policyNormalizer) normalizePolicyRule(
	path string,
	namespace string,
	setID string,
	rule policyconfig.PolicyRuleConfig,
) (registry.PolicyRule, error) {
	expression, err := normalizeExpression(path+".if", rule.If)
	if err != nil {
		return registry.PolicyRule{}, err
	}

	effects, err := normalizeEffectUses(path+".then.obligations", rule.Then.Obligations)
	if err != nil {
		return registry.PolicyRule{}, err
	}

	advice, err := normalizeEffectUses(path+".then.advice", rule.Then.Advice)
	if err != nil {
		return registry.PolicyRule{}, err
	}

	message, err := normalizeResponseMessage(path+".then.response_message", rule.Then.ResponseMessage)
	if err != nil {
		return registry.PolicyRule{}, err
	}

	language, err := normalizeResponseLanguage(path+".then.response_language", rule.Then.ResponseLanguage)
	if err != nil {
		return registry.PolicyRule{}, err
	}

	selectedDecision, err := normalizePolicyRuleDecision(namespace, rule.Then.Decision)
	if err != nil {
		return registry.PolicyRule{}, atPath(path+".then.decision", err)
	}

	requiredProviders := make([]string, 0, len(rule.RequireProviders))
	for index, provider := range rule.RequireProviders {
		resolved, resolveErr := n.resolveRequiredProviderReference(namespace, setID, rule, provider)
		if resolveErr != nil {
			return registry.PolicyRule{}, atPath(fmt.Sprintf("%s.require_providers[%d]", path, index), resolveErr)
		}

		requiredProviders = append(requiredProviders, resolved)
	}

	ruleInput := registry.PolicyRuleInput{
		Name: rule.Name, Checkpoint: rule.Checkpoint, Actions: rule.Actions, RequiredProviders: requiredProviders,
		Expression: expression, Effects: effects, Advice: advice, Decision: selectedDecision, Reason: rule.Then.Reason,
		OutcomeMarker: rule.Then.OutcomeMarker, FSMEventMarker: rule.Then.FSMEventMarker,
		ResponseMarker: rule.Then.ResponseMarker, ResponseMessage: message, ResponseLanguage: language,
		SkipRemainingCheckpointProviders: rule.Then.Control.SkipRemainingCheckpointProviders,
	}

	var definition registry.PolicyRule

	if namespace == policy.AuthnNamespace {
		definition, err = registry.NewAuthnPolicyRule(ruleInput)
	} else {
		definition, err = registry.NewPolicyRule(ruleInput)
	}
	if err != nil {
		return registry.PolicyRule{}, atPath(path, err)
	}

	return definition, nil
}

// resolveRequiredProviderReference retains configured instance names and adapts only immutable builtin schedules.
func (n *policyNormalizer) resolveRequiredProviderReference(
	namespace string,
	setID string,
	rule policyconfig.PolicyRuleConfig,
	reference string,
) (string, error) {
	references := make(map[string]struct{})
	bound := false

	for _, target := range n.targets {
		if target.target.Namespace() != namespace || !ruleAllowsTargetAction(rule.Actions, target.target.Action()) ||
			!targetBindsPolicySet(target, rule.Checkpoint, setID) {
			continue
		}

		bound = true

		resolved, err := n.requiredProviderReferenceForTarget(namespace, rule, reference, target)
		if err != nil {
			return "", err
		}

		references[resolved] = struct{}{}
	}

	if !bound {
		return qualify(namespace, reference), nil
	}

	if len(references) > 1 {
		return "", fmt.Errorf("provider instance %s resolves to incompatible configured and builtin schedule identities", reference)
	}

	for resolved := range references {
		return resolved, nil
	}

	return "", fmt.Errorf("provider instance %s has no exact schedule reference", reference)
}

// requiredProviderReferenceForTarget resolves one target-specific configured or builtin schedule identity.
func (n *policyNormalizer) requiredProviderReferenceForTarget(
	namespace string,
	rule policyconfig.PolicyRuleConfig,
	reference string,
	target normalizedTarget,
) (string, error) {
	if target.config.DomainPlan == "" {
		if namespace != policy.AuthnNamespace {
			return qualify(namespace, reference), nil
		}

		use, exists := policy.AuthnBuiltinProviderUse(
			reference,
			policy.Operation(target.target.Action()),
			policy.Stage(rule.Checkpoint),
		)
		if !exists {
			return "", fmt.Errorf(
				"builtin provider instance %s is unavailable at checkpoint %s for action %s",
				reference,
				rule.Checkpoint,
				target.target.Action(),
			)
		}

		return use, nil
	}

	plan, err := n.selectedDomainPlan(target)
	if err != nil {
		return "", err
	}

	checkpoint, exists := plan.Checkpoints[rule.Checkpoint]
	if exists {
		for _, instance := range checkpoint.Providers {
			if instance.Name == reference && providerInstanceAllowsAction(instance, target.target.Action()) {
				return reference, nil
			}
		}
	}

	return "", fmt.Errorf(
		"provider instance %s is unavailable at checkpoint %s for action %s",
		reference,
		rule.Checkpoint,
		target.target.Action(),
	)
}

// targetBindsPolicySet reports whether one exact target checkpoint selects a configured set root.
func targetBindsPolicySet(target normalizedTarget, checkpoint string, setID string) bool {
	binding, exists := target.config.Plans[checkpoint]

	return exists && slices.Contains(binding.PolicySets, setID)
}

// ruleAllowsTargetAction applies an omitted rule action list to every target action.
func ruleAllowsTargetAction(actions []string, action string) bool {
	return len(actions) == 0 || slices.Contains(actions, action)
}

// normalizeEffectUses constructs exact typed obligation or advice selections.
func normalizeEffectUses(
	path string,
	configured []policyconfig.EffectSelectionConfig,
) ([]registry.EffectUse, error) {
	uses := make([]registry.EffectUse, 0, len(configured))

	for index, selection := range configured {
		parameters := make(map[string]decision.Value, len(selection.Parameters))
		for name, configuredValue := range selection.Parameters {
			value, err := normalizeValue(configuredValue)
			if err != nil {
				return nil, atPath(fmt.Sprintf("%s[%d].parameters.%s", path, index, name), err)
			}

			parameters[name] = value
		}

		use, err := registry.NewEffectUse(selection.ID, parameters)
		if err != nil {
			return nil, atPath(fmt.Sprintf("%s[%d]", path, index), err)
		}

		uses = append(uses, use)
	}

	return uses, nil
}

// normalizeResponseMessage retains the complete optional public message source contract.
func normalizeResponseMessage(
	path string,
	configured policyconfig.ResponseMessageConfig,
) (registry.PolicyResponseMessage, error) {
	if configured == (policyconfig.ResponseMessageConfig{}) {
		return registry.PolicyResponseMessage{}, nil
	}

	maximumLength := 0
	factID := configured.Attribute

	if configured.From == "attribute_detail" {
		maximumLength = 4096
		factID = policy.AuthnResponseDetailFactID(configured.Attribute, configured.Detail)
	}

	message, err := registry.NewPolicyResponseMessage(registry.PolicyResponseMessageInput{
		From: configured.From, Text: configured.Text, I18NKey: configured.I18NKey,
		FactID: factID, Detail: configured.Detail, Fallback: configured.Fallback,
		MaxLength: maximumLength,
	})
	if err != nil {
		return registry.PolicyResponseMessage{}, atPath(path, err)
	}

	return message, nil
}

// normalizeResponseLanguage retains the complete optional response-language source contract.
func normalizeResponseLanguage(
	path string,
	configured policyconfig.ResponseLanguageConfig,
) (registry.PolicyResponseLanguage, error) {
	if configured == (policyconfig.ResponseLanguageConfig{}) {
		return registry.PolicyResponseLanguage{}, nil
	}

	language, err := registry.NewPolicyResponseLanguage(registry.PolicyResponseLanguageInput{
		From: configured.From, Language: configured.Language,
		FactID: configured.Attribute, Fallback: configured.Fallback,
	})
	if err != nil {
		return registry.PolicyResponseLanguage{}, atPath(path, err)
	}

	return language, nil
}

// normalizeDecision maps the closed generic rule result vocabulary.
func normalizeDecision(value string) (decision.Effect, error) {
	switch value {
	case string(decision.EffectPermit):
		return decision.EffectPermit, nil
	case string(decision.EffectDeny):
		return decision.EffectDeny, nil
	default:
		return "", fmt.Errorf("must be permit or deny")
	}
}

// normalizePolicyRuleDecision maps namespace-owned operator outcomes onto runtime effects.
func normalizePolicyRuleDecision(namespace string, value string) (decision.Effect, error) {
	selected, err := normalizeDecision(value)
	if err == nil || namespace != policy.AuthnNamespace {
		return selected, err
	}

	switch value {
	case string(policy.DecisionTempFail):
		return decision.EffectIndeterminate, nil
	case string(policy.DecisionNeutral):
		return decision.EffectNotApplicable, nil
	default:
		return "", fmt.Errorf("must be permit, deny, tempfail, or neutral for authn rules")
	}
}
