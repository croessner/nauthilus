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

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

// validateCompiledSchedulerGuards resolves every guard and reachable rule against candidate material.
func validateCompiledSchedulerGuards(
	catalog *policyruntime.TargetCatalog,
	configured policyconfig.PolicyConfig,
) error {
	conditionSets, timeWindows, err := PrepareConditionMaterial(configured)
	if err != nil {
		return err
	}

	for _, target := range catalog.Targets() {
		if err = validateCompiledTargetGuards(target, conditionSets, timeWindows); err != nil {
			return err
		}
	}

	return nil
}

// validateCompiledTargetGuards validates scheduler and policy expressions for one target.
func validateCompiledTargetGuards(
	target policyruntime.CompiledTarget,
	conditionSets map[string][]decision.Value,
	timeWindows map[string]policyruntime.CompiledTimeWindow,
) error {
	schema := make(map[string]registry.FactSchema)
	for _, fact := range target.Schema().Facts() {
		schema[fact.ID()] = fact
	}

	for _, checkpoint := range target.DomainPlan().Checkpoints() {
		if err := validateCompiledProviderDependencies(target, checkpoint); err != nil {
			return err
		}
	}

	if err := validateTargetSchedulerGuards(target, schema, conditionSets, timeWindows); err != nil {
		return err
	}

	return validateTargetPolicySets(target, schema, conditionSets, timeWindows)
}

// validateTargetSchedulerGuards validates every compiled scheduler predicate and its pre-host sources.
func validateTargetSchedulerGuards(
	target policyruntime.CompiledTarget,
	schema map[string]registry.FactSchema,
	conditionSets map[string][]decision.Value,
	timeWindows map[string]policyruntime.CompiledTimeWindow,
) error {
	hostGuards := hostSchedulerGuardNames(target)
	for _, guard := range target.DomainPlan().SchedulerGuards() {
		err := validateCandidateExpression(
			target.Target().Namespace(), guard.Expression(), schema, conditionSets, timeWindows,
		)
		if err != nil {
			return fmt.Errorf("scheduler guard %s/%s: %w", target.Target().String(), guard.Name(), err)
		}

		if _, usedByHost := hostGuards[guard.Name()]; !usedByHost {
			continue
		}

		if err = validateHostSchedulerGuardSources(guard.Expression(), schema); err != nil {
			return fmt.Errorf("scheduler guard %s/%s: %w", target.Target().String(), guard.Name(), err)
		}
	}

	return nil
}

// validateTargetPolicySets validates each reachable compiled set once.
func validateTargetPolicySets(
	target policyruntime.CompiledTarget,
	schema map[string]registry.FactSchema,
	conditionSets map[string][]decision.Value,
	timeWindows map[string]policyruntime.CompiledTimeWindow,
) error {
	validatedSets := make(map[string]struct{})

	for _, checkpoint := range target.DomainPlan().Checkpoints() {
		for _, setName := range checkpoint.PolicySetIDs() {
			if _, exists := validatedSets[setName]; exists {
				continue
			}

			if err := validateTargetPolicySet(target, setName, schema, conditionSets, timeWindows); err != nil {
				return err
			}

			validatedSets[setName] = struct{}{}
		}
	}

	return nil
}

// validateTargetPolicySet validates one reachable compiled policy set.
func validateTargetPolicySet(
	target policyruntime.CompiledTarget,
	setName string,
	schema map[string]registry.FactSchema,
	conditionSets map[string][]decision.Value,
	timeWindows map[string]policyruntime.CompiledTimeWindow,
) error {
	setID, err := registry.ParsePolicySetID("compiled policy set", setName)
	if err != nil {
		return err
	}

	set, exists := target.LookupPolicySet(setID)
	if !exists {
		return fmt.Errorf("compiled policy set %s is unavailable", setName)
	}

	for _, rule := range set.Rules() {
		if err = validateCandidateExpression(
			target.Target().Namespace(), rule.Expression(), schema, conditionSets, timeWindows,
		); err != nil {
			return fmt.Errorf(
				"policy rule %s/%s/%s: %w", target.Target().String(), setName, rule.Name(), err,
			)
		}
	}

	return nil
}

// hostSchedulerGuardNames indexes guards that can suppress transport-owned authn work.
func hostSchedulerGuardNames(target policyruntime.CompiledTarget) map[string]struct{} {
	result := make(map[string]struct{})

	for _, checkpoint := range target.DomainPlan().Checkpoints() {
		for _, instance := range checkpoint.ProviderInstances() {
			if !target.HostPreparesProvider(instance.Use()) {
				continue
			}

			for _, guardName := range instance.SkipIf() {
				result[guardName] = struct{}{}
			}
		}
	}

	return result
}

// validateHostSchedulerGuardSources rejects facts unavailable before host execution.
func validateHostSchedulerGuardSources(
	expression registry.PolicyExpression,
	schema map[string]registry.FactSchema,
) error {
	if expression.Kind() != registry.ExpressionKindAttribute {
		for _, child := range expression.Children() {
			if err := validateHostSchedulerGuardSources(child, schema); err != nil {
				return err
			}
		}

		return nil
	}

	fact, exists := schema[expression.FactID()]
	if !exists {
		return fmt.Errorf("fact %s is absent from the selected schema", expression.FactID())
	}

	for _, source := range fact.AllowedSources() {
		switch source {
		case decision.FactSourceBackend, decision.FactSourceLua, decision.FactSourcePlugin:
			return fmt.Errorf(
				"fact %s source %s is unavailable before host scheduling",
				expression.FactID(),
				source,
			)
		case decision.FactSourceNauthilus:
			if !hostSchedulerNauthilusFactAvailable(expression.FactID()) {
				return fmt.Errorf(
					"fact %s source %s is unavailable before host scheduling",
					expression.FactID(),
					source,
				)
			}
		}
	}

	return nil
}

// hostSchedulerNauthilusFactAvailable identifies authenticator facts admitted before host execution.
func hostSchedulerNauthilusFactAvailable(factID string) bool {
	switch factID {
	case decision.FactCallerPrincipal,
		decision.FactCallerClientID,
		decision.FactCallerAuthenticationKind,
		decision.FactCallerScopes:
		return true
	default:
		return false
	}
}

// validateCompiledProviderDependencies checks definition-owned and authored edges against scheduler guards.
func validateCompiledProviderDependencies(
	target policyruntime.CompiledTarget,
	checkpoint policyruntime.CompiledCheckpoint,
) error {
	for _, instance := range checkpoint.ProviderInstances() {
		for _, dependencyName := range instance.Dependencies() {
			dependency, exists := checkpoint.LookupProviderInstance(dependencyName)
			if !exists {
				return fmt.Errorf(
					"compiled provider %s/%s/%s has unavailable dependency %s",
					target.Target().String(), checkpoint.Name(), instance.Name(), dependencyName,
				)
			}

			if !providerRunIfCovers(dependency.RunIfAuthState(), instance.RunIfAuthState()) {
				return fmt.Errorf(
					"compiled provider %s/%s/%s dependency %s has incompatible run_if.auth_state",
					target.Target().String(), checkpoint.Name(), instance.Name(), dependencyName,
				)
			}

			if !providerGuardsCover(instance.SkipIf(), dependency.SkipIf()) {
				return fmt.Errorf(
					"compiled provider %s/%s/%s must include scheduler guards used by dependency %s",
					target.Target().String(), checkpoint.Name(), instance.Name(), dependencyName,
				)
			}
		}
	}

	return nil
}

// validateCandidateExpression recursively checks schema kinds and namespace-scoped reference existence.
func validateCandidateExpression(
	namespace string,
	expression registry.PolicyExpression,
	schema map[string]registry.FactSchema,
	conditionSets map[string][]decision.Value,
	timeWindows map[string]policyruntime.CompiledTimeWindow,
) error {
	if expression.Kind() != registry.ExpressionKindAttribute {
		return validateCandidateExpressionChildren(namespace, expression.Children(), schema, conditionSets, timeWindows)
	}

	fact, exists := schema[expression.FactID()]
	if !exists {
		return fmt.Errorf("fact %s is absent from the selected schema", expression.FactID())
	}

	if expression.Operator() != registry.ExpressionOperatorExists && fact.Kind() != expression.FactKind() {
		return fmt.Errorf(
			"fact %s has kind %s, guard requires %s",
			expression.FactID(),
			fact.Kind(),
			expression.FactKind(),
		)
	}

	reference := expression.Reference()
	if reference == "" {
		return nil
	}

	return validateCandidateExpressionReference(namespace, reference, fact, conditionSets, timeWindows)
}

// validateCandidateExpressionChildren recursively validates each composite expression child.
func validateCandidateExpressionChildren(
	namespace string,
	children []registry.PolicyExpression,
	schema map[string]registry.FactSchema,
	conditionSets map[string][]decision.Value,
	timeWindows map[string]policyruntime.CompiledTimeWindow,
) error {
	for _, child := range children {
		if err := validateCandidateExpression(namespace, child, schema, conditionSets, timeWindows); err != nil {
			return err
		}
	}

	return nil
}

// validateCandidateExpressionReference resolves one namespace-scoped condition material reference.
func validateCandidateExpressionReference(
	namespace string,
	reference string,
	fact registry.FactSchema,
	conditionSets map[string][]decision.Value,
	timeWindows map[string]policyruntime.CompiledTimeWindow,
) error {
	key := policyruntime.ConditionMaterialKey(namespace, reference)
	if strings.HasPrefix(reference, "@time_window.") {
		if _, exists := timeWindows[key]; !exists {
			return fmt.Errorf("time-window reference %s is unavailable", reference)
		}

		return nil
	}

	values, exists := conditionSets[key]
	if !exists || len(values) == 0 {
		return fmt.Errorf("condition-set reference %s is unavailable", reference)
	}

	for _, value := range values {
		if value.Kind() != fact.Kind() {
			return fmt.Errorf("condition-set reference %s has the wrong value kind", reference)
		}
	}

	return nil
}
