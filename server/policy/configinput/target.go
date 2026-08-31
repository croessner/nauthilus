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
	policy "github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

// normalizeTargetPlans instantiates configured plan topology only for explicitly selected targets.
func (n *policyNormalizer) normalizeTargetPlans(buckets map[string]*namespaceDefinitions) error {
	for _, target := range n.targets {
		if target.target.Namespace() == policy.AuthnNamespace {
			if !builtinAuthnSchema(target.schema.String()) {
				return atPath(target.path+".schema", fmt.Errorf("authn accepts only builtin exact v1 schemas"))
			}

			if target.config.DomainPlan == "" {
				continue
			}
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

	planPath := selectedDomainPlanPath(target)
	checkpointNames := normalizedCheckpointNames(target, configured)
	checkpoints := make([]registry.CheckpointDefinition, 0, len(checkpointNames))

	for _, name := range checkpointNames {
		checkpointPath := planPath + ".checkpoints." + name

		providerInstances, providerErr := orderedProviderInstances(
			checkpointPath+".providers",
			target.target.Namespace(),
			target.target.Action(),
			configured.Checkpoints[name].Providers,
			n.resolveProviderReference,
		)
		if providerErr != nil {
			return registry.DomainPlanDefinition{}, providerErr
		}

		policySets, bindingErr := authnFallbackBindings(target, checkpointPath, name)
		if bindingErr != nil {
			return registry.DomainPlanDefinition{}, bindingErr
		}

		checkpoint, err := registry.NewCheckpointDefinitionWithProviderInstances(name, policySets, providerInstances)
		if err != nil {
			return registry.DomainPlanDefinition{}, atPath(checkpointPath, err)
		}

		checkpoints = append(checkpoints, checkpoint)
	}

	guards, err := normalizeSchedulerGuards(
		planPath+".scheduler_guards",
		target.target,
		configured.SchedulerGuards,
	)
	if err != nil {
		return registry.DomainPlanDefinition{}, err
	}

	var plan registry.DomainPlanDefinition
	if target.target.Namespace() == policy.AuthnNamespace {
		plan, err = registry.NewAuthnDomainPlanDefinitionWithSchedulerGuards(target.target, checkpoints, guards)
	} else {
		plan, err = registry.NewDomainPlanDefinitionWithSchedulerGuards(target.target, checkpoints, guards)
	}

	if err != nil {
		return registry.DomainPlanDefinition{}, atPath(planPath, err)
	}

	return plan, nil
}

// normalizeSchedulerGuards compiles plan-local guard expressions through the standalone expression authority.
func normalizeSchedulerGuards(
	path string,
	target decision.Target,
	configured map[string]policyconfig.SchedulerGuardConfig,
) ([]registry.SchedulerGuardDefinition, error) {
	guards := make([]registry.SchedulerGuardDefinition, 0, len(configured))

	for _, name := range sortedKeys(configured) {
		guardPath := path + "." + name
		guardConfig := configured[name]

		expression, err := normalizeExpression(guardPath+".if", guardConfig.If)
		if err != nil {
			return nil, err
		}

		expression, err = canonicalSchedulerGuardExpression(target, expression)
		if err != nil {
			return nil, atPath(guardPath+".if", err)
		}

		guard, err := registry.NewSchedulerGuardDefinition(registry.SchedulerGuardDefinitionInput{
			Path: guardPath, Name: name, Expression: expression,
			OnMissingAttribute: guardConfig.OnMissingAttribute,
		})
		if err != nil {
			return nil, atPath(guardPath, err)
		}

		guards = append(guards, guard)
	}

	return guards, nil
}

// canonicalSchedulerGuardExpression maps authored host vocabulary into the selected exact authn schema.
func canonicalSchedulerGuardExpression(
	target decision.Target,
	expression registry.PolicyExpression,
) (registry.PolicyExpression, error) {
	children := expression.Children()
	for index := range children {
		canonical, err := canonicalSchedulerGuardExpression(target, children[index])
		if err != nil {
			return registry.PolicyExpression{}, err
		}

		children[index] = canonical
	}

	factID := expression.FactID()
	if target.Namespace() == policy.AuthnNamespace && factID == policy.AttributeRequestProtocol {
		factID = policy.AuthnFactProtocol
	}

	return registry.NewPolicyExpression(registry.PolicyExpressionInput{
		Kind: expression.Kind(), FactID: factID, FactKind: expression.FactKind(),
		Operator: expression.Operator(), Reference: expression.Reference(),
		Values: expression.Values(), Children: children,
	})
}

// normalizedCheckpointNames returns exact configured topology in deterministic execution order.
func normalizedCheckpointNames(
	target normalizedTarget,
	configured policyconfig.DomainPlanConfig,
) []string {
	checkpointNames := make(map[string]struct{}, len(target.config.Plans)+len(configured.Checkpoints))

	if target.config.DomainPlan == "" {
		for name := range target.config.Plans {
			checkpointNames[name] = struct{}{}
		}
	} else {
		for name := range configured.Checkpoints {
			checkpointNames[name] = struct{}{}
		}
	}

	names := sortedKeys(checkpointNames)
	if target.target.Namespace() != policy.AuthnNamespace {
		return names
	}

	slices.SortStableFunc(names, func(left string, right string) int {
		return authnCheckpointRank(left) - authnCheckpointRank(right)
	})

	return names
}

// authnCheckpointRank preserves established authentication checkpoint order before lexical fallback.
func authnCheckpointRank(checkpoint string) int {
	switch policy.Stage(checkpoint) {
	case policy.StagePreAuth:
		return 0
	case policy.StageAuthBackend:
		return 1
	case policy.StageSubjectAnalysis:
		return 2
	case policy.StageAccountProvider:
		return 3
	case policy.StageAuthDecision:
		return 4
	default:
		return 5
	}
}

// authnFallbackBindings retains immutable standard-auth fallback in configured authn topology.
func authnFallbackBindings(
	target normalizedTarget,
	checkpointPath string,
	checkpoint string,
) ([]registry.PolicySetImport, error) {
	if target.target.Namespace() != policy.AuthnNamespace {
		return nil, nil
	}

	binding, err := registry.NewPolicySetImport(
		checkpointPath+".builtin_standard_auth",
		registry.BuiltinStandardAuthPolicySet,
		target.target,
		checkpoint,
		registry.ExportContract{},
	)
	if err != nil {
		return nil, atPath(checkpointPath, err)
	}

	return []registry.PolicySetImport{binding}, nil
}

// providerInstanceNode retains source position around one checkpoint-local provider instance.
type providerInstanceNode struct {
	configured policyconfig.ProviderInstanceConfig
	index      int
}

// orderedProviderInstances validates dependencies and retains complete action-filtered instance metadata.
func orderedProviderInstances(
	path string,
	namespace string,
	action string,
	configured []policyconfig.ProviderInstanceConfig,
	resolveProvider func(string, string) string,
) ([]registry.ProviderInstanceDefinition, error) {
	nodes, byName, err := indexProviderInstances(path, configured)
	if err != nil {
		return nil, err
	}

	if _, err = topologicallyOrderProviderInstances(path, nodes, byName); err != nil {
		return nil, err
	}

	applicable := make([]providerInstanceNode, 0, len(nodes))
	applicableByName := make(map[string]providerInstanceNode, len(nodes))

	for _, node := range nodes {
		if !providerInstanceAllowsAction(node.configured, action) {
			continue
		}

		applicable = append(applicable, node)
		applicableByName[node.configured.Name] = node
	}

	if err = validateApplicableProviderDependencies(path, action, applicable, applicableByName); err != nil {
		return nil, err
	}

	ordered, err := topologicallyOrderProviderInstances(path, applicable, applicableByName)
	if err != nil {
		return nil, err
	}

	instances := make([]registry.ProviderInstanceDefinition, 0, len(ordered))
	for _, node := range ordered {
		instancePath := fmt.Sprintf("%s[%d]", path, node.index)

		instance, err := normalizeProviderInstance(
			instancePath,
			namespace,
			node.configured,
			resolveProvider(namespace, node.configured.Use),
		)
		if err != nil {
			return nil, err
		}

		instances = append(instances, instance)
	}

	return instances, nil
}

// validateApplicableProviderDependencies enforces scheduler safety after action filtering.
func validateApplicableProviderDependencies(
	path string,
	action string,
	nodes []providerInstanceNode,
	byName map[string]providerInstanceNode,
) error {
	for _, node := range nodes {
		for dependencyIndex, dependency := range node.configured.After {
			dependencyPath := fmt.Sprintf("%s[%d].after[%d]", path, node.index, dependencyIndex)

			dependencyNode, exists := byName[dependency]
			if !exists {
				return atPath(dependencyPath, fmt.Errorf("dependency %s does not apply to action %s", dependency, action))
			}

			if !providerRunIfCovers(dependencyNode.configured.RunIf.AuthState, node.configured.RunIf.AuthState) {
				return atPath(dependencyPath, fmt.Errorf("dependency %s has incompatible run_if.auth_state", dependency))
			}

			if !providerGuardsCover(node.configured.SkipIf, dependencyNode.configured.SkipIf) {
				return atPath(dependencyPath, fmt.Errorf("must include scheduler guards used by dependency %s", dependency))
			}
		}
	}

	return nil
}

// providerRunIfCovers requires dependencies to run in every auth state of the dependent instance.
func providerRunIfCovers(dependency string, dependent string) bool {
	if dependency == "" {
		dependency = policy.RunIfAny
	}

	if dependent == "" {
		dependent = policy.RunIfAny
	}

	return dependency == policy.RunIfAny || dependency == dependent
}

// providerGuardsCover prevents a dependent from running when one of its dependencies was skipped.
func providerGuardsCover(dependent []string, dependency []string) bool {
	for _, guard := range dependency {
		if !slices.Contains(dependent, guard) {
			return false
		}
	}

	return true
}

// normalizeProviderInstance projects one complete provider binding and its effective observe safety.
func normalizeProviderInstance(
	path string,
	namespace string,
	configured policyconfig.ProviderInstanceConfig,
	providerID string,
) (registry.ProviderInstanceDefinition, error) {
	defaultSafe, _, _ := policy.AuthnProviderObserveSafety(providerID)
	observeSafeAuthored := configured.ObserveSafe != nil
	observeSafe := defaultSafe || (observeSafeAuthored && *configured.ObserveSafe)

	runIfAuthState := configured.RunIf.AuthState
	if namespace == policy.AuthnNamespace && runIfAuthState == "" {
		runIfAuthState = policy.RunIfAny
	}

	instance, err := registry.NewProviderInstanceDefinition(registry.ProviderInstanceDefinitionInput{
		Path: path, Name: configured.Name, Use: providerID,
		Actions: configured.Actions, After: configured.After, SkipIf: configured.SkipIf,
		RunIfAuthState: runIfAuthState, Output: configured.Output,
		ObserveSafe: observeSafe, ObserveSafeAuthored: observeSafeAuthored,
	})
	if err != nil {
		return registry.ProviderInstanceDefinition{}, atPath(path, err)
	}

	return instance, nil
}

// indexProviderInstances owns checkpoint-local names and validates exact after references.
func indexProviderInstances(
	path string,
	configured []policyconfig.ProviderInstanceConfig,
) ([]providerInstanceNode, map[string]providerInstanceNode, error) {
	nodes := make([]providerInstanceNode, 0, len(configured))
	byName := make(map[string]providerInstanceNode, len(configured))

	for index, instance := range configured {
		if _, exists := byName[instance.Name]; exists {
			return nil, nil, atPath(fmt.Sprintf("%s[%d].name", path, index), fmt.Errorf("provider instance name %s occurs more than once", instance.Name))
		}

		node := providerInstanceNode{configured: instance, index: index}
		nodes = append(nodes, node)
		byName[instance.Name] = node
	}

	for _, node := range nodes {
		for dependencyIndex, dependency := range node.configured.After {
			if _, exists := byName[dependency]; !exists {
				dependencyPath := fmt.Sprintf("%s[%d].after[%d]", path, node.index, dependencyIndex)

				return nil, nil, atPath(dependencyPath, fmt.Errorf("unknown provider instance %s", dependency))
			}
		}
	}

	return nodes, byName, nil
}

// topologicallyOrderProviderInstances preserves author order while placing dependencies first.
func topologicallyOrderProviderInstances(
	path string,
	nodes []providerInstanceNode,
	byName map[string]providerInstanceNode,
) ([]providerInstanceNode, error) {
	visiting := make(map[string]bool, len(nodes))
	visited := make(map[string]bool, len(nodes))
	ordered := make([]providerInstanceNode, 0, len(nodes))

	var visit func(providerInstanceNode) error

	visit = func(node providerInstanceNode) error {
		name := node.configured.Name
		if visited[name] {
			return nil
		}

		if visiting[name] {
			return atPath(path, fmt.Errorf("contains cyclic after dependencies"))
		}

		visiting[name] = true

		for _, dependency := range node.configured.After {
			if err := visit(byName[dependency]); err != nil {
				return err
			}
		}

		visiting[name] = false
		visited[name] = true

		ordered = append(ordered, node)

		return nil
	}

	for _, node := range nodes {
		if err := visit(node); err != nil {
			return nil, err
		}
	}

	return ordered, nil
}

// providerInstanceAllowsAction applies an omitted action list to every target action.
func providerInstanceAllowsAction(instance policyconfig.ProviderInstanceConfig, action string) bool {
	return len(instance.Actions) == 0 || slices.Contains(instance.Actions, action)
}

// selectedDomainPlanPath returns the canonical source owner for one selected plan.
func selectedDomainPlanPath(target normalizedTarget) string {
	namespace, name, ok := strings.Cut(target.config.DomainPlan, "/")
	if !ok {
		return target.path + ".domain_plan"
	}

	return "policy.namespaces." + namespace + ".domain_plans." + name
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

	if namespace != target.target.Namespace() {
		return policyconfig.DomainPlanConfig{}, atPath(target.path+".domain_plan", fmt.Errorf("must belong to target namespace %s", target.target.Namespace()))
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

	report := registry.NewTargetReportSettings(
		target.config.Report.Enabled,
		target.config.Report.IncludeFSM,
		target.config.Report.IncludeChecks,
		target.config.Report.IncludeAttributes,
	)

	activation, err = activation.WithReport(report)
	if err != nil {
		return registry.TargetActivation{}, atPath(target.path+".report", err)
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
