// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyconfig

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	// ErrValidation identifies a semantic unified policy contract violation.
	ErrValidation = errors.New("invalid standalone policy configuration")

	exactSchemaPattern = regexp.MustCompile(`^([a-z0-9_]+(?:\.[a-z0-9_]+)*)/([a-z0-9]+(?:[-_][a-z0-9]+)*)/v([1-9][0-9]*)$`)
)

const (
	authnNamespace               = "authn"
	providerFailureIndeterminate = "indeterminate"
	providerFailureContinue      = "continue"
	executionReturnOnly          = "return_only"
	executionHostSync            = "host_sync"
	executionHostPostAction      = "host_post_action"
	effectKindAdvice             = "advice"
	keywordAny                   = "any"
	keywordPlugin                = "plugin"
	decisionDeny                 = "deny"
	decisionNotApplicable        = "not_applicable"
)

// Validate enforces path-aware semantic invariants on an isolated document.
func Validate(document Document) error {
	document = Normalize(document)

	if err := validateAPI(document.Policy.API); err != nil {
		return err
	}

	if err := validateNamespaces(document.Policy.Namespaces); err != nil {
		return err
	}

	if err := validateTargets(document.Policy.Targets); err != nil {
		return err
	}

	if err := validateProviderBudgets(document); err != nil {
		return err
	}

	return validateDiagnosticAliases(document)
}

// validateAPI validates global bounds and dedicated client profiles.
func validateAPI(api APIConfig) error {
	if api.GRPC.RequireMTLS && !api.GRPC.Enabled {
		return invalid("policy.api.grpc.require_mtls", "requires the gRPC transport to be enabled")
	}

	if err := validateAPILimits(api.Limits); err != nil {
		return err
	}

	principals := make(map[string]struct{}, len(api.Clients))
	usernames := make(map[string]struct{}, len(api.Clients))

	for index, client := range api.Clients {
		path := fmt.Sprintf("policy.api.clients[%d]", index)
		if err := validateClientProfile(client, api.Limits, path); err != nil {
			return err
		}

		if _, exists := principals[client.Principal]; exists {
			return invalid(path+".principal", "must be unique")
		}

		principals[client.Principal] = struct{}{}
		if client.Authentication.Basic == nil {
			continue
		}

		username := client.Authentication.Basic.Username
		if _, exists := usernames[username]; exists {
			return invalid(path+".authentication.basic.username", "must be unique across Policy-Basic profiles")
		}

		usernames[username] = struct{}{}
	}

	return nil
}

// validateAPILimits rejects negative or incomplete configured server bounds.
func validateAPILimits(limits APILimitsConfig) error {
	integerLimits := []struct {
		path  string
		value int
	}{
		{"max_request_bytes", limits.MaxRequestBytes},
		{"max_facts", limits.MaxFacts},
		{"max_string_bytes", limits.MaxStringBytes},
		{"max_list_items", limits.MaxListItems},
		{"max_value_bytes", limits.MaxValueBytes},
		{"per_client_concurrency", limits.PerClientConcurrency},
		{"per_client_requests_per_second", limits.PerClientRequestsPerSecond},
		{"max_obligations", limits.MaxObligations},
		{"max_advice", limits.MaxAdvice},
		{"max_parameter_bytes", limits.MaxParameterBytes},
	}

	for _, limit := range integerLimits {
		if limit.value < 0 {
			return invalid("policy.api.limits."+limit.path, "must not be negative")
		}
	}

	if limits.ProviderTimeout < 0 {
		return invalid("policy.api.limits.provider_timeout", "must not be negative")
	}

	if limits.EvaluationTimeout < 0 {
		return invalid("policy.api.limits.evaluation_timeout", "must not be negative")
	}

	return nil
}

// validateClientProfile validates one principal-owned admission boundary.
func validateClientProfile(client ClientProfileConfig, limits APILimitsConfig, path string) error {
	if strings.TrimSpace(client.Principal) == "" {
		return invalid(path+".principal", "must be non-empty")
	}

	for index, kind := range client.AuthenticationKinds {
		if kind != "oidc_bearer" && kind != "basic" {
			return invalid(fmt.Sprintf("%s.authentication_kinds[%d]", path, index), "must be oidc_bearer or basic")
		}
	}

	if client.Authentication.Basic != nil {
		if strings.TrimSpace(client.Authentication.Basic.Username) == "" {
			return invalid(path+".authentication.basic.username", "must be non-empty")
		}

		if client.Authentication.Basic.Password.IsZero() {
			return invalid(path+".authentication.basic.password", "must be non-empty")
		}
	}

	if err := validateClientTargets(client.Targets, path+".targets"); err != nil {
		return err
	}

	if err := validateClientLimit(client.MaxRequestBytes, limits.MaxRequestBytes, path+".max_request_bytes"); err != nil {
		return err
	}

	return validateClientLimit(client.MaxFacts, limits.MaxFacts, path+".max_facts")
}

// validateClientTargets validates namespace/action admission references.
func validateClientTargets(targets []ClientTargetConfig, path string) error {
	for index, target := range targets {
		targetPath := fmt.Sprintf("%s[%d]", path, index)
		if !validNamespace(target.Namespace) {
			return invalid(targetPath+".namespace", "must be a canonical namespace")
		}

		if len(target.Actions) == 0 {
			return invalid(targetPath+".actions", "must contain at least one exact action")
		}

		for actionIndex, action := range target.Actions {
			if !validAction(action) {
				return invalid(fmt.Sprintf("%s.actions[%d]", targetPath, actionIndex), "must be a canonical action")
			}
		}
	}

	return nil
}

// validateClientLimit keeps a per-client limit positive and no broader than a configured server limit.
func validateClientLimit(value int, serverValue int, path string) error {
	if value < 0 {
		return invalid(path, "must not be negative")
	}

	if serverValue > 0 && value > serverValue {
		return invalid(path, "must not exceed the server limit")
	}

	return nil
}

// validateNamespaces validates namespace-owned definitions in stable path order.
func validateNamespaces(namespaces map[string]NamespaceConfig) error {
	for _, namespaceName := range sortedNamespaceNames(namespaces) {
		path := "policy.namespaces." + namespaceName
		if !validNamespace(namespaceName) {
			return invalid(path, "must be a canonical namespace")
		}

		if err := validateNamespace(namespaceName, namespaces[namespaceName], path); err != nil {
			return err
		}
	}

	return nil
}

// validateNamespace delegates every namespace-owned definition family.
func validateNamespace(namespaceName string, namespace NamespaceConfig, path string) error {
	validators := []func() error{
		func() error { return validateLocalization(namespace.Localization, path+".localization") },
		func() error { return validateConditionSets(namespace.ConditionSets, path+".condition_sets") },
		func() error {
			return validateSchemaContributions(namespace.SchemaContributions, path+".schema_contributions")
		},
		func() error {
			return validateStaticSchemas(namespaceName, namespace.SchemaContributions.Static, path+".schema_contributions.static")
		},
		func() error { return validateFactSources(namespace.FactSources, path+".fact_sources") },
		func() error { return validateProviders(namespaceName, namespace.Providers, path+".providers") },
		func() error { return validateEffects(namespace.Effects, path+".effects") },
		func() error { return validateDomainPlans(namespaceName, namespace.DomainPlans, path+".domain_plans") },
		func() error { return validatePolicySets(namespaceName, namespace.PolicySets, path+".policy_sets") },
	}

	for _, validator := range validators {
		if err := validator(); err != nil {
			return err
		}
	}

	return nil
}

// validateLocalization checks required catalog identity and entries.
func validateLocalization(localization LocalizationConfig, path string) error {
	for index, catalog := range localization.Catalogs {
		catalogPath := fmt.Sprintf("%s.catalogs[%d]", path, index)
		if strings.TrimSpace(catalog.Namespace) == "" {
			return invalid(catalogPath+".namespace", "must be non-empty")
		}

		if strings.TrimSpace(catalog.Language) == "" {
			return invalid(catalogPath+".language", "must be non-empty")
		}

		if catalog.Entries == nil {
			return invalid(catalogPath+".entries", "must be present")
		}
	}

	return nil
}

// validateConditionSets checks named time-window structure and bounds.
func validateConditionSets(sets ConditionSetsConfig, path string) error {
	for _, name := range sortedTimeWindowNames(sets.TimeWindows) {
		window := sets.TimeWindows[name]

		windowPath := path + ".time_windows." + name
		if !validAction(name) {
			return invalid(windowPath, "must use a canonical local name")
		}

		for index, interval := range window.Intervals {
			intervalPath := fmt.Sprintf("%s.intervals[%d]", windowPath, index)
			if strings.TrimSpace(interval.Start) == "" {
				return invalid(intervalPath+".start", "must be non-empty")
			}

			if strings.TrimSpace(interval.End) == "" {
				return invalid(intervalPath+".end", "must be non-empty")
			}
		}
	}

	return nil
}

// validateSchemaContributions rejects empty registry-script identities.
func validateSchemaContributions(contributions SchemaContributionsConfig, path string) error {
	for index, script := range contributions.Lua.RegistryScripts {
		if strings.TrimSpace(script) == "" {
			return invalid(fmt.Sprintf("%s.lua.registry_scripts[%d]", path, index), "must be non-empty")
		}
	}

	return nil
}

// validateFactSources validates bounded source-to-fact projections.
func validateFactSources(sources FactSourcesConfig, path string) error {
	for index, source := range sources.HTTPHeaders {
		sourcePath := fmt.Sprintf("%s.http_headers[%d]", path, index)
		if strings.TrimSpace(source.Header) == "" {
			return invalid(sourcePath+".header", "must be non-empty")
		}

		if !validFact(source.Attribute) {
			return invalid(sourcePath+".attribute", "must be a canonical fact identity")
		}
	}

	for index, source := range sources.GRPCMetadata {
		sourcePath := fmt.Sprintf("%s.grpc_metadata[%d]", path, index)
		if strings.TrimSpace(source.Key) == "" {
			return invalid(sourcePath+".key", "must be non-empty")
		}

		if !validFact(source.Attribute) {
			return invalid(sourcePath+".attribute", "must be a canonical fact identity")
		}
	}

	return validateBackendFactSources(sources.BackendAttributes, path+".backend_attributes")
}

// validateBackendFactSources validates backend attribute export contracts.
func validateBackendFactSources(sources []BackendAttributeFactSourceConfig, path string) error {
	for index, source := range sources {
		sourcePath := fmt.Sprintf("%s[%d]", path, index)
		if strings.TrimSpace(source.Name) == "" {
			return invalid(sourcePath+".name", "must be non-empty")
		}

		if !validFact(source.Attribute) {
			return invalid(sourcePath+".attribute", "must be a canonical fact identity")
		}

		if !validValueKind(source.Type) {
			return invalid(sourcePath+".type", "must be an exact value kind")
		}

		if source.Sensitivity != "" && source.Sensitivity != "public" && source.Sensitivity != "internal" && source.Sensitivity != "secret" {
			return invalid(sourcePath+".sensitivity", "must be public, internal, or secret")
		}
	}

	return nil
}

// validateProviders validates configured provider ownership and failure semantics.
func validateProviders(namespace string, providers map[string]ProviderConfig, path string) error {
	for _, name := range sortedProviderNames(providers) {
		provider := providers[name]

		providerPath := path + "." + name
		if !validAction(name) {
			return invalid(providerPath, "must use a canonical local name")
		}

		if !validProviderKind(provider.Kind) {
			return invalid(providerPath+".kind", "must be lua_environment, lua_subject, native, or plugin")
		}

		if err := validateProviderSchedule(namespace, provider, providerPath); err != nil {
			return err
		}

		if err := validateTargetReferences(provider.Targets, providerPath+".targets"); err != nil {
			return err
		}

		if err := validateExecutions(provider.Executions, providerPath+".executions"); err != nil {
			return err
		}

		if err := validateDiagnosticID(provider.Diagnostics.PublicID, providerPath+".diagnostics.public_id"); err != nil {
			return err
		}
	}

	return nil
}

// validateProviderSchedule requires explicit generic failure and bounded timeout behavior.
func validateProviderSchedule(namespace string, provider ProviderConfig, path string) error {
	if namespace != authnNamespace && provider.Failure == "" {
		return invalid(path+".failure", "generic providers require indeterminate or continue")
	}

	if provider.Failure != "" && provider.Failure != providerFailureIndeterminate && provider.Failure != providerFailureContinue {
		return invalid(path+".failure", "must be indeterminate or continue")
	}

	if provider.Timeout < 0 {
		return invalid(path+".timeout", "must not be negative")
	}

	return nil
}

// validateTargetReferences validates namespace-local action allowlists.
func validateTargetReferences(targets []TargetReferenceConfig, path string) error {
	for index, target := range targets {
		if !validAction(target.Action) {
			return invalid(fmt.Sprintf("%s[%d].action", path, index), "must be a canonical action")
		}
	}

	return nil
}

// validateExecutions checks provider host execution allowlists.
func validateExecutions(executions []string, path string) error {
	for index, execution := range executions {
		if execution != executionHostSync && execution != executionHostPostAction {
			return invalid(fmt.Sprintf("%s[%d]", path, index), "must be host_sync or host_post_action")
		}
	}

	return nil
}

// validateEffects validates execution ownership, providers, parameters, and diagnostics.
func validateEffects(effects map[string]EffectConfig, path string) error {
	for _, name := range sortedEffectNames(effects) {
		effect := effects[name]

		effectPath := path + "." + name
		if !validAction(name) {
			return invalid(effectPath, "must use a canonical local name")
		}

		if err := validateEffect(effect, effectPath); err != nil {
			return err
		}
	}

	return nil
}

// validateEffect enforces exactly one effect execution owner.
func validateEffect(effect EffectConfig, path string) error {
	if effect.Kind != defaultEffectKind && effect.Kind != effectKindAdvice && effect.Kind != "lua_action" {
		return invalid(path+".kind", "must be obligation, advice, or lua_action")
	}

	if err := validateEffectOwnership(effect, path); err != nil {
		return err
	}

	if err := validateLuaActionExecution(effect, path); err != nil {
		return err
	}

	if err := validateTargetReferences(effect.Targets, path+".targets"); err != nil {
		return err
	}

	if err := validateEffectParameters(effect.Parameters, path+".parameters"); err != nil {
		return err
	}

	return validateDiagnosticID(effect.Diagnostics.PublicID, path+".diagnostics.public_id")
}

// validateEffectOwnership enforces one closed execution class and compatible provider binding.
func validateEffectOwnership(effect EffectConfig, path string) error {
	if effect.Execution != executionReturnOnly && effect.Execution != executionHostSync && effect.Execution != executionHostPostAction {
		return invalid(path+".execution", "must be return_only, host_sync, or host_post_action")
	}

	if effect.Execution == executionReturnOnly && effect.Provider != "" {
		return invalid(path+".provider", "return_only effects cannot bind a provider")
	}

	if effect.Execution != executionReturnOnly && !validQualified(effect.Provider) {
		return invalid(path+".provider", "host effects require one exact qualified provider")
	}

	if effect.Kind == effectKindAdvice && effect.Execution != executionReturnOnly {
		return invalid(path+".execution", "advice must be return_only")
	}

	return nil
}

// validateLuaActionExecution preserves the exact action-type host ownership mapping.
func validateLuaActionExecution(effect EffectConfig, path string) error {
	if effect.ActionType == "" {
		return nil
	}

	want := executionHostSync
	if effect.ActionType == "post" {
		want = executionHostPostAction
	}

	if effect.Execution != want {
		return invalid(path+".execution", "does not match action_type host ownership")
	}

	return nil
}

// validateEffectParameters validates typed parameter declarations.
func validateEffectParameters(parameters map[string]EffectParameterConfig, path string) error {
	for _, name := range sortedEffectParameterNames(parameters) {
		parameter := parameters[name]

		parameterPath := path + "." + name
		if !validAction(name) {
			return invalid(parameterPath, "must use a canonical parameter name")
		}

		if !validValueKind(parameter.Type) {
			return invalid(parameterPath+".type", "must be an exact value kind")
		}

		if parameter.MaxLength < 0 || parameter.MaxItems < 0 || parameter.MaxBytes < 0 {
			return invalid(parameterPath, "bounds must not be negative")
		}
	}

	return nil
}

// validateDomainPlans validates checkpoint ownership and provider instances.
func validateDomainPlans(namespace string, plans map[string]DomainPlanConfig, path string) error {
	for _, name := range sortedDomainPlanNames(plans) {
		plan := plans[name]

		planPath := path + "." + name
		if !validAction(name) {
			return invalid(planPath, "must use a canonical local name")
		}

		if err := validateSchedulerGuards(plan.SchedulerGuards, planPath+".scheduler_guards"); err != nil {
			return err
		}

		if err := validateCheckpoints(namespace, plan.Checkpoints, planPath+".checkpoints"); err != nil {
			return err
		}
	}

	return nil
}

// validateSchedulerGuards validates exact missing-fact behavior.
func validateSchedulerGuards(guards map[string]SchedulerGuardConfig, path string) error {
	for _, name := range sortedSchedulerGuardNames(guards) {
		guard := guards[name]

		guardPath := path + "." + name
		if !validAction(name) {
			return invalid(guardPath, "must use a canonical local name")
		}

		if guard.OnMissingAttribute != "" && guard.OnMissingAttribute != "skip" && guard.OnMissingAttribute != "run" {
			return invalid(guardPath+".on_missing_attribute", "must be skip or run")
		}
	}

	return nil
}

// validateCheckpoints validates provider instance names, references, and auth-only guards.
func validateCheckpoints(namespace string, checkpoints map[string]CheckpointConfig, path string) error {
	for _, name := range sortedCheckpointNames(checkpoints) {
		checkpoint := checkpoints[name]

		checkpointPath := path + "." + name
		if !validAction(name) {
			return invalid(checkpointPath, "must use a canonical checkpoint name")
		}

		for index, provider := range checkpoint.Providers {
			providerPath := fmt.Sprintf("%s.providers[%d]", checkpointPath, index)
			if err := validateProviderInstance(namespace, provider, providerPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// validateProviderInstance validates one checkpoint-local provider binding.
func validateProviderInstance(namespace string, provider ProviderInstanceConfig, path string) error {
	if !validAction(provider.Name) {
		return invalid(path+".name", "must be a canonical instance name")
	}

	if !validQualified(provider.Use) {
		return invalid(path+".use", "must be an exact qualified provider identity")
	}

	if provider.RunIf.AuthState != "" {
		if namespace != authnNamespace {
			return invalid(path+".run_if.auth_state", "is restricted to authn domain plans")
		}

		if provider.RunIf.AuthState != "authenticated" && provider.RunIf.AuthState != "unauthenticated" && provider.RunIf.AuthState != keywordAny {
			return invalid(path+".run_if.auth_state", "must be authenticated, unauthenticated, or any")
		}
	}

	for index, action := range provider.Actions {
		if !validAction(action) {
			return invalid(fmt.Sprintf("%s.actions[%d]", path, index), "must be a canonical action")
		}
	}

	return nil
}

// validatePolicySets validates visibility, exports, rules, and diagnostics.
func validatePolicySets(namespace string, policySets map[string]PolicySetConfig, path string) error {
	for _, name := range sortedPolicySetNames(policySets) {
		policySet := policySets[name]

		setPath := path + "." + name
		if !validAction(name) {
			return invalid(setPath, "must use a canonical local name")
		}

		if namespace == authnNamespace && name == "standard_auth" {
			return invalid(setPath, "authn/standard_auth is supplied only by the builtin contribution")
		}

		if err := validatePolicySet(policySet, setPath); err != nil {
			return err
		}
	}

	return nil
}

// validatePolicySet enforces private/exported ownership and validates ordered rules.
func validatePolicySet(policySet PolicySetConfig, path string) error {
	if policySet.Visibility != VisibilityPrivate && policySet.Visibility != VisibilityExported {
		return invalid(path+".visibility", "must be private or exported")
	}

	if policySet.Visibility == VisibilityPrivate && policySet.ExportContract != nil {
		return invalid(path+".export_contract", "private policy sets cannot declare an export contract")
	}

	if policySet.Visibility == VisibilityExported {
		if policySet.ExportContract == nil {
			return invalid(path+".export_contract", "exported policy sets require a complete contract")
		}

		if err := validateExportContract(*policySet.ExportContract, path+".export_contract"); err != nil {
			return err
		}
	}

	if err := validateDiagnosticID(policySet.Diagnostics.PublicID, path+".diagnostics.public_id"); err != nil {
		return err
	}

	for index, rule := range policySet.Rules {
		if err := validatePolicyRule(rule, fmt.Sprintf("%s.rules[%d]", path, index)); err != nil {
			return err
		}
	}

	return nil
}

// validateExportContract requires every explicit capability field.
func validateExportContract(contract ExportContractConfig, path string) error {
	if contract.RequiredFacts == nil {
		return invalid(path+".required_facts", "must be present, including when empty")
	}

	if len(contract.CompatibleCheckpoints) == 0 {
		return invalid(path+".compatible_checkpoints", "must contain at least one checkpoint")
	}

	if len(contract.AllowedDecisions) == 0 {
		return invalid(path+".allowed_decisions", "must contain at least one decision")
	}

	if contract.AllowedEffects == nil {
		return invalid(path+".allowed_effects", "must be present, including when empty")
	}

	for index, fact := range contract.RequiredFacts {
		factPath := fmt.Sprintf("%s.required_facts[%d]", path, index)
		if !validFact(fact.Attribute) {
			return invalid(factPath+".attribute", "must be a canonical fact identity")
		}

		if !validValueKind(fact.Type) {
			return invalid(factPath+".type", "must be an exact value kind")
		}
	}

	return nil
}

// validatePolicyRule validates exact checkpoint selection and qualified effects.
func validatePolicyRule(rule PolicyRuleConfig, path string) error {
	if !validAction(rule.Name) {
		return invalid(path+".name", "must be a canonical rule name")
	}

	if !validAction(rule.Checkpoint) {
		return invalid(path+".checkpoint", "must be a canonical checkpoint selector")
	}

	for index, action := range rule.Actions {
		if !validAction(action) {
			return invalid(fmt.Sprintf("%s.actions[%d]", path, index), "must be a canonical action")
		}
	}

	if err := validateCondition(rule.If, path+".if"); err != nil {
		return err
	}

	return validateThen(rule.Then, path+".then")
}

// validateCondition requires one unambiguous logical or attribute expression.
func validateCondition(condition ConditionConfig, path string) error {
	logicalForms := presentLogicalForms(condition)
	operators := presentAttributeOperators(condition)

	if len(logicalForms) > 0 {
		return validateLogicalCondition(condition, path, logicalForms, operators)
	}

	return validateAttributeCondition(condition, path, operators)
}

// validateLogicalCondition rejects mixed forms and validates the selected logical children.
func validateLogicalCondition(
	condition ConditionConfig,
	path string,
	forms []string,
	operators []string,
) error {
	if len(forms) > 1 {
		return invalid(path+"."+forms[1], "condition must declare exactly one logical form")
	}

	if condition.Attribute != "" {
		return invalid(path+".attribute", "cannot be combined with a logical condition")
	}

	if condition.Detail != "" {
		return invalid(path+".detail", "cannot be combined with a logical condition")
	}

	if len(operators) > 0 {
		return invalid(path+"."+operators[0], "cannot be combined with a logical condition")
	}

	switch forms[0] {
	case "always":
		if condition.Always == nil || !*condition.Always {
			return invalid(path+".always", "must be true")
		}

		return nil
	case "not":
		return validateCondition(*condition.Not, path+".not")
	case "all":
		return validateConditionChildren(condition.All, path+".all")
	case keywordAny:
		return validateConditionChildren(condition.Any, path+".any")
	default:
		return invalid(path, "condition requires exactly one expression")
	}
}

// validateAttributeCondition requires one fact identity and exactly one operator.
func validateAttributeCondition(condition ConditionConfig, path string, operators []string) error {
	if condition.Attribute == "" {
		if len(operators) == 0 && condition.Detail == "" {
			return invalid(path, "condition requires exactly one expression")
		}

		return invalid(path+".attribute", "attribute operators require a canonical fact identity")
	}

	if !validFact(condition.Attribute) {
		return invalid(path+".attribute", "must be a canonical fact identity")
	}

	if len(operators) == 0 {
		return invalid(path, "attribute condition requires exactly one operator")
	}

	if len(operators) > 1 {
		return invalid(path+"."+operators[1], "attribute condition must declare exactly one operator")
	}

	return nil
}

// validateConditionChildren requires a non-empty logical child list and validates every child.
func validateConditionChildren(children []ConditionConfig, path string) error {
	if len(children) == 0 {
		return invalid(path, "logical conditions require at least one child")
	}

	for index, child := range children {
		if err := validateCondition(child, fmt.Sprintf("%s[%d]", path, index)); err != nil {
			return err
		}
	}

	return nil
}

// presentLogicalForms returns configured logical fields in canonical model order.
func presentLogicalForms(condition ConditionConfig) []string {
	forms := make([]string, 0, 4)
	if condition.Not != nil {
		forms = append(forms, "not")
	}

	if condition.Always != nil {
		forms = append(forms, "always")
	}

	if condition.All != nil {
		forms = append(forms, "all")
	}

	if condition.Any != nil {
		forms = append(forms, keywordAny)
	}

	return forms
}

// presentAttributeOperators returns configured attribute operators in canonical model order.
func presentAttributeOperators(condition ConditionConfig) []string {
	operators := make([]string, 0, 17)
	appendConditionOperator(&operators, "matches", condition.Matches != "")
	appendConditionOperator(&operators, "cidr_contains", condition.CIDRContains != "")
	appendConditionOperator(&operators, "within_time_window", condition.WithinTimeWindow != "")
	appendConditionOperator(&operators, "is", condition.Is != nil)
	appendConditionOperator(&operators, "eq", condition.Eq != nil)
	appendConditionOperator(&operators, "ne", condition.Ne != nil)
	appendConditionOperator(&operators, "in", condition.In != nil)
	appendConditionOperator(&operators, "not_in", condition.NotIn != nil)
	appendConditionOperator(&operators, "exists", condition.Exists != nil)
	appendConditionOperator(&operators, "contains", condition.Contains != nil)
	appendConditionOperator(&operators, "contains_any", condition.ContainsAny != nil)
	appendConditionOperator(&operators, "contains_all", condition.ContainsAll != nil)
	appendConditionOperator(&operators, "contains_none", condition.ContainsNone != nil)
	appendConditionOperator(&operators, "gt", condition.GT != nil)
	appendConditionOperator(&operators, "gte", condition.GTE != nil)
	appendConditionOperator(&operators, "lt", condition.LT != nil)
	appendConditionOperator(&operators, "lte", condition.LTE != nil)

	return operators
}

// appendConditionOperator records one present operator without duplicating selection logic.
func appendConditionOperator(operators *[]string, name string, present bool) {
	if present {
		*operators = append(*operators, name)
	}
}

// validateThen checks closed decisions and exact effect references.
func validateThen(then ThenConfig, path string) error {
	if then.Decision != "" && then.Decision != "permit" && then.Decision != decisionDeny && then.Decision != providerFailureIndeterminate && then.Decision != decisionNotApplicable {
		return invalid(path+".decision", "must be a registered decision")
	}

	if err := validateEffectSelections(then.Obligations, path+".obligations"); err != nil {
		return err
	}

	return validateEffectSelections(then.Advice, path+".advice")
}

// validateEffectSelections checks exact qualified selected effect identities.
func validateEffectSelections(selections []EffectSelectionConfig, path string) error {
	for index, selection := range selections {
		if !validQualified(selection.ID) {
			return invalid(fmt.Sprintf("%s[%d].id", path, index), "must be an exact qualified effect identity")
		}
	}

	return nil
}

// validateTargets validates every explicit activation in source order.
func validateTargets(targets []TargetConfig) error {
	seen := make(map[string]struct{}, len(targets))

	for index, target := range targets {
		path := fmt.Sprintf("policy.targets[%d]", index)
		if err := validateTarget(target, path); err != nil {
			return err
		}

		identity := target.Namespace + "/" + target.Action
		if _, exists := seen[identity]; exists {
			return invalid(path+".action", "target activation must be unique")
		}

		seen[identity] = struct{}{}
	}

	return nil
}

// validateTarget enforces exact schema, activation, fallback, and timeout semantics.
func validateTarget(target TargetConfig, path string) error {
	if !validNamespace(target.Namespace) {
		return invalid(path+".namespace", "must be a canonical namespace")
	}

	if !validAction(target.Action) {
		return invalid(path+".action", "must be a canonical action")
	}

	if err := validateTargetSchema(target, path+".schema"); err != nil {
		return err
	}

	if err := validateTargetMode(target, path+".mode"); err != nil {
		return err
	}

	if target.DefaultPolicy != "" && !validQualified(target.DefaultPolicy) {
		return invalid(path+".default_policy", "must be an exact qualified policy-set identity")
	}

	if target.DomainPlan != "" && !validQualified(target.DomainPlan) {
		return invalid(path+".domain_plan", "must be an exact qualified domain-plan identity")
	}

	if err := validateTargetFallback(target, path); err != nil {
		return err
	}

	if err := validateTargetPlans(target.Plans, path+".plans"); err != nil {
		return err
	}

	return validateTargetReport(target, path+".report")
}

// validateTargetMode keeps observe authority restricted to authn targets.
func validateTargetMode(target TargetConfig, path string) error {
	if target.Mode != defaultAuthorityMode && target.Mode != "observe" {
		return invalid(path, "must be enforce or observe")
	}

	if target.Namespace != authnNamespace && target.Mode != defaultAuthorityMode {
		return invalid(path, "generic targets support enforce mode only")
	}

	return nil
}

// validateTargetSchema requires one exact version matching the activated target.
func validateTargetSchema(target TargetConfig, path string) error {
	matches := exactSchemaPattern.FindStringSubmatch(target.Schema)
	if len(matches) != 4 {
		return invalid(path, "must be an exact namespace/action/vN schema reference")
	}

	if matches[1] != target.Namespace || matches[2] != target.Action {
		return invalid(path, "must match the activated namespace and action")
	}

	if _, err := strconv.ParseUint(matches[3], 10, 32); err != nil {
		return invalid(path, "schema version is out of range")
	}

	return nil
}

// validateTargetFallback separates authn-owned and generic fallback contracts.
func validateTargetFallback(target TargetConfig, path string) error {
	if target.Namespace == authnNamespace {
		if target.NoMatch != "" {
			return invalid(path+".no_match", "authn targets forbid generic no-match configuration")
		}

		if target.Timeouts.Evaluation != 0 {
			return invalid(path+".timeouts.evaluation", "authn preserves its host-owned timeout")
		}

		if target.Timeouts.ProviderDefault != 0 {
			return invalid(path+".timeouts.provider_default", "authn preserves its host-owned timeout")
		}

		if target.DefaultPolicy != standardAuthPolicy {
			return invalid(path+".default_policy", "authn builtin fallback is exactly authn/standard_auth")
		}

		return nil
	}

	if target.NoMatch != decisionNotApplicable && target.NoMatch != decisionDeny {
		return invalid(path+".no_match", "generic targets require not_applicable or deny")
	}

	if target.Timeouts.Evaluation <= 0 {
		return invalid(path+".timeouts.evaluation", "generic targets require a positive evaluation timeout")
	}

	if target.Timeouts.ProviderDefault <= 0 {
		return invalid(path+".timeouts.provider_default", "generic targets require a positive provider timeout")
	}

	if target.Timeouts.ProviderDefault > target.Timeouts.Evaluation {
		return invalid(path+".timeouts.provider_default", "must not exceed the target evaluation timeout")
	}

	return nil
}

// validateTargetPlans checks exact checkpoint and qualified set references.
func validateTargetPlans(plans map[string]TargetPlanConfig, path string) error {
	for _, checkpoint := range sortedTargetPlanNames(plans) {
		plan := plans[checkpoint]

		checkpointPath := path + "." + checkpoint
		if !validAction(checkpoint) {
			return invalid(checkpointPath, "must use a canonical checkpoint name")
		}

		for index, policySet := range plan.PolicySets {
			if !validQualified(policySet) {
				return invalid(fmt.Sprintf("%s.policy_sets[%d]", checkpointPath, index), "must be an exact qualified policy-set identity")
			}
		}
	}

	return nil
}

// validateTargetReport restricts authn-specific detail toggles to authn targets.
func validateTargetReport(target TargetConfig, path string) error {
	if target.Namespace == authnNamespace {
		return nil
	}

	if target.Report.IncludeFSM {
		return invalid(path+".include_fsm", "is restricted to authn targets")
	}

	if target.Report.IncludeChecks {
		return invalid(path+".include_checks", "is restricted to authn targets")
	}

	if target.Report.IncludeAttributes {
		return invalid(path+".include_attributes", "is restricted to authn targets")
	}

	return nil
}

// validateProviderBudgets keeps explicit provider timeouts inside every matching target budget.
func validateProviderBudgets(document Document) error {
	for _, namespaceName := range sortedNamespaceNames(document.Policy.Namespaces) {
		namespace := document.Policy.Namespaces[namespaceName]

		for _, providerName := range sortedProviderNames(namespace.Providers) {
			provider := namespace.Providers[providerName]
			if provider.Timeout <= 0 {
				continue
			}

			for _, target := range document.Policy.Targets {
				if target.Namespace != namespaceName || !targetReferencesAction(provider.Targets, target.Action) {
					continue
				}

				if target.Timeouts.ProviderDefault > 0 && provider.Timeout > target.Timeouts.ProviderDefault {
					return invalid(
						"policy.namespaces."+namespaceName+".providers."+providerName+".timeout",
						"must not exceed the matching target provider-default timeout",
					)
				}

				if target.Timeouts.Evaluation > 0 && provider.Timeout > target.Timeouts.Evaluation {
					return invalid(
						"policy.namespaces."+namespaceName+".providers."+providerName+".timeout",
						"must not exceed the matching target evaluation timeout",
					)
				}
			}
		}
	}

	return nil
}

// validateDiagnosticID enforces one bounded lowercase alias without path syntax.
func validateDiagnosticID(value string, path string) error {
	if value == "" {
		return nil
	}

	if !validAction(value) {
		return invalid(path, "must be one bounded lowercase target-local alias without a path")
	}

	return nil
}

// validateDiagnosticAliases rejects aliases that collide in one activated target projection.
func validateDiagnosticAliases(document Document) error {
	for targetIndex, target := range document.Policy.Targets {
		aliases := make(map[string]string)
		if err := collectTargetDefinitionAliases(document, target, aliases); err != nil {
			return err
		}

		if err := collectTargetPolicySetAliases(document, targetIndex, target, aliases); err != nil {
			return err
		}
	}

	return nil
}

// collectTargetDefinitionAliases indexes provider and effect aliases available to one target.
func collectTargetDefinitionAliases(document Document, target TargetConfig, aliases map[string]string) error {
	namespace, exists := document.Policy.Namespaces[target.Namespace]
	if !exists {
		return nil
	}

	base := "policy.namespaces." + target.Namespace

	for _, name := range sortedProviderNames(namespace.Providers) {
		provider := namespace.Providers[name]
		if targetReferencesAction(provider.Targets, target.Action) {
			path := base + ".providers." + name + ".diagnostics.public_id"
			if err := addDiagnosticAlias(aliases, provider.Diagnostics.PublicID, path); err != nil {
				return err
			}
		}
	}

	for _, name := range sortedEffectNames(namespace.Effects) {
		effect := namespace.Effects[name]
		if targetReferencesAction(effect.Targets, target.Action) {
			path := base + ".effects." + name + ".diagnostics.public_id"
			if err := addDiagnosticAlias(aliases, effect.Diagnostics.PublicID, path); err != nil {
				return err
			}
		}
	}

	return nil
}

// collectTargetPolicySetAliases indexes the exact policy sets bound into one target plan.
func collectTargetPolicySetAliases(document Document, targetIndex int, target TargetConfig, aliases map[string]string) error {
	references := make([]string, 0)
	if target.DefaultPolicy != "" {
		references = append(references, target.DefaultPolicy)
	}

	for _, checkpoint := range sortedTargetPlanNames(target.Plans) {
		references = append(references, target.Plans[checkpoint].PolicySets...)
	}

	for _, reference := range references {
		parts := strings.SplitN(reference, "/", 2)
		if len(parts) != 2 {
			continue
		}

		namespace, exists := document.Policy.Namespaces[parts[0]]
		if !exists {
			continue
		}

		policySet, exists := namespace.PolicySets[parts[1]]
		if !exists {
			continue
		}

		path := "policy.namespaces." + parts[0] + ".policy_sets." + parts[1] + ".diagnostics.public_id"
		if err := addDiagnosticAlias(aliases, policySet.Diagnostics.PublicID, path); err != nil {
			return newPathError(path, ErrValidation, fmt.Sprintf("duplicates a diagnostic alias in policy.targets[%d]", targetIndex))
		}
	}

	return nil
}

// targetReferencesAction reports whether an empty or explicit allowlist includes the target action.
func targetReferencesAction(targets []TargetReferenceConfig, action string) bool {
	if len(targets) == 0 {
		return true
	}

	for _, target := range targets {
		if target.Action == action {
			return true
		}
	}

	return false
}

// addDiagnosticAlias adds one alias and returns the colliding path on duplication.
func addDiagnosticAlias(aliases map[string]string, alias string, path string) error {
	if alias == "" {
		return nil
	}

	if existingPath, exists := aliases[alias]; exists {
		if existingPath == path {
			return nil
		}

		return invalid(path, "duplicates another public alias in this target")
	}

	aliases[alias] = path

	return nil
}

// invalid creates one semantic path error.
func invalid(path string, message string) *PathError {
	return newPathError(path, ErrValidation, message)
}

// validNamespace reports whether value uses bounded lowercase dotted segments.
func validNamespace(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}

	for _, segment := range strings.Split(value, ".") {
		if !validIdentifierSegment(segment, false) {
			return false
		}
	}

	return true
}

// validAction reports whether value uses bounded lowercase words and separators.
func validAction(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}

	separator := false

	for index := range len(value) {
		current := value[index]
		switch {
		case lowerWordByte(current):
			separator = false
		case current == '-' || current == '_':
			if index == 0 || index == len(value)-1 || separator {
				return false
			}

			separator = true
		default:
			return false
		}
	}

	return true
}

// validIdentifierSegment validates one lowercase namespace or fact segment.
func validIdentifierSegment(value string, allowHyphen bool) bool {
	if value == "" {
		return false
	}

	for index := range len(value) {
		current := value[index]
		if lowerWordByte(current) || current == '_' || allowHyphen && current == '-' {
			continue
		}

		return false
	}

	return true
}

// lowerWordByte reports whether value is one lowercase ASCII word byte.
func lowerWordByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

// validFact reports whether value is one bounded dotted fact identity.
func validFact(value string) bool {
	if len(value) == 0 || len(value) > 192 {
		return false
	}

	segments := strings.Split(value, ".")
	if len(segments) < 2 {
		return false
	}

	for _, segment := range segments {
		if !validIdentifierSegment(segment, true) {
			return false
		}
	}

	return true
}

// validQualified reports whether value is one exact namespace/local identity.
func validQualified(value string) bool {
	if len(value) == 0 || len(value) > 128 || strings.Count(value, "/") != 1 {
		return false
	}

	parts := strings.SplitN(value, "/", 2)

	return validNamespace(parts[0]) && validAction(parts[1])
}

// validValueKind reports whether value belongs to the compiler's closed kind set.
func validValueKind(value string) bool {
	switch value {
	case "string", "boolean", "integer", "double", "strings", "bytes", "timestamp":
		return true
	default:
		return false
	}
}

// validProviderKind reports whether one configured provider uses a registered binding family.
func validProviderKind(value string) bool {
	switch value {
	case "lua_environment", "lua_subject", "native", keywordPlugin:
		return true
	default:
		return false
	}
}

// sortedNamespaceNames returns deterministic namespace keys.
func sortedNamespaceNames(values map[string]NamespaceConfig) []string {
	return sortedMapKeys(values)
}

// sortedTimeWindowNames returns deterministic time-window keys.
func sortedTimeWindowNames(values map[string]TimeWindowConfig) []string {
	return sortedMapKeys(values)
}

// sortedProviderNames returns deterministic provider keys.
func sortedProviderNames(values map[string]ProviderConfig) []string {
	return sortedMapKeys(values)
}

// sortedEffectNames returns deterministic effect keys.
func sortedEffectNames(values map[string]EffectConfig) []string {
	return sortedMapKeys(values)
}

// sortedEffectParameterNames returns deterministic parameter keys.
func sortedEffectParameterNames(values map[string]EffectParameterConfig) []string {
	return sortedMapKeys(values)
}

// sortedDomainPlanNames returns deterministic domain-plan keys.
func sortedDomainPlanNames(values map[string]DomainPlanConfig) []string {
	return sortedMapKeys(values)
}

// sortedSchedulerGuardNames returns deterministic scheduler-guard keys.
func sortedSchedulerGuardNames(values map[string]SchedulerGuardConfig) []string {
	return sortedMapKeys(values)
}

// sortedCheckpointNames returns deterministic checkpoint keys.
func sortedCheckpointNames(values map[string]CheckpointConfig) []string {
	return sortedMapKeys(values)
}

// sortedPolicySetNames returns deterministic policy-set keys.
func sortedPolicySetNames(values map[string]PolicySetConfig) []string {
	return sortedMapKeys(values)
}

// sortedTargetPlanNames returns deterministic target plan keys.
func sortedTargetPlanNames(values map[string]TargetPlanConfig) []string {
	return sortedMapKeys(values)
}

// sortedMapKeys returns deterministic string keys for any configured definition map.
func sortedMapKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}
