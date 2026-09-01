// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package registry

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

const (
	builtinStandardOutcomeDefaultDeny = "auth.outcome.default_deny"
	builtinStandardOutcomePreAuthOK   = "auth.outcome.pre_auth_ok"
	builtinStatusMessageDetail        = "status_message"
	builtinGeneratedFamilyLua         = "lua"
	builtinGeneratedFamilyPlugin      = "plugin"
	builtinGeneratedKindEnvironment   = "environment"
	builtinGeneratedKindSubject       = "subject"
)

type builtinAuthRuleInput struct {
	expression        PolicyExpression
	responseMessage   PolicyResponseMessage
	effects           []EffectUse
	actions           []string
	name              string
	checkpoint        string
	presentationStage string
	outcomeMarker     string
	fsmMarker         string
	responseMarker    string
	decision          decision.Effect
	skipRemaining     bool
}

type builtinGeneratedRuleSource struct {
	operations []policy.Operation
	name       string
	check      string
	kind       string
	family     string
	order      uint32
}

// builtinStandardAuthFactSchemaInputs declares fixed standard-auth decision inputs by operation.
func builtinStandardAuthFactSchemaInputs(action string) []FactSchemaInput {
	boolean := func(id string, category decision.FactCategory) FactSchemaInput {
		return builtinAuthnFactSchemaInput(
			id,
			category,
			decision.ValueKindBoolean,
			decision.FactSourceNauthilus,
		)
	}

	var ids []string

	switch action {
	case builtinActionAuthenticate:
		ids = []string{
			policy.AuthnFactBruteForceError,
			policy.AuthnFactBruteForceTriggered,
			policy.AuthnFactTLSSecure,
			policy.AuthnFactRelayDomainError,
			policy.AuthnFactRelayDomainPresent,
			policy.AuthnFactRelayDomainKnown,
			policy.AuthnFactRBLError,
			policy.AuthnFactRBLThresholdReached,
			policy.AuthnFactBackendTempFail,
			policy.AuthnFactBackendEmptyUsername,
			policy.AuthnFactBackendEmptyPassword,
			policy.AuthnFactMasterUserActive,
			policy.AuthnFactBruteForceTolerationCustom,
			policy.AuthnFactBruteForceTolerationSuppressedBlock,
		}
	case builtinActionLookupIdentity:
		ids = []string{
			policy.AuthnFactTLSSecure,
			policy.AuthnFactRBLError,
			policy.AuthnFactRBLThresholdReached,
			policy.AuthnFactBackendTempFail,
			policy.AuthnFactBackendEmptyUsername,
		}
	case builtinActionListAccounts:
		ids = []string{policy.AuthnFactAccountProviderTempFail}
	}

	inputs := make([]FactSchemaInput, 0, len(ids))
	for _, id := range ids {
		inputs = append(inputs, boolean(id, builtinStandardFactCategory(id)))
	}

	return inputs
}

// builtinStandardFactCategory preserves the established category of each mapped host fact.
func builtinStandardFactCategory(id string) decision.FactCategory {
	switch id {
	case policy.AuthnFactBackendEmptyUsername, policy.AuthnFactBackendEmptyPassword, policy.AuthnFactMasterUserActive:
		return decision.FactCategorySubject
	case policy.AuthnFactBackendTempFail, policy.AuthnFactAccountProviderTempFail:
		return decision.FactCategoryResource
	default:
		return decision.FactCategoryEnvironment
	}
}

// builtinAuthnPolicyFactSchemaInputs converts captured legacy definitions before catalog compilation.
func builtinAuthnPolicyFactSchemaInputs(
	action string,
	attributes map[string]AttributeDefinition,
) ([]FactSchemaInput, error) {
	operation := policy.Operation(action)
	keys := make([]string, 0, len(attributes))

	for id := range attributes {
		keys = append(keys, id)
	}

	sort.Strings(keys)

	result := make([]FactSchemaInput, 0)
	seen := make(map[string]struct{})

	for _, attributeID := range keys {
		inputs, err := builtinAuthnPolicyFactSchemaForAttribute(operation, attributeID, attributes[attributeID])
		if err != nil {
			return nil, err
		}

		for _, input := range inputs {
			if _, exists := seen[input.ID]; exists {
				continue
			}

			result = append(result, input)
			seen[input.ID] = struct{}{}
		}
	}

	return result, nil
}

// builtinAuthnPolicyFactSchemaForAttribute maps one applicable definition and its public detail metadata.
func builtinAuthnPolicyFactSchemaForAttribute(
	operation policy.Operation,
	attributeID string,
	definition AttributeDefinition,
) ([]FactSchemaInput, error) {
	if !slices.Contains(definition.Operations, operation) {
		return nil, nil
	}

	factID, _, ok := policy.AuthnCanonicalFactIdentity(attributeID, string(definition.Source))
	if !ok || builtinStandardFixedFact(factID) {
		return nil, nil
	}

	input, err := builtinFactSchemaFromAttribute(factID, definition)
	if err != nil {
		return nil, err
	}

	result := []FactSchemaInput{input}

	responseDetail, exists := definition.Details[builtinStatusMessageDetail]
	if !exists || responseDetail.Sensitivity != DetailSensitivityPublic ||
		responseDetail.Purpose != DetailPurposeResponseMessage {
		return result, nil
	}

	detailInput := input
	detailInput.ID = policy.AuthnResponseDetailFactID(factID, builtinStatusMessageDetail)
	detailInput.Kind = decision.ValueKindString

	detailInput.MaxLength = responseDetail.MaxLength
	if detailInput.MaxLength <= 0 {
		detailInput.MaxLength = 256
	}

	truncatedInput := input
	truncatedInput.ID = policy.AuthnResponseDetailTruncatedFactID(factID, builtinStatusMessageDetail)
	truncatedInput.Kind = decision.ValueKindBoolean
	truncatedInput.MaxLength = 0
	truncatedInput.MaxItems = 0
	selectedInput := truncatedInput
	selectedInput.ID = policy.AuthnResponseDetailSelectedFactID(factID, builtinStatusMessageDetail)

	return append(result, detailInput, truncatedInput, selectedInput), nil
}

// builtinStandardFixedFact reports whether the static schema already owns one mapped fact.
func builtinStandardFixedFact(id string) bool {
	for _, input := range builtinAuthnCommonFactSchemaInputs() {
		if input.ID == id {
			return true
		}
	}

	for _, action := range builtinAuthnActions() {
		for _, input := range builtinStandardAuthFactSchemaInputs(action) {
			if input.ID == id {
				return true
			}
		}
	}

	return false
}

// builtinFactSchemaFromAttribute maps one captured definition to the strict generic vocabulary.
func builtinFactSchemaFromAttribute(id string, definition AttributeDefinition) (FactSchemaInput, error) {
	category, ok := builtinFactCategory(definition.Category)
	if !ok {
		return FactSchemaInput{}, fmt.Errorf("authn policy fact %s has unsupported category %s", id, definition.Category)
	}

	kind, ok := builtinFactKind(definition.Type)
	if !ok {
		return FactSchemaInput{}, fmt.Errorf("authn policy fact %s has unsupported type %s", id, definition.Type)
	}

	source, ok := builtinFactSource(definition.Source)
	if !ok {
		return FactSchemaInput{}, fmt.Errorf("authn policy fact %s has unsupported source %s", id, definition.Source)
	}

	return builtinAuthnFactSchemaInput(id, category, kind, source), nil
}

// builtinFactCategory maps the established category into the strict contract.
func builtinFactCategory(input AttributeCategory) (decision.FactCategory, bool) {
	switch input {
	case AttributeCategoryEnvironment:
		return decision.FactCategoryEnvironment, true
	case AttributeCategorySubject:
		return decision.FactCategorySubject, true
	case AttributeCategoryResource:
		return decision.FactCategoryResource, true
	default:
		return "", false
	}
}

// builtinFactKind maps the established type into one immutable value kind.
func builtinFactKind(input AttributeType) (decision.ValueKind, bool) {
	switch input {
	case AttributeTypeBool:
		return decision.ValueKindBoolean, true
	case AttributeTypeString, AttributeTypeIP, AttributeTypeCIDR:
		return decision.ValueKindString, true
	case AttributeTypeStringList:
		return decision.ValueKindStrings, true
	case AttributeTypeNumber:
		return decision.ValueKindDouble, true
	case AttributeTypeDateTime:
		return decision.ValueKindTimestamp, true
	default:
		return "", false
	}
}

// builtinFactSource maps captured attribute authority to strict provenance.
func builtinFactSource(input AttributeSource) (decision.FactSource, bool) {
	switch input {
	case SourceBuiltin:
		return decision.FactSourceNauthilus, true
	case SourceLua:
		return decision.FactSourceLua, true
	case SourcePlugin:
		return decision.FactSourcePlugin, true
	default:
		return "", false
	}
}

// builtinStandardAuthRules constructs the sole executable standard-auth representation.
func builtinStandardAuthRules(attributes map[string]AttributeDefinition) ([]PolicyRule, error) {
	rules, err := builtinFixedStandardAuthRules()
	if err != nil {
		return nil, err
	}

	dynamic, err := builtinGeneratedStandardAuthRules(attributes)
	if err != nil {
		return nil, err
	}

	rules = append(rules, dynamic...)
	sort.SliceStable(rules, func(left int, right int) bool {
		return builtinStandardRulePriority(rules[left].Name()) < builtinStandardRulePriority(rules[right].Name())
	})

	return appendBuiltinStandardTerminalRules(rules)
}

// builtinStandardRulePriority preserves current stage-local standard rule precedence.
func builtinStandardRulePriority(name string) int {
	switch {
	case strings.HasPrefix(name, "standard_lua_environment_"),
		strings.HasPrefix(name, "standard_plugin_environment_"):
		return 20
	case name == "standard_backend_tempfail" || name == "standard_empty_username" || name == "standard_empty_password":
		return 30
	case strings.HasPrefix(name, "standard_lua_subject_"),
		strings.HasPrefix(name, "standard_plugin_subject_"):
		return 40
	case name == "standard_auth_success" || name == "standard_auth_failure" ||
		strings.HasPrefix(name, "standard_lookup_identity_") || strings.HasPrefix(name, "standard_list_accounts_"):
		return 50
	default:
		return 10
	}
}

// builtinFixedStandardAuthRules preserves fixed current behavior in catalog order.
func builtinFixedStandardAuthRules() ([]PolicyRule, error) {
	var rules []PolicyRule

	inputs, err := builtinFixedStandardAuthRuleInputs()
	if err != nil {
		return nil, err
	}

	for _, input := range inputs {
		rule, buildErr := newBuiltinAuthRule(input)
		if buildErr != nil {
			return nil, buildErr
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// builtinFixedStandardAuthRuleInputs declares deterministic fixed rule precedence.
func builtinFixedStandardAuthRuleInputs() ([]builtinAuthRuleInput, error) {
	authenticate := []string{builtinActionAuthenticate}
	lookup := []string{builtinActionLookupIdentity}
	authLookup := []string{builtinActionAuthenticate, builtinActionLookupIdentity}
	listAccounts := []string{builtinActionListAccounts}

	bruteForceEffects, err := builtinBruteForceDenyEffects()
	if err != nil {
		return nil, err
	}

	var tlsEffects []EffectUse

	relayEffects, err := builtinLearningActionEffects(policy.LuaActionDispatchRelayDomains)
	if err != nil {
		return nil, err
	}

	rblEffects, err := builtinLearningActionEffects(policy.LuaActionDispatchRBL)
	if err != nil {
		return nil, err
	}

	relayUnknown, err := builtinAllBooleanExpression(
		builtinBooleanCondition(policy.AuthnFactRelayDomainPresent, true),
		builtinBooleanCondition(policy.AuthnFactRelayDomainKnown, false),
	)
	if err != nil {
		return nil, err
	}

	rules := builtinFixedBruteForceAndTLSRuleInputs(authenticate, lookup, bruteForceEffects, tlsEffects)
	rules = append(rules, builtinFixedRelayAndRBLRuleInputs(
		authenticate,
		lookup,
		relayUnknown,
		relayEffects,
		rblEffects,
	)...)
	rules = append(rules, builtinFixedBackendRuleInputs(authenticate, lookup, authLookup, listAccounts)...)

	return rules, nil
}

// builtinFixedBruteForceAndTLSRuleInputs preserves the earliest protection precedence.
func builtinFixedBruteForceAndTLSRuleInputs(
	authenticate []string,
	lookup []string,
	bruteForceEffects []EffectUse,
	tlsEffects []EffectUse,
) []builtinAuthRuleInput {
	return []builtinAuthRuleInput{
		builtinBooleanRule("standard_brute_force_error_tempfail", builtinCheckpointPreAuth, policy.StagePreAuth,
			authenticate, policy.AuthnFactBruteForceError, true, decision.EffectIndeterminate,
			"auth.outcome.brute_force_error", policy.FSMEventMarkerPreAuthTempFail, policy.ResponseMarkerTempFail, nil),
		builtinBooleanRule("standard_brute_force_deny", builtinCheckpointPreAuth, policy.StagePreAuth,
			authenticate, policy.AuthnFactBruteForceTriggered, true, decision.EffectDeny,
			"auth.outcome.brute_force_reject", policy.FSMEventMarkerPreAuthDeny, policy.ResponseMarkerFail, bruteForceEffects),
		builtinBooleanRule("standard_tls_enforcement", builtinCheckpointDecision, policy.StagePreAuth,
			authenticate, policy.AuthnFactTLSSecure, false, decision.EffectIndeterminate,
			"auth.outcome.tls_required", policy.FSMEventMarkerPreAuthTempFail, policy.ResponseMarkerTempFailNoTLS, tlsEffects),
		builtinBooleanRule("standard_tls_enforcement", builtinCheckpointPreAuth, policy.StagePreAuth,
			lookup, policy.AuthnFactTLSSecure, false, decision.EffectIndeterminate,
			"auth.outcome.tls_required", policy.FSMEventMarkerPreAuthTempFail, policy.ResponseMarkerTempFailNoTLS, tlsEffects),
	}
}

// builtinFixedRelayAndRBLRuleInputs preserves relay and block-list precedence.
func builtinFixedRelayAndRBLRuleInputs(
	authenticate []string,
	lookup []string,
	relayUnknown PolicyExpression,
	relayEffects []EffectUse,
	rblEffects []EffectUse,
) []builtinAuthRuleInput {
	return []builtinAuthRuleInput{
		builtinBooleanRule("standard_relay_domain_error_tempfail", builtinCheckpointDecision, policy.StagePreAuth,
			authenticate, policy.AuthnFactRelayDomainError, true, decision.EffectIndeterminate,
			"auth.outcome.relay_domain_error", policy.FSMEventMarkerPreAuthTempFail, policy.ResponseMarkerTempFail, nil),
		{
			name: "standard_relay_domain_reject", checkpoint: builtinCheckpointDecision,
			presentationStage: string(policy.StagePreAuth), actions: authenticate, expression: relayUnknown,
			decision: decision.EffectDeny, outcomeMarker: "auth.outcome.relay_domain_reject",
			fsmMarker: policy.FSMEventMarkerPreAuthDeny, responseMarker: policy.ResponseMarkerFail, effects: relayEffects,
		},
		builtinBooleanRule("standard_rbl_error_tempfail", builtinCheckpointDecision, policy.StagePreAuth,
			authenticate, policy.AuthnFactRBLError, true, decision.EffectIndeterminate,
			"auth.outcome.rbl_error", policy.FSMEventMarkerPreAuthTempFail, policy.ResponseMarkerTempFail, nil),
		builtinBooleanRule("standard_rbl_error_tempfail", builtinCheckpointPreAuth, policy.StagePreAuth,
			lookup, policy.AuthnFactRBLError, true, decision.EffectIndeterminate,
			"auth.outcome.rbl_error", policy.FSMEventMarkerPreAuthTempFail, policy.ResponseMarkerTempFail, nil),
		builtinBooleanRule("standard_rbl_reject", builtinCheckpointDecision, policy.StagePreAuth,
			authenticate, policy.AuthnFactRBLThresholdReached, true, decision.EffectDeny,
			"auth.outcome.rbl_reject", policy.FSMEventMarkerPreAuthDeny, policy.ResponseMarkerFail, rblEffects),
		builtinBooleanRule("standard_rbl_reject", builtinCheckpointPreAuth, policy.StagePreAuth,
			lookup, policy.AuthnFactRBLThresholdReached, true, decision.EffectDeny,
			"auth.outcome.rbl_reject", policy.FSMEventMarkerPreAuthDeny, policy.ResponseMarkerFail, rblEffects),
	}
}

// builtinFixedBackendRuleInputs preserves backend and operation-terminal precedence.
func builtinFixedBackendRuleInputs(
	authenticate []string,
	lookup []string,
	authLookup []string,
	listAccounts []string,
) []builtinAuthRuleInput {
	return []builtinAuthRuleInput{
		builtinBooleanRule("standard_backend_tempfail", builtinCheckpointDecision, policy.StageAuthDecision,
			authLookup, policy.AuthnFactBackendTempFail, true, decision.EffectIndeterminate,
			"auth.outcome.backend_tempfail", policy.FSMEventMarkerAuthTempFail, policy.ResponseMarkerTempFail, nil),
		builtinBooleanRule("standard_empty_username", builtinCheckpointDecision, policy.StageAuthDecision,
			authLookup, policy.AuthnFactBackendEmptyUsername, true, decision.EffectIndeterminate,
			"auth.outcome.empty_username", policy.FSMEventMarkerAuthEmptyUser, policy.ResponseMarkerTempFail, nil),
		builtinBooleanRule("standard_empty_password", builtinCheckpointDecision, policy.StageAuthDecision,
			authenticate, policy.AuthnFactBackendEmptyPassword, true, decision.EffectDeny,
			"auth.outcome.empty_password", policy.FSMEventMarkerAuthEmptyPass, policy.ResponseMarkerFail, nil),
		builtinBooleanRule("standard_auth_success", builtinCheckpointDecision, policy.StageAuthDecision,
			authenticate, policy.AuthnFactAuthenticated, true, decision.EffectPermit,
			policy.OutcomeMarkerAuthSuccess, policy.FSMEventMarkerAuthPermit, policy.ResponseMarkerOK, nil),
		builtinBooleanRule("standard_auth_failure", builtinCheckpointDecision, policy.StageAuthDecision,
			authenticate, policy.AuthnFactAuthenticated, false, decision.EffectDeny,
			policy.OutcomeMarkerAuthFailure, policy.FSMEventMarkerAuthDeny, policy.ResponseMarkerFail, nil),
		builtinBooleanRule("standard_lookup_identity_success", builtinCheckpointDecision, policy.StageAuthDecision,
			lookup, policy.AuthnFactIdentityFound, true, decision.EffectPermit,
			"auth.outcome.lookup_identity_success", policy.FSMEventMarkerAuthPermit, policy.ResponseMarkerOK, nil),
		builtinBooleanRule("standard_lookup_identity_failure", builtinCheckpointDecision, policy.StageAuthDecision,
			lookup, policy.AuthnFactIdentityFound, false, decision.EffectDeny,
			"auth.outcome.lookup_identity_failure", policy.FSMEventMarkerAuthDeny, policy.ResponseMarkerFail, nil),
		builtinBooleanRule("standard_list_accounts_tempfail", builtinCheckpointDecision, policy.StageAuthDecision,
			listAccounts, policy.AuthnFactAccountProviderTempFail, true, decision.EffectIndeterminate,
			"auth.outcome.list_accounts_tempfail", policy.FSMEventMarkerAuthTempFail, policy.ResponseMarkerTempFail, nil),
		builtinBooleanRule("standard_list_accounts_success", builtinCheckpointDecision, policy.StageAuthDecision,
			listAccounts, policy.AuthnFactAccountProviderCompleted, true, decision.EffectPermit,
			"auth.outcome.list_accounts_success", policy.FSMEventMarkerAuthPermit, policy.ResponseMarkerListAccountsOK, nil),
		builtinBooleanRule("standard_list_accounts_failure", builtinCheckpointDecision, policy.StageAuthDecision,
			listAccounts, policy.AuthnFactAccountProviderCompleted, false, decision.EffectDeny,
			"auth.outcome.list_accounts_failure", policy.FSMEventMarkerAuthDeny, policy.ResponseMarkerFail, nil),
	}
}

// builtinBooleanRule constructs one fixed boolean standard-auth rule input.
func builtinBooleanRule(
	name string,
	checkpoint string,
	stage policy.Stage,
	actions []string,
	factID string,
	expected bool,
	effect decision.Effect,
	outcomeMarker string,
	fsmMarker string,
	responseMarker string,
	effects []EffectUse,
) builtinAuthRuleInput {
	expression, _ := builtinBooleanExpression(factID, expected)

	return builtinAuthRuleInput{
		name: name, checkpoint: checkpoint, presentationStage: string(stage), actions: actions,
		expression: expression, decision: effect, outcomeMarker: outcomeMarker,
		fsmMarker: fsmMarker, responseMarker: responseMarker, effects: effects,
	}
}

// newBuiltinAuthRule validates one complete catalog-owned rule input.
func newBuiltinAuthRule(input builtinAuthRuleInput) (PolicyRule, error) {
	rule, err := newBuiltinAuthPolicyRule(PolicyRuleInput{
		Name: input.name, Checkpoint: input.checkpoint, Actions: input.actions,
		Expression: input.expression, Effects: input.effects, Decision: input.decision,
		OutcomeMarker: input.outcomeMarker, FSMEventMarker: input.fsmMarker,
		ResponseMarker: input.responseMarker, ResponseMessage: input.responseMessage,
		SkipRemainingCheckpointProviders: input.skipRemaining,
	}, input.presentationStage)
	if err != nil {
		return PolicyRule{}, fmt.Errorf("build builtin standard-auth rule %q: %w", input.name, err)
	}

	return rule, nil
}

// appendBuiltinStandardTerminalRules adds explicit neutral and fail-closed terminal rules last.
func appendBuiltinStandardTerminalRules(rules []PolicyRule) ([]PolicyRule, error) {
	always, err := NewPolicyExpression(PolicyExpressionInput{Kind: ExpressionKindAlways})
	if err != nil {
		return nil, err
	}

	for _, input := range []builtinAuthRuleInput{
		{
			name: "implicit_pre_auth_pass", checkpoint: builtinCheckpointPreAuth,
			presentationStage: string(policy.StagePreAuth), actions: []string{builtinActionAuthenticate, builtinActionLookupIdentity},
			expression: always, decision: decision.EffectNotApplicable,
			outcomeMarker: builtinStandardOutcomePreAuthOK, fsmMarker: policy.FSMEventMarkerPreAuthOK,
		},
		{
			name: "standard_default_deny", checkpoint: builtinCheckpointDecision,
			presentationStage: string(policy.StageAuthDecision), actions: builtinAuthnActions(),
			expression: always, decision: decision.EffectDeny,
			outcomeMarker: builtinStandardOutcomeDefaultDeny, fsmMarker: policy.FSMEventMarkerAuthDeny,
			responseMarker: policy.ResponseMarkerFail,
		},
	} {
		rule, buildErr := newBuiltinAuthRule(input)
		if buildErr != nil {
			return nil, buildErr
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// builtinGeneratedStandardAuthRules derives immutable Lua and native rules from captured definitions.
func builtinGeneratedStandardAuthRules(attributes map[string]AttributeDefinition) ([]PolicyRule, error) {
	sources := builtinGeneratedRuleSources(attributes)
	rules := make([]PolicyRule, 0, len(sources)*3)
	pluginEnvironmentSources := make([]builtinGeneratedRuleSource, 0, len(sources))
	pluginSubjectSources := make([]builtinGeneratedRuleSource, 0, len(sources))

	for _, source := range sources {
		if source.family == builtinGeneratedFamilyPlugin {
			switch source.kind {
			case builtinGeneratedKindEnvironment:
				pluginEnvironmentSources = append(pluginEnvironmentSources, source)
			case builtinGeneratedKindSubject:
				pluginSubjectSources = append(pluginSubjectSources, source)
			}

			if source.kind == builtinGeneratedKindEnvironment || source.kind == builtinGeneratedKindSubject {
				continue
			}
		}

		for _, operation := range source.operations {
			compiled, err := builtinGeneratedRulesForOperation(source, operation)
			if err != nil {
				return nil, err
			}

			rules = append(rules, compiled...)
		}
	}

	pluginEnvironmentRules, err := builtinGeneratedPluginEnvironmentRules(pluginEnvironmentSources)
	if err != nil {
		return nil, err
	}

	rules = append(rules, pluginEnvironmentRules...)

	pluginSubjectRules, err := builtinGeneratedPluginSubjectRules(pluginSubjectSources)
	if err != nil {
		return nil, err
	}

	rules = append(rules, pluginSubjectRules...)

	return rules, nil
}

// builtinGeneratedPluginEnvironmentRules preserves aggregate error, trigger, and abort precedence.
func builtinGeneratedPluginEnvironmentRules(
	sources []builtinGeneratedRuleSource,
) ([]PolicyRule, error) {
	return builtinGeneratedPluginRules(sources, 3, builtinGeneratedEnvironmentRuleInputs)
}

// builtinGeneratedPluginSubjectRules preserves aggregate error then final rejection precedence.
func builtinGeneratedPluginSubjectRules(
	sources []builtinGeneratedRuleSource,
) ([]PolicyRule, error) {
	return builtinGeneratedPluginRules(sources, 2, builtinGeneratedSubjectRuleInputs)
}

// builtinGeneratedPluginRules groups errors before terminal results for every operation.
func builtinGeneratedPluginRules(
	sources []builtinGeneratedRuleSource,
	groupCount int,
	build func(builtinGeneratedRuleSource, policy.Operation) ([]builtinAuthRuleInput, error),
) ([]PolicyRule, error) {
	sortGeneratedRuleSourcesByProducerOrder(sources)

	var rules []PolicyRule

	for _, operation := range []policy.Operation{policy.OperationAuthenticate, policy.OperationLookupIdentity} {
		inputs := make([][]builtinAuthRuleInput, groupCount)

		for _, source := range sources {
			if !slices.Contains(source.operations, operation) {
				continue
			}

			generated, err := build(source, operation)
			if err != nil {
				return nil, err
			}

			for index := range generated {
				inputs[index] = append(inputs[index], generated[index])
			}
		}

		slices.Reverse(inputs[1])

		for _, group := range inputs {
			compiled, err := buildBuiltinAuthRules(group)
			if err != nil {
				return nil, err
			}

			rules = append(rules, compiled...)
		}
	}

	return rules, nil
}

// sortGeneratedRuleSourcesByProducerOrder preserves dependency order with a stable lexical fallback.
func sortGeneratedRuleSourcesByProducerOrder(sources []builtinGeneratedRuleSource) {
	sort.SliceStable(sources, func(left int, right int) bool {
		if sources[left].order != sources[right].order {
			return sources[left].order < sources[right].order
		}

		return sources[left].name < sources[right].name
	})
}

// builtinGeneratedRuleSources extracts one deterministic rule source per generated host component.
func builtinGeneratedRuleSources(attributes map[string]AttributeDefinition) []builtinGeneratedRuleSource {
	byKey := make(map[string]builtinGeneratedRuleSource)

	for _, definition := range attributes {
		family, kind, name, ok := builtinGeneratedAttribute(definition.ID)
		if !ok || definition.ProducerCheck == "" {
			continue
		}

		key := family + ":" + kind + ":" + definition.ProducerCheck + ":" + name
		source := byKey[key]
		source.family = family
		source.kind = kind
		source.name = name
		source.check = definition.ProducerCheck

		source.operations = appendUniqueOperations(source.operations, definition.Operations...)
		if source.order == 0 || definition.ProducerOrder > 0 && definition.ProducerOrder < source.order {
			source.order = definition.ProducerOrder
		}

		byKey[key] = source
	}

	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	result := make([]builtinGeneratedRuleSource, 0, len(keys))
	for _, key := range keys {
		result = append(result, byKey[key])
	}

	return result
}

// builtinGeneratedAttribute recognizes host-owned Lua and native execution facts.
func builtinGeneratedAttribute(attributeID string) (string, string, string, bool) {
	for _, source := range []struct {
		family string
		kind   string
		prefix string
	}{
		{family: builtinGeneratedFamilyLua, kind: builtinGeneratedKindEnvironment, prefix: "auth.lua.environment."},
		{family: builtinGeneratedFamilyLua, kind: builtinGeneratedKindSubject, prefix: "auth.lua.subject."},
		{family: builtinGeneratedFamilyPlugin, kind: builtinGeneratedKindEnvironment, prefix: "auth.plugin.environment."},
		{family: builtinGeneratedFamilyPlugin, kind: builtinGeneratedKindSubject, prefix: "auth.plugin.subject."},
	} {
		if !strings.HasPrefix(attributeID, source.prefix) {
			continue
		}

		nameAndSuffix := strings.TrimPrefix(attributeID, source.prefix)

		separator := strings.LastIndex(nameAndSuffix, ".")
		if separator <= 0 {
			return "", "", "", false
		}

		return source.family, source.kind, nameAndSuffix[:separator], true
	}

	return "", "", "", false
}

// appendUniqueOperations owns operation order without duplicates.
func appendUniqueOperations(existing []policy.Operation, values ...policy.Operation) []policy.Operation {
	for _, value := range values {
		found := false

		for _, current := range existing {
			if current == value {
				found = true

				break
			}
		}

		if !found {
			existing = append(existing, value)
		}
	}

	return existing
}

// builtinGeneratedRulesForOperation builds exact environment or subject precedence for one operation.
func builtinGeneratedRulesForOperation(
	source builtinGeneratedRuleSource,
	operation policy.Operation,
) ([]PolicyRule, error) {
	if operation != policy.OperationAuthenticate && operation != policy.OperationLookupIdentity {
		return nil, nil
	}

	if source.kind == builtinGeneratedKindEnvironment {
		return builtinGeneratedEnvironmentRules(source, operation)
	}

	return builtinGeneratedSubjectRules(source, operation)
}

// builtinGeneratedEnvironmentRules preserves error, trigger, and nonterminal abort order.
func builtinGeneratedEnvironmentRules(
	source builtinGeneratedRuleSource,
	operation policy.Operation,
) ([]PolicyRule, error) {
	inputs, err := builtinGeneratedEnvironmentRuleInputs(source, operation)
	if err != nil {
		return nil, err
	}

	return buildBuiltinAuthRules(inputs)
}

// builtinGeneratedEnvironmentRuleInputs describes one source without assigning cross-source order.
func builtinGeneratedEnvironmentRuleInputs(
	source builtinGeneratedRuleSource,
	operation policy.Operation,
) ([]builtinAuthRuleInput, error) {
	checkpoint := builtinCheckpointPreAuth
	if operation == policy.OperationAuthenticate {
		checkpoint = builtinCheckpointDecision
	}

	effects, err := builtinGeneratedEnvironmentEffects(source)
	if err != nil {
		return nil, err
	}

	triggerFact := builtinGeneratedFactID(source, "triggered")
	rulePrefix := builtinGeneratedRulePrefix(source)
	outcomePrefix := "auth.outcome." + source.family + "_environment." + source.name

	inputs := []builtinAuthRuleInput{
		builtinBooleanRule(rulePrefix+"_error", checkpoint, policy.StagePreAuth,
			[]string{string(operation)}, builtinGeneratedFactID(source, "error"), true,
			decision.EffectIndeterminate, outcomePrefix+".error",
			policy.FSMEventMarkerPreAuthTempFail, policy.ResponseMarkerTempFail, nil),
		builtinBooleanRule(rulePrefix+"_trigger", checkpoint, policy.StagePreAuth,
			[]string{string(operation)}, triggerFact, true, decision.EffectDeny,
			outcomePrefix+".reject",
			policy.FSMEventMarkerPreAuthDeny, policy.ResponseMarkerFail, effects),
		builtinBooleanRule(rulePrefix+"_abort", checkpoint, policy.StagePreAuth,
			[]string{string(operation)}, builtinGeneratedFactID(source, "abort"), true,
			decision.EffectNotApplicable, builtinStandardOutcomePreAuthOK,
			policy.FSMEventMarkerPreAuthOK, "", nil),
	}

	message, messageErr := builtinResponseDetailMessage(triggerFact)
	if messageErr != nil {
		return nil, messageErr
	}

	inputs[1].responseMessage = message
	inputs[2].skipRemaining = true

	return inputs, nil
}

// builtinGeneratedSubjectRules preserves error then rejection order for one source.
func builtinGeneratedSubjectRules(
	source builtinGeneratedRuleSource,
	operation policy.Operation,
) ([]PolicyRule, error) {
	inputs, err := builtinGeneratedSubjectRuleInputs(source, operation)
	if err != nil {
		return nil, err
	}

	return buildBuiltinAuthRules(inputs)
}

// builtinGeneratedSubjectRuleInputs describes one source without assigning cross-source order.
func builtinGeneratedSubjectRuleInputs(
	source builtinGeneratedRuleSource,
	operation policy.Operation,
) ([]builtinAuthRuleInput, error) {
	rejectedFact := builtinGeneratedFactID(source, "rejected")
	rulePrefix := builtinGeneratedRulePrefix(source)
	outcomePrefix := "auth.outcome." + source.family + "_subject." + source.name

	inputs := []builtinAuthRuleInput{
		builtinBooleanRule(rulePrefix+"_error", builtinCheckpointDecision, policy.StageAuthDecision,
			[]string{string(operation)}, builtinGeneratedFactID(source, "error"), true,
			decision.EffectIndeterminate, outcomePrefix+".error",
			policy.FSMEventMarkerAuthTempFail, policy.ResponseMarkerTempFail, nil),
		builtinBooleanRule(rulePrefix+"_reject", builtinCheckpointDecision, policy.StageAuthDecision,
			[]string{string(operation)}, rejectedFact, true, decision.EffectDeny,
			outcomePrefix+".reject",
			policy.FSMEventMarkerAuthDeny, policy.ResponseMarkerFail, nil),
	}

	message, err := builtinResponseDetailMessage(rejectedFact)
	if err != nil {
		return nil, err
	}

	inputs[1].responseMessage = message

	return inputs, nil
}

// builtinGeneratedEnvironmentEffects preserves Lua learning/action work while native sources stay host-owned.
func builtinGeneratedEnvironmentEffects(source builtinGeneratedRuleSource) ([]EffectUse, error) {
	if source.family != builtinGeneratedFamilyLua {
		return nil, nil
	}

	return builtinLuaEnvironmentEffects(source.name, source.check)
}

// builtinGeneratedFactID maps one captured source and suffix into the strict catalog identity.
func builtinGeneratedFactID(source builtinGeneratedRuleSource, suffix string) string {
	if source.family == builtinGeneratedFamilyLua {
		if source.kind == builtinGeneratedKindEnvironment {
			return policy.AuthnLuaEnvironmentFactID(source.name, suffix)
		}

		return policy.AuthnLuaSubjectFactID(source.name, suffix)
	}

	return "nauthilus.auth.plugin." + source.kind + "." + source.name + "." + suffix
}

// builtinGeneratedRulePrefix returns one stable rule name for dotted native component identities.
func builtinGeneratedRulePrefix(source builtinGeneratedRuleSource) string {
	name := strings.ReplaceAll(source.name, ".", "_")

	return "standard_" + source.family + "_" + source.kind + "_" + name
}

// buildBuiltinAuthRules constructs an ordered rule input slice.
func buildBuiltinAuthRules(inputs []builtinAuthRuleInput) ([]PolicyRule, error) {
	rules := make([]PolicyRule, 0, len(inputs))
	for _, input := range inputs {
		rule, err := newBuiltinAuthRule(input)
		if err != nil {
			return nil, err
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// builtinResponseDetailMessage selects one sanitized public status-message fact.
func builtinResponseDetailMessage(factID string) (PolicyResponseMessage, error) {
	return NewPolicyResponseMessage(PolicyResponseMessageInput{
		From:      policy.ResponseSourceAttributeDetail,
		FactID:    policy.AuthnResponseDetailFactID(factID, builtinStatusMessageDetail),
		Detail:    builtinStatusMessageDetail,
		Fallback:  definitions.PasswordFail,
		MaxLength: 256,
	})
}

// builtinBooleanExpression constructs one exact boolean equality predicate.
func builtinBooleanExpression(factID string, expected bool) (PolicyExpression, error) {
	value, err := decision.NewValue(decision.ValueInput{Boolean: &expected})
	if err != nil {
		return PolicyExpression{}, err
	}

	return NewPolicyExpression(PolicyExpressionInput{
		Kind: ExpressionKindAttribute, FactID: factID, FactKind: decision.ValueKindBoolean,
		Operator: ExpressionOperatorIs, Values: []decision.Value{value},
	})
}

// builtinBooleanCondition creates one child for a composite expression.
func builtinBooleanCondition(factID string, expected bool) PolicyExpression {
	expression, _ := builtinBooleanExpression(factID, expected)

	return expression
}

// builtinAllBooleanExpression combines exact boolean children.
func builtinAllBooleanExpression(children ...PolicyExpression) (PolicyExpression, error) {
	return NewPolicyExpression(PolicyExpressionInput{Kind: ExpressionKindAll, Children: children})
}

// builtinBruteForceDenyEffects selects only the generation-owned bucket update.
func builtinBruteForceDenyEffects() ([]EffectUse, error) {
	update, err := NewEffectUse(builtinBruteForceEffect, nil)
	if err != nil {
		return nil, err
	}

	return []EffectUse{update}, nil
}

// builtinLearningActionEffects constructs the current learning update.
func builtinLearningActionEffects(action string) ([]EffectUse, error) {
	update, err := builtinEffectUse(builtinBruteForceEffect, map[string]any{
		policy.ObligationArgFeature: action, policy.ObligationArgEnvironment: action,
	})
	if err != nil {
		return nil, err
	}

	return []EffectUse{update}, nil
}

// builtinLuaEnvironmentEffects constructs the learning update for one script.
func builtinLuaEnvironmentEffects(name string, check string) ([]EffectUse, error) {
	update, err := builtinEffectUse(builtinBruteForceEffect, map[string]any{
		policy.ObligationArgFeature: policy.LuaActionDispatchLua, policy.ObligationArgEnvironment: name,
	})
	if err != nil {
		return nil, err
	}

	_ = check

	return []EffectUse{update}, nil
}

// builtinEffectUse converts one closed scalar parameter map to strict immutable values.
func builtinEffectUse(effectID string, parameters map[string]any) (EffectUse, error) {
	values := make(map[string]decision.Value, len(parameters))
	for key, raw := range parameters {
		text, ok := raw.(string)
		if !ok {
			return EffectUse{}, fmt.Errorf("builtin effect %s parameter %s is not a string", effectID, key)
		}

		value, err := decision.NewValue(decision.ValueInput{String: &text})
		if err != nil {
			return EffectUse{}, err
		}

		values[key] = value
	}

	return NewEffectUse(effectID, values)
}
