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

// Package evaluation evaluates built-in policy decisions from collected facts.
package evaluation

import (
	"context"
	"log/slog"
	"reflect"
	"sort"
	"strings"
	"unicode"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/policy"
	"github.com/croessner/nauthilus/server/policy/observability"
	"github.com/croessner/nauthilus/server/policy/report"
)

const (
	responseMarkerOK                 = policy.ResponseMarkerOK
	responseMarkerFail               = policy.ResponseMarkerFail
	responseMarkerTempFail           = policy.ResponseMarkerTempFail
	responseMarkerNoTLS              = policy.ResponseMarkerTempFailNoTLS
	responseMarkerListAccountsOK     = policy.ResponseMarkerListAccountsOK
	fsmMarkerPreAuthOK               = policy.FSMEventMarkerPreAuthOK
	fsmMarkerPreAuthDeny             = policy.FSMEventMarkerPreAuthDeny
	fsmMarkerPreAuthTempFail         = policy.FSMEventMarkerPreAuthTempFail
	fsmMarkerAuthPermit              = policy.FSMEventMarkerAuthPermit
	fsmMarkerAuthDeny                = policy.FSMEventMarkerAuthDeny
	fsmMarkerAuthTempFail            = policy.FSMEventMarkerAuthTempFail
	fsmMarkerAuthEmptyUser           = policy.FSMEventMarkerAuthEmptyUser
	fsmMarkerAuthEmptyPass           = policy.FSMEventMarkerAuthEmptyPass
	obligationBruteForceUpdate       = policy.ObligationBruteForceUpdate
	obligationLuaPostActionEnqueue   = policy.ObligationLuaPostActionEnqueue
	mismatchNone                     = "none"
	mismatchMultiple                 = "multiple"
	defaultMode                      = "enforce"
	maxSelectedResponseMessageLength = 256
)

var (
	authenticateOps = []policy.Operation{policy.OperationAuthenticate}
	authLookupOps   = []policy.Operation{policy.OperationAuthenticate, policy.OperationLookupIdentity}
	allOps          = []policy.Operation{
		policy.OperationAuthenticate,
		policy.OperationLookupIdentity,
		policy.OperationListAccounts,
	}
)

// Result contains the selected built-in policy decision.
type Result struct {
	Final    *report.FinalDecision
	Mismatch bool
}

// CompareInput carries comparison dependencies and runtime metadata.
type CompareInput struct {
	Logger     *slog.Logger
	Recorder   observability.Recorder
	Mode       string
	Set        string
	Surface    string
	Generation uint64
}

// CompareResult describes the default-policy comparison outcome.
type CompareResult struct {
	Shadow       *report.FinalDecision
	Production   *report.FinalDecision
	MismatchType string
	Mismatch     bool
}

type standardRule struct {
	messageSelector func(*report.DecisionReport, string) *report.ResponseMessageSelection
	condition       func(*report.DecisionReport) bool
	control         *report.DecisionControl
	name            string
	reason          string
	outcomeMarker   string
	responseMarker  string
	fsmMarker       string
	stage           policy.Stage
	effect          policy.Decision
	operations      []policy.Operation
	requiredChecks  []string
	obligations     []report.EffectRequest
	advice          []report.EffectRequest
}

// EvaluateStandardAuth evaluates the built-in default policy from collected facts.
func EvaluateStandardAuth(policyReport *report.DecisionReport) Result {
	policyReport = prepareStandardReport(policyReport)
	operation := policyReport.Operation

	if final := evaluatePreAuth(policyReport, operation); isTerminal(final) {
		return Result{Final: final}
	}

	final := evaluateAuthDecision(policyReport, operation)

	return Result{Final: final}
}

// EvaluateStandardPreAuth evaluates only the built-in pre-auth rules.
func EvaluateStandardPreAuth(policyReport *report.DecisionReport) Result {
	policyReport = prepareStandardReport(policyReport)

	return Result{Final: evaluatePreAuth(policyReport, policyReport.Operation)}
}

func normalizeCompareInput(
	ctx context.Context,
	policyReport *report.DecisionReport,
	input CompareInput,
) (context.Context, *report.DecisionReport, CompareInput) {
	if ctx == nil {
		ctx = context.Background()
	}

	if policyReport == nil {
		policyReport = report.NewDecisionReport()
	}

	if input.Mode == "" {
		input.Mode = defaultMode
	}

	if input.Set == "" {
		input.Set = policy.BuiltinDefaultSet
	}

	return ctx, policyReport, input
}

func prepareStandardReport(policyReport *report.DecisionReport) *report.DecisionReport {
	if policyReport == nil {
		policyReport = report.NewDecisionReport()
	}

	if policyReport.Operation == "" {
		policyReport.Operation = policy.OperationAuthenticate
	}

	policyReport.Policies = policyReport.Policies[:0]
	policyReport.Final = nil
	policyReport.Stage = ""

	return policyReport
}

// TargetFSMEventMarkers returns the target marker sequence for a selected decision.
func TargetFSMEventMarkers(policyReport *report.DecisionReport, final *report.FinalDecision) []string {
	markers := []string{policy.FSMEventMarkerParseOK}
	if final == nil {
		return markers
	}

	if final.Stage == policy.StagePreAuth {
		return append(markers, final.FSMEventMarker)
	}

	markers = append(markers, selectedPreAuthMarker(policyReport))
	if policyReport != nil && policyReport.Operation == policy.OperationListAccounts {
		markers = append(markers, policy.FSMEventMarkerAccountProviderEvaluated)
	} else {
		markers = append(markers, policy.FSMEventMarkerAuthEvaluated)
	}

	return append(markers, final.FSMEventMarker)
}

func selectedPreAuthMarker(policyReport *report.DecisionReport) string {
	if policyReport == nil {
		return policy.FSMEventMarkerPreAuthOK
	}

	marker := ""
	for _, decision := range policyReport.Policies {
		if decision.Stage == policy.StagePreAuth && decision.FSMEventMarker != "" {
			marker = decision.FSMEventMarker
		}
	}

	if marker == "" {
		return policy.FSMEventMarkerPreAuthOK
	}

	return marker
}

func evaluatePreAuth(policyReport *report.DecisionReport, operation policy.Operation) *report.FinalDecision {
	if operation == policy.OperationListAccounts {
		return nil
	}

	for _, rule := range preAuthRules(policyReport, operation) {
		if !rule.applies(policyReport, operation) {
			continue
		}

		decision := rule.selectDecision(policyReport)
		appendDecision(policyReport, decision)
		if strings.HasSuffix(rule.name, "_abort") {
			return nil
		}

		if decision.Effect == policy.DecisionDeny || decision.Effect == policy.DecisionTempFail {
			return finalDecisionFromPolicy(decision)
		}
	}

	pass := standardRule{
		name:          "implicit_pre_auth_pass",
		stage:         policy.StagePreAuth,
		effect:        policy.DecisionNeutral,
		outcomeMarker: "auth.outcome.pre_auth_ok",
		fsmMarker:     fsmMarkerPreAuthOK,
		operations:    allOps,
	}.selectDecision(policyReport)
	appendDecision(policyReport, pass)

	return nil
}

func evaluateAuthDecision(policyReport *report.DecisionReport, operation policy.Operation) *report.FinalDecision {
	for _, rule := range authDecisionRules(policyReport, operation) {
		if !rule.applies(policyReport, operation) {
			continue
		}

		decision := rule.selectDecision(policyReport)
		appendDecision(policyReport, decision)

		return finalDecisionFromPolicy(decision)
	}

	decision := defaultDenyRule().selectDecision(policyReport)
	appendDecision(policyReport, decision)

	return finalDecisionFromPolicy(decision)
}

func preAuthRules(policyReport *report.DecisionReport, operation policy.Operation) []standardRule {
	rules := append([]standardRule{}, bruteForceRules()...)
	rules = append(rules, tlsRule())
	rules = append(rules, relayDomainRules()...)
	rules = append(rules, rblRules()...)

	if operation == policy.OperationAuthenticate {
		rules = append(rules, luaControlRules(policyReport)...)
	}

	return rules
}

func authDecisionRules(policyReport *report.DecisionReport, operation policy.Operation) []standardRule {
	rules := backendDecisionRules()

	if operation == policy.OperationAuthenticate {
		rules = append(rules, authenticateDecisionRules(policyReport)...)
	}

	if operation == policy.OperationLookupIdentity {
		rules = append(rules, lookupIdentityRules()...)
	}

	if operation == policy.OperationListAccounts {
		rules = append(rules, listAccountRules()...)
	}

	rules = append(rules, defaultDenyRule())

	return rules
}

func bruteForceRules() []standardRule {
	return []standardRule{
		ruleWithCheck(
			"standard_brute_force_error_tempfail",
			policy.StagePreAuth,
			policy.DecisionTempFail,
			"auth.outcome.brute_force_error",
			fsmMarkerPreAuthTempFail,
			responseMarkerTempFail,
			authenticateOps,
			"brute_force",
			attrIsTrue(policy.AttributeBruteForceError),
		),
		bruteForceDenyRule(),
	}
}

func bruteForceDenyRule() standardRule {
	rule := ruleWithCheck(
		"standard_brute_force_deny",
		policy.StagePreAuth,
		policy.DecisionDeny,
		"auth.outcome.brute_force_reject",
		fsmMarkerPreAuthDeny,
		responseMarkerFail,
		authenticateOps,
		"brute_force",
		attrIsTrue(policy.AttributeBruteForceTriggered),
	)
	rule.obligations = []report.EffectRequest{
		{ID: obligationBruteForceUpdate},
		{ID: obligationLuaPostActionEnqueue, Args: map[string]any{"action": "brute_force"}},
	}

	return rule
}

func tlsRule() standardRule {
	return ruleWithCheck(
		"standard_tls_enforcement",
		policy.StagePreAuth,
		policy.DecisionTempFail,
		"auth.outcome.tls_required",
		fsmMarkerPreAuthTempFail,
		responseMarkerNoTLS,
		authLookupOps,
		"tls_encryption",
		attrIsFalse(policy.AttributeTLSSecure),
	)
}

func relayDomainRules() []standardRule {
	return []standardRule{
		ruleWithCheck(
			"standard_relay_domain_error_tempfail",
			policy.StagePreAuth,
			policy.DecisionTempFail,
			"auth.outcome.relay_domain_error",
			fsmMarkerPreAuthTempFail,
			responseMarkerTempFail,
			authenticateOps,
			"relay_domains",
			attrIsTrue(policy.AttributeRelayDomainError),
		),
		ruleWithCheck(
			"standard_relay_domain_reject",
			policy.StagePreAuth,
			policy.DecisionDeny,
			"auth.outcome.relay_domain_reject",
			fsmMarkerPreAuthDeny,
			responseMarkerFail,
			authenticateOps,
			"relay_domains",
			unknownRelayDomain,
		),
	}
}

func rblRules() []standardRule {
	return []standardRule{
		ruleWithCheck(
			"standard_rbl_error_tempfail",
			policy.StagePreAuth,
			policy.DecisionTempFail,
			"auth.outcome.rbl_error",
			fsmMarkerPreAuthTempFail,
			responseMarkerTempFail,
			authLookupOps,
			"rbl",
			attrIsTrue(policy.AttributeRBLError),
		),
		ruleWithCheck(
			"standard_rbl_reject",
			policy.StagePreAuth,
			policy.DecisionDeny,
			"auth.outcome.rbl_reject",
			fsmMarkerPreAuthDeny,
			responseMarkerFail,
			authLookupOps,
			"rbl",
			attrIsTrue(policy.AttributeRBLThresholdReached),
		),
	}
}

func backendDecisionRules() []standardRule {
	return []standardRule{
		newRule(
			"standard_backend_tempfail",
			policy.StageAuthDecision,
			policy.DecisionTempFail,
			"auth.outcome.backend_tempfail",
			fsmMarkerAuthTempFail,
			responseMarkerTempFail,
			authLookupOps,
			attrIsTrue(policy.AttributeBackendTempFail),
		),
		newRule(
			"standard_empty_username",
			policy.StageAuthDecision,
			policy.DecisionTempFail,
			"auth.outcome.empty_username",
			fsmMarkerAuthEmptyUser,
			responseMarkerTempFail,
			authLookupOps,
			attrIsTrue(policy.AttributeBackendEmptyUsername),
		),
		newRule(
			"standard_empty_password",
			policy.StageAuthDecision,
			policy.DecisionDeny,
			"auth.outcome.empty_password",
			fsmMarkerAuthEmptyPass,
			responseMarkerFail,
			authenticateOps,
			attrIsTrue(policy.AttributeBackendEmptyPassword),
		),
	}
}

func authenticateDecisionRules(policyReport *report.DecisionReport) []standardRule {
	rules := append([]standardRule{}, luaFilterRules(policyReport)...)
	rules = append(rules,
		newRule(
			"standard_auth_success",
			policy.StageAuthDecision,
			policy.DecisionPermit,
			"auth.outcome.auth_success",
			fsmMarkerAuthPermit,
			responseMarkerOK,
			authenticateOps,
			attrIsTrue(policy.AttributeAuthenticated),
		),
		newRule(
			"standard_auth_failure",
			policy.StageAuthDecision,
			policy.DecisionDeny,
			"auth.outcome.auth_failure",
			fsmMarkerAuthDeny,
			responseMarkerFail,
			authenticateOps,
			attrIsFalse(policy.AttributeAuthenticated),
		),
	)

	return rules
}

func lookupIdentityRules() []standardRule {
	lookupOps := []policy.Operation{policy.OperationLookupIdentity}

	return []standardRule{
		newRule(
			"standard_lookup_identity_success",
			policy.StageAuthDecision,
			policy.DecisionPermit,
			"auth.outcome.lookup_identity_success",
			fsmMarkerAuthPermit,
			responseMarkerOK,
			lookupOps,
			attrIsTrue(policy.AttributeIdentityFound),
		),
		newRule(
			"standard_lookup_identity_failure",
			policy.StageAuthDecision,
			policy.DecisionDeny,
			"auth.outcome.lookup_identity_failure",
			fsmMarkerAuthDeny,
			responseMarkerFail,
			lookupOps,
			attrIsFalse(policy.AttributeIdentityFound),
		),
	}
}

func listAccountRules() []standardRule {
	listOps := []policy.Operation{policy.OperationListAccounts}

	return []standardRule{
		accountRule("standard_list_accounts_tempfail", policy.DecisionTempFail, "auth.outcome.list_accounts_tempfail",
			fsmMarkerAuthTempFail, responseMarkerTempFail, listOps, attrIsTrue(policy.AttributeAccountProviderTempFail)),
		accountRule("standard_list_accounts_success", policy.DecisionPermit, "auth.outcome.list_accounts_success",
			fsmMarkerAuthPermit, responseMarkerListAccountsOK, listOps, attrIsTrue(policy.AttributeAccountProviderCompleted)),
		accountRule("standard_list_accounts_failure", policy.DecisionDeny, "auth.outcome.list_accounts_failure",
			fsmMarkerAuthDeny, responseMarkerFail, listOps, attrIsFalse(policy.AttributeAccountProviderCompleted)),
	}
}

func accountRule(
	name string,
	effect policy.Decision,
	outcomeMarker string,
	fsmMarker string,
	responseMarker string,
	operations []policy.Operation,
	condition func(*report.DecisionReport) bool,
) standardRule {
	return ruleWithCheck(
		name,
		policy.StageAuthDecision,
		effect,
		outcomeMarker,
		fsmMarker,
		responseMarker,
		operations,
		"account_provider",
		condition,
	)
}

func newRule(
	name string,
	stage policy.Stage,
	effect policy.Decision,
	outcomeMarker string,
	fsmMarker string,
	responseMarker string,
	operations []policy.Operation,
	condition func(*report.DecisionReport) bool,
) standardRule {
	return standardRule{
		name:           name,
		stage:          stage,
		effect:         effect,
		outcomeMarker:  outcomeMarker,
		fsmMarker:      fsmMarker,
		responseMarker: responseMarker,
		operations:     operations,
		condition:      condition,
	}
}

func ruleWithCheck(
	name string,
	stage policy.Stage,
	effect policy.Decision,
	outcomeMarker string,
	fsmMarker string,
	responseMarker string,
	operations []policy.Operation,
	checkName string,
	condition func(*report.DecisionReport) bool,
) standardRule {
	rule := newRule(name, stage, effect, outcomeMarker, fsmMarker, responseMarker, operations, condition)
	rule.requiredChecks = []string{checkName}

	return rule
}

func unknownRelayDomain(policyReport *report.DecisionReport) bool {
	return attrBool(policyReport, policy.AttributeRelayDomainPresent, true) &&
		attrBool(policyReport, policy.AttributeRelayDomainKnown, false)
}

func luaControlRules(policyReport *report.DecisionReport) []standardRule {
	rules := make([]standardRule, 0)
	for _, checkResult := range sortedChecks(policyReport, policy.CheckTypeLuaControl) {
		name := strings.TrimPrefix(checkResult.Name, "lua_control_")
		if name == "" {
			continue
		}

		prefix := "auth.lua.control." + name
		rules = append(rules,
			standardRule{
				name:           "standard_lua_control_" + name + "_error",
				stage:          policy.StagePreAuth,
				effect:         policy.DecisionTempFail,
				outcomeMarker:  "auth.outcome.lua_control." + name + ".error",
				fsmMarker:      fsmMarkerPreAuthTempFail,
				responseMarker: responseMarkerTempFail,
				operations:     []policy.Operation{policy.OperationAuthenticate},
				requiredChecks: []string{checkResult.Name},
				condition:      attrIsTrue(prefix + ".error"),
			},
			standardRule{
				name:            "standard_lua_control_" + name + "_trigger",
				stage:           policy.StagePreAuth,
				effect:          policy.DecisionDeny,
				outcomeMarker:   "auth.outcome.lua_control." + name + ".reject",
				fsmMarker:       fsmMarkerPreAuthDeny,
				responseMarker:  responseMarkerFail,
				operations:      []policy.Operation{policy.OperationAuthenticate},
				requiredChecks:  []string{checkResult.Name},
				condition:       attrIsTrue(prefix + ".triggered"),
				messageSelector: attributeMessage(prefix+".triggered", definitions.PasswordFail),
			},
			standardRule{
				name:           "standard_lua_control_" + name + "_abort",
				stage:          policy.StagePreAuth,
				effect:         policy.DecisionNeutral,
				outcomeMarker:  "auth.outcome.pre_auth_ok",
				fsmMarker:      fsmMarkerPreAuthOK,
				operations:     []policy.Operation{policy.OperationAuthenticate},
				requiredChecks: []string{checkResult.Name},
				condition:      attrIsTrue(prefix + ".abort"),
				control: &report.DecisionControl{
					SkipRemainingStageChecks: true,
				},
			},
		)
	}

	return rules
}

func luaFilterRules(policyReport *report.DecisionReport) []standardRule {
	rules := make([]standardRule, 0)
	for _, checkResult := range sortedChecks(policyReport, policy.CheckTypeLuaFilter) {
		name := strings.TrimPrefix(checkResult.Name, "lua_filter_")
		if name == "" {
			continue
		}

		prefix := "auth.lua.filter." + name
		rules = append(rules,
			standardRule{
				name:           "standard_lua_filter_" + name + "_error",
				stage:          policy.StageAuthDecision,
				effect:         policy.DecisionTempFail,
				outcomeMarker:  "auth.outcome.lua_filter." + name + ".error",
				fsmMarker:      fsmMarkerAuthTempFail,
				responseMarker: responseMarkerTempFail,
				operations:     []policy.Operation{policy.OperationAuthenticate},
				requiredChecks: []string{checkResult.Name},
				condition:      attrIsTrue(prefix + ".error"),
			},
			standardRule{
				name:            "standard_lua_filter_" + name + "_reject",
				stage:           policy.StageAuthDecision,
				effect:          policy.DecisionDeny,
				outcomeMarker:   "auth.outcome.lua_filter." + name + ".reject",
				fsmMarker:       fsmMarkerAuthDeny,
				responseMarker:  responseMarkerFail,
				operations:      []policy.Operation{policy.OperationAuthenticate},
				requiredChecks:  []string{checkResult.Name},
				condition:       attrIsTrue(prefix + ".rejected"),
				messageSelector: attributeMessage(prefix+".rejected", definitions.PasswordFail),
			},
		)
	}

	return rules
}

func defaultDenyRule() standardRule {
	return standardRule{
		name:           "standard_default_deny",
		stage:          policy.StageAuthDecision,
		effect:         policy.DecisionDeny,
		outcomeMarker:  "auth.outcome.default_deny",
		fsmMarker:      fsmMarkerAuthDeny,
		responseMarker: responseMarkerFail,
		operations:     allOps,
		condition:      func(*report.DecisionReport) bool { return true },
	}
}

func (r standardRule) applies(policyReport *report.DecisionReport, operation policy.Operation) bool {
	if !operationApplies(r.operations, operation) {
		return false
	}

	if !checksAvailable(policyReport, r.requiredChecks) {
		return false
	}

	return r.condition == nil || r.condition(policyReport)
}

func (r standardRule) selectDecision(policyReport *report.DecisionReport) report.PolicyDecision {
	responseMessage := defaultResponseMessage(r.responseMarker)
	if r.messageSelector != nil {
		responseMessage = r.messageSelector(policyReport, r.responseMarker)
	}

	return report.PolicyDecision{
		Name:            r.name,
		Stage:           r.stage,
		Effect:          r.effect,
		Reason:          r.reason,
		OutcomeMarker:   r.outcomeMarker,
		FSMEventMarker:  r.fsmMarker,
		ResponseMarker:  r.responseMarker,
		ResponseMessage: responseMessage,
		Control:         cloneDecisionControl(r.control),
		Obligations:     cloneEffectRequests(r.obligations),
		Advice:          cloneEffectRequests(r.advice),
	}
}

func finalDecisionFromPolicy(d report.PolicyDecision) *report.FinalDecision {
	return &report.FinalDecision{
		PolicyName:      d.Name,
		Stage:           d.Stage,
		Effect:          d.Effect,
		Reason:          d.Reason,
		OutcomeMarker:   d.OutcomeMarker,
		FSMEventMarker:  d.FSMEventMarker,
		ResponseMarker:  d.ResponseMarker,
		ResponseMessage: cloneResponseMessage(d.ResponseMessage),
		Control:         cloneDecisionControl(d.Control),
		Obligations:     cloneEffectRequests(d.Obligations),
		Advice:          cloneEffectRequests(d.Advice),
	}
}

func appendDecision(policyReport *report.DecisionReport, decision report.PolicyDecision) {
	policyReport.Policies = append(policyReport.Policies, decision)
	policyReport.Stage = decision.Stage
	final := finalDecisionFromPolicy(decision)
	if final.Effect != policy.DecisionNeutral {
		policyReport.Final = final
	}
}

func isTerminal(decision *report.FinalDecision) bool {
	if decision == nil {
		return false
	}

	return decision.Effect == policy.DecisionDeny || decision.Effect == policy.DecisionTempFail || decision.Effect == policy.DecisionPermit
}

func attrIsTrue(id string) func(*report.DecisionReport) bool {
	return func(policyReport *report.DecisionReport) bool {
		return attrBool(policyReport, id, true)
	}
}

func attrIsFalse(id string) func(*report.DecisionReport) bool {
	return func(policyReport *report.DecisionReport) bool {
		return attrBool(policyReport, id, false)
	}
}

func attrBool(policyReport *report.DecisionReport, id string, expected bool) bool {
	if policyReport == nil {
		return false
	}

	value, ok := policyReport.Attributes[id]
	if !ok {
		return false
	}

	boolValue, ok := value.Value.(bool)

	return ok && boolValue == expected
}

func checksAvailable(policyReport *report.DecisionReport, names []string) bool {
	for _, name := range names {
		checkResult, ok := policyReport.Checks[name]
		if !ok {
			return false
		}

		if checkResult.Status != policy.CheckStatusOK && checkResult.Status != policy.CheckStatusError {
			return false
		}
	}

	return true
}

func operationApplies(operations []policy.Operation, operation policy.Operation) bool {
	for _, candidate := range operations {
		if candidate == operation {
			return true
		}
	}

	return false
}

func sortedChecks(policyReport *report.DecisionReport, checkType string) []report.CheckResult {
	if policyReport == nil {
		return nil
	}

	checks := make([]report.CheckResult, 0)
	for _, checkResult := range policyReport.Checks {
		if checkResult.Type == checkType {
			checks = append(checks, checkResult)
		}
	}

	sort.SliceStable(checks, func(left int, right int) bool {
		return checks[left].Name < checks[right].Name
	})

	return checks
}

func attributeMessage(attributeID string, fallback string) func(*report.DecisionReport, string) *report.ResponseMessageSelection {
	return func(policyReport *report.DecisionReport, responseMarker string) *report.ResponseMessageSelection {
		attributeValue, ok := policyReport.Attributes[attributeID]
		if ok {
			if detail, detailOK := attributeValue.Details["status_message"]; detailOK {
				if detail.Sensitivity == report.SensitivityPublic && detail.Purpose == report.PurposeResponseMessage {
					if value, stringOK := detail.Value.(string); stringOK && strings.TrimSpace(value) != "" {
						detail.Selected = true
						attributeValue.Details["status_message"] = detail
						policyReport.Attributes[attributeID] = attributeValue

						return &report.ResponseMessageSelection{
							Source:      "attribute_detail",
							Message:     sanitizeResponseMessage(value, maxSelectedResponseMessageLength),
							AttributeID: attributeID,
							Detail:      "status_message",
						}
					}
				}
			}
		}

		if fallback != "" {
			return &report.ResponseMessageSelection{
				Source:       "attribute_detail",
				Message:      sanitizeResponseMessage(fallback, maxSelectedResponseMessageLength),
				AttributeID:  attributeID,
				Detail:       "status_message",
				Fallback:     fallback,
				FallbackUsed: true,
			}
		}

		return defaultResponseMessage(responseMarker)
	}
}

func defaultResponseMessage(responseMarker string) *report.ResponseMessageSelection {
	message := ""
	switch responseMarker {
	case responseMarkerFail:
		message = definitions.PasswordFail
	case responseMarkerTempFail:
		message = definitions.TempFailDefault
	case responseMarkerNoTLS:
		message = definitions.TempFailNoTLS
	}

	if message == "" {
		return nil
	}

	return &report.ResponseMessageSelection{
		Source:  "response_marker",
		Message: message,
	}
}

func sanitizeResponseMessage(message string, maxLength int) string {
	if maxLength <= 0 {
		maxLength = maxSelectedResponseMessageLength
	}

	builder := strings.Builder{}
	for _, r := range message {
		if r == '\n' || r == '\r' || r == 0 {
			continue
		}

		if unicode.IsControl(r) && r != '\t' {
			continue
		}

		builder.WriteRune(r)
		if builder.Len() >= maxLength {
			break
		}
	}

	return builder.String()
}

func obligationsMatch(left []report.EffectRequest, right []report.EffectRequest) bool {
	return reflect.DeepEqual(left, right)
}

func observeResult(mismatch bool) observability.Result {
	if mismatch {
		return observability.ResultFailure
	}

	return observability.ResultSuccess
}

func cloneFinal(decision *report.FinalDecision) *report.FinalDecision {
	if decision == nil {
		return nil
	}

	cloned := *decision
	cloned.ResponseMessage = cloneResponseMessage(decision.ResponseMessage)
	cloned.Control = cloneDecisionControl(decision.Control)
	cloned.Obligations = cloneEffectRequests(decision.Obligations)
	cloned.Advice = cloneEffectRequests(decision.Advice)

	return &cloned
}

func cloneResponseMessage(message *report.ResponseMessageSelection) *report.ResponseMessageSelection {
	if message == nil {
		return nil
	}

	cloned := *message

	return &cloned
}

func cloneDecisionControl(control *report.DecisionControl) *report.DecisionControl {
	if control == nil {
		return nil
	}

	cloned := *control

	return &cloned
}

func cloneEffectRequests(requests []report.EffectRequest) []report.EffectRequest {
	cloned := append([]report.EffectRequest(nil), requests...)
	for index := range cloned {
		if cloned[index].Args == nil {
			continue
		}

		args := make(map[string]any, len(cloned[index].Args))
		for key, value := range cloned[index].Args {
			args[key] = value
		}

		cloned[index].Args = args
	}

	return cloned
}
