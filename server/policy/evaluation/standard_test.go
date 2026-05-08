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

//nolint:goconst
package evaluation

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/server/policy"
	"github.com/croessner/nauthilus/server/policy/observability"
	"github.com/croessner/nauthilus/server/policy/report"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"
)

const (
	testI18NResponseKey      = "auth.policy.company.account_blocked"
	testI18NResponseFallback = "Login failed because the account is locked."
	testPreferredLanguage    = "lua.company.preferred_language"
	testFallbackLanguage     = "en"
)

type standardDecisionCase struct {
	report             *report.DecisionReport
	name               string
	wantPolicy         string
	wantEffect         policy.Decision
	wantFSMMarker      string
	wantResponseMarker string
}

const customTLSDenyPolicyName = "custom_deny_tls"

func TestStandardAuthSelectsMappedDecision(t *testing.T) {
	for _, testCase := range standardDecisionCases() {
		t.Run(testCase.name, func(t *testing.T) {
			got := EvaluateStandardAuth(testCase.report)
			if got.Final == nil {
				t.Fatal("final decision is nil")
			}

			if got.Final.PolicyName != testCase.wantPolicy {
				t.Fatalf("policy = %q, want %q", got.Final.PolicyName, testCase.wantPolicy)
			}

			if got.Final.Effect != testCase.wantEffect {
				t.Fatalf("effect = %q, want %q", got.Final.Effect, testCase.wantEffect)
			}

			if got.Final.FSMEventMarker != testCase.wantFSMMarker {
				t.Fatalf("FSM marker = %q, want %q", got.Final.FSMEventMarker, testCase.wantFSMMarker)
			}

			if got.Final.ResponseMarker != testCase.wantResponseMarker {
				t.Fatalf("response marker = %q, want %q", got.Final.ResponseMarker, testCase.wantResponseMarker)
			}
		})
	}
}

func TestStandardPreAuthEvaluationDoesNotSelectFinalDefaultDeny(t *testing.T) {
	policyReport := standardReport(
		policy.OperationAuthenticate,
		check("tls_encryption", policy.CheckTypeTLSEncryption, policy.StagePreAuth, policy.CheckStatusOK),
		boolAttr(policy.AttributeTLSSecure, policy.StagePreAuth, policy.OperationAuthenticate, true, nil),
	)

	got := EvaluateStandardPreAuth(policyReport)
	if got.Final != nil {
		t.Fatalf("final decision = %#v, want nil", got.Final)
	}

	if policyReport.Final != nil {
		t.Fatalf("report final = %#v, want nil", policyReport.Final)
	}

	if len(policyReport.Policies) != 1 {
		t.Fatalf("selected policies = %d, want 1", len(policyReport.Policies))
	}

	if got := policyReport.Policies[0].Name; got != "implicit_pre_auth_pass" {
		t.Fatalf("policy = %q, want implicit pre-auth pass", got)
	}
}

func standardDecisionCases() []standardDecisionCase {
	return []standardDecisionCase{
		bruteForceDecisionCase(),
		tlsDecisionCase(),
		backendSuccessDecisionCase(),
		listAccountsTempFailDecisionCase(),
	}
}

func bruteForceDecisionCase() standardDecisionCase {
	return standardDecisionCase{
		name: "brute force deny stops at pre auth",
		report: standardReport(
			policy.OperationAuthenticate,
			check("brute_force", policy.CheckTypeBruteForce, policy.StagePreAuth, policy.CheckStatusOK),
			boolAttr(policy.AttributeBruteForceTriggered, policy.StagePreAuth, policy.OperationAuthenticate, true, nil),
			boolAttr(policy.AttributeBruteForceError, policy.StagePreAuth, policy.OperationAuthenticate, false, nil),
			boolAttr(policy.AttributeTLSSecure, policy.StagePreAuth, policy.OperationAuthenticate, false, nil),
		),
		wantPolicy:         "standard_brute_force_deny",
		wantEffect:         policy.DecisionDeny,
		wantFSMMarker:      "auth.fsm.event.pre_auth_deny",
		wantResponseMarker: "auth.response.fail",
	}
}

func tlsDecisionCase() standardDecisionCase {
	return standardDecisionCase{
		name: "tls failure maps to no tls tempfail",
		report: standardReport(
			policy.OperationAuthenticate,
			check("tls_encryption", policy.CheckTypeTLSEncryption, policy.StagePreAuth, policy.CheckStatusOK),
			boolAttr(policy.AttributeBruteForceTriggered, policy.StagePreAuth, policy.OperationAuthenticate, false, nil),
			boolAttr(policy.AttributeTLSSecure, policy.StagePreAuth, policy.OperationAuthenticate, false, nil),
		),
		wantPolicy:         "standard_tls_enforcement",
		wantEffect:         policy.DecisionTempFail,
		wantFSMMarker:      "auth.fsm.event.pre_auth_tempfail",
		wantResponseMarker: "auth.response.tempfail.no_tls",
	}
}

func backendSuccessDecisionCase() standardDecisionCase {
	return standardDecisionCase{
		name: "authenticated backend permits final decision",
		report: standardReport(
			policy.OperationAuthenticate,
			check("ldap_backend", policy.CheckTypeLDAPBackend, policy.StageAuthBackend, policy.CheckStatusOK),
			boolAttr(policy.AttributeAuthenticated, policy.StageAuthBackend, policy.OperationAuthenticate, true, nil),
		),
		wantPolicy:         "standard_auth_success",
		wantEffect:         policy.DecisionPermit,
		wantFSMMarker:      "auth.fsm.event.auth_permit",
		wantResponseMarker: "auth.response.ok",
	}
}

func listAccountsTempFailDecisionCase() standardDecisionCase {
	return standardDecisionCase{
		name: "list account provider tempfail wins before completion",
		report: standardReport(
			policy.OperationListAccounts,
			check("account_provider", policy.CheckTypeAccountProvider, policy.StageAccountProvider, policy.CheckStatusError),
			boolAttr(policy.AttributeAccountProviderTempFail, policy.StageAccountProvider, policy.OperationListAccounts, true, nil),
			boolAttr(policy.AttributeAccountProviderCompleted, policy.StageAccountProvider, policy.OperationListAccounts, true, nil),
		),
		wantPolicy:         "standard_list_accounts_tempfail",
		wantEffect:         policy.DecisionTempFail,
		wantFSMMarker:      "auth.fsm.event.auth_tempfail",
		wantResponseMarker: "auth.response.tempfail",
	}
}

func TestStandardAuthSelectsLuaStatusMessageAndPlannedObligations(t *testing.T) {
	details := map[string]report.DetailValue{
		"status_message": {
			Value:       "Denied by Lua",
			Sensitivity: report.SensitivityPublic,
			Purpose:     report.PurposeResponseMessage,
		},
	}
	luaReport := standardReport(
		policy.OperationAuthenticate,
		check("lua_environment_risk", policy.CheckTypeLuaEnvironment, policy.StagePreAuth, policy.CheckStatusOK),
		boolAttr("auth.lua.environment.risk.triggered", policy.StagePreAuth, policy.OperationAuthenticate, true, details),
	)

	got := EvaluateStandardAuth(luaReport)
	if got.Final == nil {
		t.Fatal("final decision is nil")
	}

	if got.Final.ResponseMessage == nil || got.Final.ResponseMessage.Message != "Denied by Lua" {
		t.Fatalf("response message = %#v, want Lua detail", got.Final.ResponseMessage)
	}

	if !luaReport.Attributes["auth.lua.environment.risk.triggered"].Details["status_message"].Selected {
		t.Fatal("selected Lua response detail was not marked for redaction")
	}

	subjectReport := standardReport(
		policy.OperationAuthenticate,
		check("lua_subject_billing", policy.CheckTypeLuaSubjectSource, policy.StageSubjectAnalysis, policy.CheckStatusOK),
		boolAttr("auth.lua.subject.billing.rejected", policy.StageSubjectAnalysis, policy.OperationAuthenticate, true, map[string]report.DetailValue{
			"status_message": {
				Value:       "Rejected by Lua subject",
				Sensitivity: report.SensitivityPublic,
				Purpose:     report.PurposeResponseMessage,
			},
		}),
	)

	got = EvaluateStandardAuth(subjectReport)
	if got.Final == nil {
		t.Fatal("final decision is nil")
	}

	if got.Final.PolicyName != "standard_lua_subject_billing_reject" {
		t.Fatalf("policy = %q, want standard_lua_subject_billing_reject", got.Final.PolicyName)
	}

	if got.Final.ResponseMessage == nil || got.Final.ResponseMessage.Message != "Rejected by Lua subject" {
		t.Fatalf("subject response message = %#v, want Lua detail", got.Final.ResponseMessage)
	}

	if !subjectReport.Attributes["auth.lua.subject.billing.rejected"].Details["status_message"].Selected {
		t.Fatal("selected Lua subject response detail was not marked")
	}

	bruteForceReport := standardReport(
		policy.OperationAuthenticate,
		check("brute_force", policy.CheckTypeBruteForce, policy.StagePreAuth, policy.CheckStatusOK),
		boolAttr(policy.AttributeBruteForceTriggered, policy.StagePreAuth, policy.OperationAuthenticate, true, nil),
	)

	got = EvaluateStandardAuth(bruteForceReport)
	if len(got.Final.Obligations) != 3 {
		t.Fatalf("obligations = %d, want 3 planned obligations", len(got.Final.Obligations))
	}

	if got.Final.Obligations[0].ID != "auth.obligation.brute_force.update" {
		t.Fatalf("first obligation = %q, want brute force update", got.Final.Obligations[0].ID)
	}

	if got.Final.Obligations[1].ID != policy.ObligationLuaActionDispatch {
		t.Fatalf("second obligation = %q, want lua action dispatch", got.Final.Obligations[1].ID)
	}

	abortReport := standardReport(
		policy.OperationAuthenticate,
		check("lua_environment_risk", policy.CheckTypeLuaEnvironment, policy.StagePreAuth, policy.CheckStatusOK),
		boolAttr("auth.lua.environment.risk.abort", policy.StagePreAuth, policy.OperationAuthenticate, true, nil),
	)

	got = EvaluateStandardAuth(abortReport)
	if len(abortReport.Policies) == 0 || abortReport.Policies[0].Control == nil ||
		!abortReport.Policies[0].Control.SkipRemainingStageChecks {
		t.Fatalf("abort control = %#v, want skip remaining stage checks", abortReport.Policies)
	}
}

func TestStandardAuthMapsLuaScriptsForLookupIdentity(t *testing.T) {
	controlCheck := check("lua_environment_risk", policy.CheckTypeLuaEnvironment, policy.StagePreAuth, policy.CheckStatusOK)
	controlCheck.Operation = policy.OperationLookupIdentity
	controlReport := standardReport(
		policy.OperationLookupIdentity,
		controlCheck,
		boolAttr("auth.lua.environment.risk.triggered", policy.StagePreAuth, policy.OperationLookupIdentity, true, nil),
	)

	got := EvaluateStandardAuth(controlReport)
	if got.Final == nil {
		t.Fatal("final decision is nil")
	}

	if got.Final.PolicyName != "standard_lua_environment_risk_trigger" {
		t.Fatalf("policy = %q, want standard_lua_environment_risk_trigger", got.Final.PolicyName)
	}

	subjectCheck := check("lua_subject_billing", policy.CheckTypeLuaSubjectSource, policy.StageSubjectAnalysis, policy.CheckStatusOK)
	subjectCheck.Operation = policy.OperationLookupIdentity
	subjectReport := standardReport(
		policy.OperationLookupIdentity,
		subjectCheck,
		boolAttr("auth.lua.subject.billing.rejected", policy.StageSubjectAnalysis, policy.OperationLookupIdentity, true, nil),
	)

	got = EvaluateStandardAuth(subjectReport)
	if got.Final == nil {
		t.Fatal("final decision is nil")
	}

	if got.Final.PolicyName != "standard_lua_subject_billing_reject" {
		t.Fatalf("policy = %q, want standard_lua_subject_billing_reject", got.Final.PolicyName)
	}
}

func TestStandardAuthMapsLuaScriptsFromEmittedAttributes(t *testing.T) {
	controlCheck := check("geoip_policy_gate", policy.CheckTypeLuaEnvironment, policy.StagePreAuth, policy.CheckStatusOK)
	controlCheck.Attributes = []string{"auth.lua.environment.geoip.triggered"}
	controlReport := standardReport(
		policy.OperationAuthenticate,
		controlCheck,
		boolAttr("auth.lua.environment.geoip.triggered", policy.StagePreAuth, policy.OperationAuthenticate, true, nil),
	)

	got := EvaluateStandardAuth(controlReport)
	if got.Final == nil {
		t.Fatal("final decision is nil")
	}

	if got.Final.PolicyName != "standard_lua_environment_geoip_trigger" {
		t.Fatalf("policy = %q, want standard_lua_environment_geoip_trigger", got.Final.PolicyName)
	}

	subjectCheck := check("billing_policy_gate", policy.CheckTypeLuaSubjectSource, policy.StageSubjectAnalysis, policy.CheckStatusOK)
	subjectCheck.Attributes = []string{"auth.lua.subject.billing.rejected"}
	subjectReport := standardReport(
		policy.OperationAuthenticate,
		subjectCheck,
		boolAttr("auth.lua.subject.billing.rejected", policy.StageSubjectAnalysis, policy.OperationAuthenticate, true, nil),
	)

	got = EvaluateStandardAuth(subjectReport)
	if got.Final == nil {
		t.Fatal("final decision is nil")
	}

	if got.Final.PolicyName != "standard_lua_subject_billing_reject" {
		t.Fatalf("policy = %q, want standard_lua_subject_billing_reject", got.Final.PolicyName)
	}
}

func TestCustomObserveComparesConfiguredPolicyWithDefault(t *testing.T) {
	recorder := &recordingRecorder{}
	policyReport := standardReport(
		policy.OperationAuthenticate,
		check("ldap_backend", policy.CheckTypeLDAPBackend, policy.StageAuthBackend, policy.CheckStatusOK),
		boolAttr(policy.AttributeAuthenticated, policy.StageAuthBackend, policy.OperationAuthenticate, true, nil),
	)
	snapshot := observeSnapshotWithCustomDecision(customAuthDecisionPolicy(
		"custom_deny_success",
		policy.DecisionDeny,
		policy.FSMEventMarkerAuthDeny,
		policy.ResponseMarkerFail,
	))

	got := CompareCustomObserve(context.Background(), snapshot, policyReport, CompareInput{
		Mode:       "observe",
		Set:        policy.BuiltinDefaultSet,
		Generation: 12,
		Recorder:   recorder,
	})

	if !got.Mismatch {
		t.Fatal("mismatch = false, want true")
	}

	if got.Production == nil || got.Production.PolicyName != "standard_auth_success" {
		t.Fatalf("production = %#v, want standard auth success", got.Production)
	}

	if got.Shadow == nil || got.Shadow.PolicyName != "custom_deny_success" {
		t.Fatalf("shadow = %#v, want custom deny", got.Shadow)
	}

	if policyReport.Final == nil || policyReport.Final.PolicyName != "standard_auth_success" {
		t.Fatalf("final = %#v, want authoritative default", policyReport.Final)
	}

	if policyReport.Observe == nil || policyReport.Observe.ProductionTerminalState != "auth_ok" ||
		policyReport.Observe.ShadowTerminalState != "auth_fail" {
		t.Fatalf("observe terminal states = %#v, want default auth_ok and custom auth_fail", policyReport.Observe)
	}

	if len(recorder.comparisons) != 1 || recorder.comparisons[0].Result != observability.ResultFailure {
		t.Fatalf("comparison metrics = %#v, want one failure", recorder.comparisons)
	}
}

func TestCustomObserveReportsUnsafeCustomOnlyCheckUnavailable(t *testing.T) {
	recorder := &recordingRecorder{}
	policyReport := standardReport(
		policy.OperationAuthenticate,
		check("ldap_backend", policy.CheckTypeLDAPBackend, policy.StageAuthBackend, policy.CheckStatusOK),
		boolAttr(policy.AttributeAuthenticated, policy.StageAuthBackend, policy.OperationAuthenticate, true, nil),
	)
	snapshot := observeSnapshotWithUnavailableCheck()

	got := CompareCustomObserve(context.Background(), snapshot, policyReport, CompareInput{
		Mode:       "observe",
		Set:        policy.BuiltinDefaultSet,
		Generation: 13,
		Recorder:   recorder,
	})

	if !got.Mismatch {
		t.Fatal("mismatch = false, want default-vs-custom mismatch")
	}

	if got := policyReport.Unavailable["lua_environment_risk"].Reason; got != "not_observe_safe" {
		t.Fatalf("unavailable reason = %q, want not_observe_safe", got)
	}

	if len(recorder.unavailable) != 1 {
		t.Fatalf("unavailable metrics = %d, want 1", len(recorder.unavailable))
	}

	if recorder.unavailable[0].Check != "lua_environment_risk" {
		t.Fatalf("unavailable check = %q, want lua_environment_risk", recorder.unavailable[0].Check)
	}
}

func TestConfiguredPreAuthEnforceSelectsConfiguredDecision(t *testing.T) {
	recorder := &recordingRecorder{}
	policyReport := standardReport(
		policy.OperationAuthenticate,
		check("tls_encryption", policy.CheckTypeTLSEncryption, policy.StagePreAuth, policy.CheckStatusOK),
		boolAttr(policy.AttributeTLSSecure, policy.StagePreAuth, policy.OperationAuthenticate, false, nil),
	)
	snapshot := enforceSnapshotWithCustomPreAuth(customPreAuthPolicy(
		customTLSDenyPolicyName,
		policy.DecisionDeny,
		policy.FSMEventMarkerPreAuthDeny,
		policy.ResponseMarkerFail,
	))

	got := EvaluateConfiguredPreAuth(context.Background(), snapshot, policyReport, CompareInput{
		Mode:       "enforce",
		Set:        policy.BuiltinDefaultSet,
		Generation: 21,
		Recorder:   recorder,
	})
	if got.Final == nil {
		t.Fatal("final decision is nil")
	}

	if got.Final.PolicyName != customTLSDenyPolicyName {
		t.Fatalf("policy = %q, want %s", got.Final.PolicyName, customTLSDenyPolicyName)
	}

	if got.Final.Effect != policy.DecisionDeny {
		t.Fatalf("effect = %q, want deny", got.Final.Effect)
	}

	if policyReport.Final == nil || policyReport.Final.PolicyName != customTLSDenyPolicyName {
		t.Fatalf("report final = %#v, want configured decision", policyReport.Final)
	}

	if len(policyReport.Policies) != 1 || policyReport.Policies[0].Name != customTLSDenyPolicyName {
		t.Fatalf("selected policies = %#v, want configured policy", policyReport.Policies)
	}

	if len(recorder.decisions) != 1 {
		t.Fatalf("decision metrics = %d, want 1", len(recorder.decisions))
	}
}

func TestConfiguredPreAuthEnforceDoesNotSelectFinalDefaultDeny(t *testing.T) {
	policyReport := standardReport(
		policy.OperationAuthenticate,
		check("tls_encryption", policy.CheckTypeTLSEncryption, policy.StagePreAuth, policy.CheckStatusOK),
		boolAttr(policy.AttributeTLSSecure, policy.StagePreAuth, policy.OperationAuthenticate, false, nil),
	)
	snapshot := enforceSnapshotWithCustomPreAuth(customPreAuthPolicy(
		"custom_no_tls_match",
		policy.DecisionDeny,
		policy.FSMEventMarkerPreAuthDeny,
		policy.ResponseMarkerFail,
	))
	stagePlan := snapshot.StagePlans[policy.OperationAuthenticate][policy.StagePreAuth]
	stagePlan.Policies[0].Root.Expected = policyruntime.TypedValue{Value: true}
	snapshot.StagePlans[policy.OperationAuthenticate][policy.StagePreAuth] = stagePlan

	got := EvaluateConfiguredPreAuth(context.Background(), snapshot, policyReport, CompareInput{
		Mode:       "enforce",
		Set:        policy.BuiltinDefaultSet,
		Generation: 22,
	})
	if got.Final != nil {
		t.Fatalf("final decision = %#v, want nil", got.Final)
	}

	if policyReport.Final != nil {
		t.Fatalf("report final = %#v, want nil", policyReport.Final)
	}
}

func TestConfiguredPreAuthSkippedRequiredCheckIsNonApplicable(t *testing.T) {
	recorder := &recordingRecorder{}
	policyReport := standardReport(
		policy.OperationAuthenticate,
		check("tls_encryption", policy.CheckTypeTLSEncryption, policy.StagePreAuth, policy.CheckStatusSkipped),
		boolAttr(policy.AttributeTLSSecure, policy.StagePreAuth, policy.OperationAuthenticate, false, nil),
	)
	policyReport.Checks["tls_encryption"] = report.CheckResult{
		Name:      "tls_encryption",
		Type:      policy.CheckTypeTLSEncryption,
		Stage:     policy.StagePreAuth,
		Operation: policy.OperationAuthenticate,
		Status:    policy.CheckStatusSkipped,
		Reason:    "scheduler_guard:insecure_connection",
	}

	first := customPreAuthPolicy(
		"custom_requires_skipped_tls",
		policy.DecisionDeny,
		policy.FSMEventMarkerPreAuthDeny,
		policy.ResponseMarkerFail,
	)
	later := customPreAuthPolicy(
		"custom_later_tls_rule",
		policy.DecisionDeny,
		policy.FSMEventMarkerPreAuthDeny,
		policy.ResponseMarkerFail,
	)
	later.RequireChecks = nil

	snapshot := enforceSnapshotWithCustomPreAuth(first)
	stagePlan := snapshot.StagePlans[policy.OperationAuthenticate][policy.StagePreAuth]
	stagePlan.Policies = []policyruntime.CompiledPolicy{first, later}
	snapshot.StagePlans[policy.OperationAuthenticate][policy.StagePreAuth] = stagePlan

	got := EvaluateConfiguredPreAuth(context.Background(), snapshot, policyReport, CompareInput{
		Mode:       "enforce",
		Set:        policy.BuiltinDefaultSet,
		Generation: 23,
		Recorder:   recorder,
	})
	if got.Final == nil {
		t.Fatal("final decision is nil")
	}

	if got.Final.PolicyName != "custom_later_tls_rule" {
		t.Fatalf("policy = %q, want custom_later_tls_rule", got.Final.PolicyName)
	}

	if len(policyReport.Policies) != 1 || policyReport.Policies[0].Name != "custom_later_tls_rule" {
		t.Fatalf("selected policies = %#v, want only later policy", policyReport.Policies)
	}

	if len(recorder.requireChecks) != 1 {
		t.Fatalf("require-check metrics = %d, want 1", len(recorder.requireChecks))
	}

	if got := recorder.requireChecks[0].Result; got != "skipped" {
		t.Fatalf("require-check result = %q, want skipped", got)
	}
}

func TestConfiguredAuthEnforceSelectsBackendDecision(t *testing.T) {
	recorder := &recordingRecorder{}
	policyReport := standardReport(
		policy.OperationAuthenticate,
		check("ldap_backend", policy.CheckTypeLDAPBackend, policy.StageAuthBackend, policy.CheckStatusOK),
		boolAttr(policy.AttributeAuthenticated, policy.StageAuthBackend, policy.OperationAuthenticate, true, nil),
	)
	snapshot := enforceSnapshotWithCustomAuth(customAuthDecisionPolicy(
		"custom_deny_authenticated_user",
		policy.DecisionDeny,
		policy.FSMEventMarkerAuthDeny,
		policy.ResponseMarkerFail,
	))

	got := EvaluateConfiguredAuth(context.Background(), snapshot, policyReport, CompareInput{
		Mode:       "enforce",
		Set:        policy.BuiltinDefaultSet,
		Generation: 31,
		Recorder:   recorder,
	})
	if got.Final == nil {
		t.Fatal("final decision is nil")
	}

	if got.Final.PolicyName != "custom_deny_authenticated_user" {
		t.Fatalf("policy = %q, want custom_deny_authenticated_user", got.Final.PolicyName)
	}

	if got.Final.Effect != policy.DecisionDeny {
		t.Fatalf("effect = %q, want deny", got.Final.Effect)
	}

	if policyReport.Final == nil || policyReport.Final.PolicyName != "custom_deny_authenticated_user" {
		t.Fatalf("report final = %#v, want configured auth decision", policyReport.Final)
	}

	if len(recorder.decisions) != 1 {
		t.Fatalf("decision metrics = %d, want 1", len(recorder.decisions))
	}
}

func TestConfiguredAuthEnforceSelectsLuaSubjectSourceStatusMessage(t *testing.T) {
	details := map[string]report.DetailValue{
		"status_message": {
			Value:       "Billing lock",
			Sensitivity: report.SensitivityPublic,
			Purpose:     report.PurposeResponseMessage,
		},
	}
	policyReport := standardReport(
		policy.OperationAuthenticate,
		check("lua_subject_billing", policy.CheckTypeLuaSubjectSource, policy.StageSubjectAnalysis, policy.CheckStatusOK),
		boolAttr("auth.lua.subject.billing.rejected", policy.StageSubjectAnalysis, policy.OperationAuthenticate, true, details),
	)
	snapshot := enforceSnapshotWithCustomAuth(customLuaSubjectSourcePolicy())

	got := EvaluateConfiguredAuth(context.Background(), snapshot, policyReport, CompareInput{
		Mode:       "enforce",
		Set:        policy.BuiltinDefaultSet,
		Generation: 32,
	})
	if got.Final == nil {
		t.Fatal("final decision is nil")
	}

	if got.Final.ResponseMessage == nil || got.Final.ResponseMessage.Message != "Billing lock" {
		t.Fatalf("response message = %#v, want Lua subject detail", got.Final.ResponseMessage)
	}

	if !policyReport.Attributes["auth.lua.subject.billing.rejected"].Details["status_message"].Selected {
		t.Fatal("selected Lua subject response detail was not marked")
	}
}

func TestConfiguredAuthEnforceSelectsI18NMessageAndLiteralLanguage(t *testing.T) {
	policyReport := standardReport(
		policy.OperationAuthenticate,
		check("ldap_backend", policy.CheckTypeLDAPBackend, policy.StageAuthBackend, policy.CheckStatusOK),
		boolAttr(policy.AttributeAuthenticated, policy.StageAuthBackend, policy.OperationAuthenticate, false, nil),
	)
	snapshot := enforceSnapshotWithCustomAuth(customI18NAuthPolicy())

	got := EvaluateConfiguredAuth(context.Background(), snapshot, policyReport, CompareInput{
		Mode:       "enforce",
		Set:        policy.BuiltinDefaultSet,
		Generation: 32,
	})
	if got.Final == nil {
		t.Fatal("final decision is nil")
	}

	if got.Final.ResponseMessage == nil {
		t.Fatal("response message is nil")
	}

	if got.Final.ResponseMessage.I18NKey != testI18NResponseKey {
		t.Fatalf("i18n key = %q, want configured key", got.Final.ResponseMessage.I18NKey)
	}

	if got.Final.ResponseMessage.Message != testI18NResponseFallback {
		t.Fatalf("fallback message = %q, want configured fallback", got.Final.ResponseMessage.Message)
	}

	if got.Final.ResponseLanguage == nil || got.Final.ResponseLanguage.Language != "de" {
		t.Fatalf("response language = %#v, want literal de", got.Final.ResponseLanguage)
	}
}

func TestConfiguredAuthEnforceSelectsAttributeResponseLanguage(t *testing.T) {
	testCases := map[string]responseLanguageCase{
		"valid attribute": {
			attributeValue: new("fr"),
			wantLanguage:   "fr",
		},
		"invalid attribute": {
			attributeValue: new("not a language"),
			wantLanguage:   testFallbackLanguage,
			wantFallback:   true,
		},
		"missing attribute": {
			wantLanguage: testFallbackLanguage,
			wantFallback: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			responseLanguage := evaluateAttributeResponseLanguage(t, testCase.attributeValue)

			if responseLanguage.Source != policy.ResponseSourceAttribute ||
				responseLanguage.AttributeID != testPreferredLanguage ||
				responseLanguage.Language != testCase.wantLanguage ||
				responseLanguage.FallbackUsed != testCase.wantFallback {
				t.Fatalf("response language = %#v, want attribute language %q fallback=%v", responseLanguage, testCase.wantLanguage, testCase.wantFallback)
			}
		})
	}
}

type responseLanguageCase struct {
	attributeValue *string
	wantLanguage   string
	wantFallback   bool
}

func evaluateAttributeResponseLanguage(t *testing.T, attributeValue *string) *report.ResponseLanguageSelection {
	t.Helper()

	attributes := []report.AttributeValue{
		boolAttr(policy.AttributeAuthenticated, policy.StageAuthBackend, policy.OperationAuthenticate, false, nil),
	}
	if attributeValue != nil {
		attributes = append(attributes, stringAttr(testPreferredLanguage, policy.StageAuthBackend, policy.OperationAuthenticate, *attributeValue))
	}

	policyReport := standardReport(
		policy.OperationAuthenticate,
		check("ldap_backend", policy.CheckTypeLDAPBackend, policy.StageAuthBackend, policy.CheckStatusOK),
		attributes...,
	)
	compiled := customI18NAuthPolicy()
	compiled.Then.ResponseLanguage = policyruntime.ResponseLanguagePlan{
		Source:      policy.ResponseSourceAttribute,
		AttributeID: testPreferredLanguage,
		Fallback:    testFallbackLanguage,
	}
	snapshot := enforceSnapshotWithCustomAuth(compiled)

	got := EvaluateConfiguredAuth(context.Background(), snapshot, policyReport, CompareInput{
		Mode:       "enforce",
		Set:        policy.BuiltinDefaultSet,
		Generation: 32,
	})
	if got.Final == nil {
		t.Fatal("final decision is nil")
	}

	if got.Final.ResponseLanguage == nil {
		t.Fatal("response language is nil")
	}

	return got.Final.ResponseLanguage
}

func standardReport(
	operation policy.Operation,
	checkResult report.CheckResult,
	attributes ...report.AttributeValue,
) *report.DecisionReport {
	policyReport := report.NewDecisionReport()
	policyReport.Operation = operation
	if checkResult.Name != "" {
		policyReport.Checks[checkResult.Name] = checkResult
	}

	for _, attribute := range attributes {
		policyReport.Attributes[attribute.ID] = attribute
	}

	return policyReport
}

func check(name string, checkType string, stage policy.Stage, status policy.CheckStatus) report.CheckResult {
	return report.CheckResult{
		Name:      name,
		Type:      checkType,
		Stage:     stage,
		Status:    status,
		Operation: policy.OperationAuthenticate,
	}
}

func boolAttr(
	id string,
	stage policy.Stage,
	operation policy.Operation,
	value bool,
	details map[string]report.DetailValue,
) report.AttributeValue {
	return report.AttributeValue{
		ID:        id,
		Stage:     stage,
		Operation: operation,
		Value:     value,
		Details:   details,
	}
}

func stringAttr(
	id string,
	stage policy.Stage,
	operation policy.Operation,
	value string,
) report.AttributeValue {
	return report.AttributeValue{
		ID:        id,
		Stage:     stage,
		Operation: operation,
		Value:     value,
	}
}

//go:fix inline
func stringPtr(value string) *string {
	return new(value)
}

func observeSnapshotWithCustomDecision(compiled policyruntime.CompiledPolicy) *policyruntime.Snapshot {
	return &policyruntime.Snapshot{
		Mode:          "observe",
		DefaultPolicy: policy.BuiltinDefaultSet,
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationAuthenticate: {
				policy.StageAuthDecision: {
					Stage:    policy.StageAuthDecision,
					Policies: []policyruntime.CompiledPolicy{compiled},
				},
			},
		},
	}
}

func observeSnapshotWithUnavailableCheck() *policyruntime.Snapshot {
	snapshot := observeSnapshotWithCustomDecision(customAuthDecisionPolicy(
		"custom_deny_risk",
		policy.DecisionDeny,
		policy.FSMEventMarkerAuthDeny,
		policy.ResponseMarkerFail,
	))
	snapshot.StagePlans[policy.OperationAuthenticate][policy.StagePreAuth] = policyruntime.CompiledStagePlan{
		Stage: policy.StagePreAuth,
		Checks: []policyruntime.CompiledCheck{
			{
				Name:       "lua_environment_risk",
				Type:       policy.CheckTypeLuaEnvironment,
				Stage:      policy.StagePreAuth,
				Operations: []policy.Operation{policy.OperationAuthenticate},
			},
		},
	}
	snapshot.StagePlans[policy.OperationAuthenticate][policy.StageAuthDecision].Policies[0].RequireChecks = []string{"lua_environment_risk"}

	return snapshot
}

func enforceSnapshotWithCustomPreAuth(compiled policyruntime.CompiledPolicy) *policyruntime.Snapshot {
	return &policyruntime.Snapshot{
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationAuthenticate: {
				policy.StagePreAuth: {
					Stage: policy.StagePreAuth,
					Checks: []policyruntime.CompiledCheck{
						{
							Name:        "tls_encryption",
							Type:        policy.CheckTypeTLSEncryption,
							Stage:       policy.StagePreAuth,
							Operations:  []policy.Operation{policy.OperationAuthenticate},
							RunIf:       policyruntime.RunIfPlan{AuthState: policy.RunIfAny},
							ObserveSafe: true,
						},
					},
					Policies: []policyruntime.CompiledPolicy{compiled},
				},
			},
		},
	}
}

func enforceSnapshotWithCustomAuth(compiled policyruntime.CompiledPolicy) *policyruntime.Snapshot {
	return &policyruntime.Snapshot{
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationAuthenticate: {
				policy.StageAuthDecision: {
					Stage:    policy.StageAuthDecision,
					Policies: []policyruntime.CompiledPolicy{compiled},
				},
			},
		},
	}
}

func customPreAuthPolicy(
	name string,
	decision policy.Decision,
	fsmMarker string,
	responseMarker string,
) policyruntime.CompiledPolicy {
	return policyruntime.CompiledPolicy{
		Name:          name,
		Stage:         policy.StagePreAuth,
		Operations:    []policy.Operation{policy.OperationAuthenticate},
		RequireChecks: []string{"tls_encryption"},
		Root: policyruntime.CompiledExpr{
			Kind:        policyruntime.ExprKindAttribute,
			AttributeID: policy.AttributeTLSSecure,
			Operator:    "is",
			Expected:    policyruntime.TypedValue{Value: false},
		},
		Then: policyruntime.DecisionPlan{
			Decision:       decision,
			OutcomeMarker:  "auth.outcome.custom_tls",
			FSMEventMarker: fsmMarker,
			ResponseMarker: responseMarker,
			ResponseMessage: policyruntime.ResponseMessagePlan{
				Source:  policy.ResponseSourceLiteral,
				Literal: "Custom TLS deny",
			},
		},
	}
}

func customAuthDecisionPolicy(
	name string,
	decision policy.Decision,
	fsmMarker string,
	responseMarker string,
) policyruntime.CompiledPolicy {
	return policyruntime.CompiledPolicy{
		Name:       name,
		Stage:      policy.StageAuthDecision,
		Operations: []policy.Operation{policy.OperationAuthenticate},
		Root: policyruntime.CompiledExpr{
			Kind:        policyruntime.ExprKindAttribute,
			AttributeID: policy.AttributeAuthenticated,
			Operator:    "is",
			Expected:    policyruntime.TypedValue{Value: true},
		},
		Then: policyruntime.DecisionPlan{
			Decision:       decision,
			OutcomeMarker:  "auth.outcome.custom",
			FSMEventMarker: fsmMarker,
			ResponseMarker: responseMarker,
			ResponseMessage: policyruntime.ResponseMessagePlan{
				Source:  policy.ResponseSourceLiteral,
				Literal: "Custom deny",
			},
		},
	}
}

func customLuaSubjectSourcePolicy() policyruntime.CompiledPolicy {
	return policyruntime.CompiledPolicy{
		Name:          "custom_billing_subject_deny",
		Stage:         policy.StageAuthDecision,
		Operations:    []policy.Operation{policy.OperationAuthenticate},
		RequireChecks: []string{"lua_subject_billing"},
		Root: policyruntime.CompiledExpr{
			Kind:        policyruntime.ExprKindAttribute,
			AttributeID: "auth.lua.subject.billing.rejected",
			Operator:    "is",
			Expected:    policyruntime.TypedValue{Value: true},
		},
		Then: policyruntime.DecisionPlan{
			Decision:       policy.DecisionDeny,
			OutcomeMarker:  "auth.outcome.custom_billing",
			FSMEventMarker: policy.FSMEventMarkerAuthDeny,
			ResponseMarker: policy.ResponseMarkerFail,
			ResponseMessage: policyruntime.ResponseMessagePlan{
				Source:      policy.ResponseSourceAttributeDetail,
				AttributeID: "auth.lua.subject.billing.rejected",
				Detail:      "status_message",
				Fallback:    "Invalid login or password",
				MaxLength:   256,
			},
		},
	}
}

func customI18NAuthPolicy() policyruntime.CompiledPolicy {
	compiled := customAuthDecisionPolicy(
		"custom_i18n_backend_deny",
		policy.DecisionDeny,
		policy.FSMEventMarkerAuthDeny,
		policy.ResponseMarkerFail,
	)
	compiled.Root = policyruntime.CompiledExpr{
		Kind:        policyruntime.ExprKindAttribute,
		AttributeID: policy.AttributeAuthenticated,
		Operator:    "is",
		Expected:    policyruntime.TypedValue{Value: false},
	}
	compiled.Then.ResponseMessage = policyruntime.ResponseMessagePlan{
		Source:    policy.ResponseSourceI18N,
		I18NKey:   testI18NResponseKey,
		Fallback:  testI18NResponseFallback,
		MaxLength: 256,
	}
	compiled.Then.ResponseLanguage = policyruntime.ResponseLanguagePlan{
		Source:   policy.ResponseSourceLiteral,
		Language: "de",
	}

	return compiled
}

type recordingRecorder struct {
	decisions     []observability.DecisionMeasurement
	comparisons   []observability.ObserveMeasurement
	requireChecks []observability.RequireCheckMeasurement
	unavailable   []observability.ObserveUnavailableMeasurement
}

func (r *recordingRecorder) RecordSnapshotBuild(context.Context, observability.SnapshotBuildMeasurement) {
}
func (r *recordingRecorder) RecordReloadFailure(context.Context, observability.ReloadFailureMeasurement) {
}
func (r *recordingRecorder) RecordCheck(context.Context, observability.CheckMeasurement)           {}
func (r *recordingRecorder) RecordStageEvaluation(context.Context, observability.StageMeasurement) {}
func (r *recordingRecorder) RecordFSMTransition(context.Context, observability.FSMMeasurement)     {}
func (r *recordingRecorder) RecordResponseRender(context.Context, observability.RendererMeasurement) {
}
func (r *recordingRecorder) RecordObligation(context.Context, observability.ObligationMeasurement) {}
func (r *recordingRecorder) RecordAdvice(context.Context, observability.AdviceMeasurement)         {}

func (r *recordingRecorder) RecordDecision(_ context.Context, measurement observability.DecisionMeasurement) {
	r.decisions = append(r.decisions, measurement)
}

func (r *recordingRecorder) RecordRequireCheck(_ context.Context, measurement observability.RequireCheckMeasurement) {
	r.requireChecks = append(r.requireChecks, measurement)
}

func (r *recordingRecorder) RecordObserveComparison(_ context.Context, measurement observability.ObserveMeasurement) {
	r.comparisons = append(r.comparisons, measurement)
}

func (r *recordingRecorder) RecordObserveUnavailable(_ context.Context, measurement observability.ObserveUnavailableMeasurement) {
	r.unavailable = append(r.unavailable, measurement)
}
