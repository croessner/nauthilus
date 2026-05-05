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

package evaluation

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/server/policy"
	"github.com/croessner/nauthilus/server/policy/observability"
	"github.com/croessner/nauthilus/server/policy/report"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"
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
		check("lua_control_risk", policy.CheckTypeLuaControl, policy.StagePreAuth, policy.CheckStatusOK),
		boolAttr("auth.lua.control.risk.triggered", policy.StagePreAuth, policy.OperationAuthenticate, true, details),
	)

	got := EvaluateStandardAuth(luaReport)
	if got.Final == nil {
		t.Fatal("final decision is nil")
	}

	if got.Final.ResponseMessage == nil || got.Final.ResponseMessage.Message != "Denied by Lua" {
		t.Fatalf("response message = %#v, want Lua detail", got.Final.ResponseMessage)
	}

	if !luaReport.Attributes["auth.lua.control.risk.triggered"].Details["status_message"].Selected {
		t.Fatal("selected Lua response detail was not marked for redaction")
	}

	bruteForceReport := standardReport(
		policy.OperationAuthenticate,
		check("brute_force", policy.CheckTypeBruteForce, policy.StagePreAuth, policy.CheckStatusOK),
		boolAttr(policy.AttributeBruteForceTriggered, policy.StagePreAuth, policy.OperationAuthenticate, true, nil),
	)

	got = EvaluateStandardAuth(bruteForceReport)
	if len(got.Final.Obligations) != 2 {
		t.Fatalf("obligations = %d, want 2 planned obligations", len(got.Final.Obligations))
	}

	if got.Final.Obligations[0].ID != "auth.obligation.brute_force.update" {
		t.Fatalf("first obligation = %q, want brute force update", got.Final.Obligations[0].ID)
	}

	abortReport := standardReport(
		policy.OperationAuthenticate,
		check("lua_control_risk", policy.CheckTypeLuaControl, policy.StagePreAuth, policy.CheckStatusOK),
		boolAttr("auth.lua.control.risk.abort", policy.StagePreAuth, policy.OperationAuthenticate, true, nil),
	)

	got = EvaluateStandardAuth(abortReport)
	if len(abortReport.Policies) == 0 || abortReport.Policies[0].Control == nil ||
		!abortReport.Policies[0].Control.SkipRemainingStageChecks {
		t.Fatalf("abort control = %#v, want skip remaining stage checks", abortReport.Policies)
	}
}

func TestCompareWithProductionReportsMismatch(t *testing.T) {
	recorder := &recordingRecorder{}
	policyReport := standardReport(
		policy.OperationAuthenticate,
		check("ldap_backend", policy.CheckTypeLDAPBackend, policy.StageAuthBackend, policy.CheckStatusOK),
		boolAttr(policy.AttributeAuthenticated, policy.StageAuthBackend, policy.OperationAuthenticate, false, nil),
	)

	got := CompareWithProduction(context.Background(), policyReport, CompareInput{
		Mode:          "enforce",
		Set:           policy.BuiltinDefaultSet,
		Generation:    11,
		Recorder:      recorder,
		Production:    ProductionOutcome{Effect: policy.DecisionPermit, ResponseMarker: "auth.response.ok"},
		ProductionSet: true,
	})

	if !got.Mismatch {
		t.Fatal("mismatch = false, want true")
	}

	if policyReport.Observe == nil || !policyReport.Observe.Mismatch {
		t.Fatalf("observe report = %#v, want mismatch", policyReport.Observe)
	}

	if policyReport.Final == nil || policyReport.Final.PolicyName != "standard_auth_failure" {
		t.Fatalf("final = %#v, want standard auth failure", policyReport.Final)
	}

	if len(recorder.decisions) != 1 {
		t.Fatalf("decision metrics = %d, want 1", len(recorder.decisions))
	}

	if len(recorder.comparisons) != 1 || recorder.comparisons[0].Result != observability.ResultFailure {
		t.Fatalf("comparison metrics = %#v, want one failure", recorder.comparisons)
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

	if got := policyReport.Unavailable["lua_control_risk"].Reason; got != "not_observe_safe" {
		t.Fatalf("unavailable reason = %q, want not_observe_safe", got)
	}

	if len(recorder.unavailable) != 1 {
		t.Fatalf("unavailable metrics = %d, want 1", len(recorder.unavailable))
	}

	if recorder.unavailable[0].Check != "lua_control_risk" {
		t.Fatalf("unavailable check = %q, want lua_control_risk", recorder.unavailable[0].Check)
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
				Name:       "lua_control_risk",
				Type:       policy.CheckTypeLuaControl,
				Stage:      policy.StagePreAuth,
				Operations: []policy.Operation{policy.OperationAuthenticate},
			},
		},
	}
	snapshot.StagePlans[policy.OperationAuthenticate][policy.StageAuthDecision].Policies[0].RequireChecks = []string{"lua_control_risk"}

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
				Source:  "literal",
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
				Source:  "literal",
				Literal: "Custom deny",
			},
		},
	}
}

type recordingRecorder struct {
	decisions   []observability.DecisionMeasurement
	comparisons []observability.ObserveMeasurement
	unavailable []observability.ObserveUnavailableMeasurement
}

func (r *recordingRecorder) RecordSnapshotBuild(context.Context, observability.SnapshotBuildMeasurement) {
}
func (r *recordingRecorder) RecordReloadFailure(context.Context, observability.ReloadFailureMeasurement) {
}
func (r *recordingRecorder) RecordCheck(context.Context, observability.CheckMeasurement)           {}
func (r *recordingRecorder) RecordStageEvaluation(context.Context, observability.StageMeasurement) {}
func (r *recordingRecorder) RecordRequireCheck(context.Context, observability.RequireCheckMeasurement) {
}
func (r *recordingRecorder) RecordFSMTransition(context.Context, observability.FSMMeasurement) {}
func (r *recordingRecorder) RecordResponseRender(context.Context, observability.RendererMeasurement) {
}
func (r *recordingRecorder) RecordObligation(context.Context, observability.ObligationMeasurement) {}
func (r *recordingRecorder) RecordAdvice(context.Context, observability.AdviceMeasurement)         {}

func (r *recordingRecorder) RecordDecision(_ context.Context, measurement observability.DecisionMeasurement) {
	r.decisions = append(r.decisions, measurement)
}

func (r *recordingRecorder) RecordObserveComparison(_ context.Context, measurement observability.ObserveMeasurement) {
	r.comparisons = append(r.comparisons, measurement)
}

func (r *recordingRecorder) RecordObserveUnavailable(_ context.Context, measurement observability.ObserveUnavailableMeasurement) {
	r.unavailable = append(r.unavailable, measurement)
}
