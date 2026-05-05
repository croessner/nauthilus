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
)

type standardDecisionCase struct {
	report             *report.DecisionReport
	name               string
	wantPolicy         string
	wantEffect         policy.Decision
	wantFSMMarker      string
	wantResponseMarker string
}

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

type recordingRecorder struct {
	decisions   []observability.DecisionMeasurement
	comparisons []observability.ObserveMeasurement
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
