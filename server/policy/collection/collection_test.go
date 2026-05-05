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

package collection

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/server/policy"
	"github.com/croessner/nauthilus/server/policy/observability"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"
)

func TestDecisionContextRecordsCheckResultAndAttributes(t *testing.T) {
	recorder := &recordingRecorder{}
	ctx := NewDecisionContext(testSnapshot(), policy.OperationAuthenticate, recorder)
	check := ctx.BeginCheck(context.Background(), CheckSelector{
		CheckType: policy.CheckTypeTLSEncryption,
		Stage:     policy.StagePreAuth,
		Name:      "tls_encryption",
	})

	check.Finish(CheckResult{
		Matched:      true,
		DecisionHint: policy.DecisionTempFail,
		Attributes: []AttributeValue{
			BoolAttribute("auth.tls.secure", policy.StagePreAuth, policy.OperationAuthenticate, false, nil),
		},
	})

	report := ctx.Report()
	if got := report.Checks["tls_encryption"].Status; got != policy.CheckStatusOK {
		t.Fatalf("check status = %q, want %q", got, policy.CheckStatusOK)
	}

	if got := report.Attributes["auth.tls.secure"].Value; got != false {
		t.Fatalf("tls attribute = %v, want false", got)
	}

	if len(recorder.checks) != 1 {
		t.Fatalf("recorded checks = %d, want 1", len(recorder.checks))
	}

	if got := recorder.checks[0].CheckType; got != policy.CheckTypeTLSEncryption {
		t.Fatalf("metric check type = %q, want %q", got, policy.CheckTypeTLSEncryption)
	}

	if got := recorder.checks[0].Status; got != policy.CheckStatusOK {
		t.Fatalf("metric status = %q, want %q", got, policy.CheckStatusOK)
	}
}

func TestDecisionContextReportsSkippedMissingAndUnavailableFacts(t *testing.T) {
	ctx := NewDecisionContext(testSnapshot(), policy.OperationAuthenticate, nil)
	ctx.MarkUnavailable("lua_control_risk", "not_observe_safe")
	ctx.CompleteStage(policy.StagePreAuth, AuthStateUnauthenticated)

	report := ctx.Report()
	if got := report.Checks["lua_control_auth_only"].Status; got != policy.CheckStatusSkipped {
		t.Fatalf("skipped status = %q, want %q", got, policy.CheckStatusSkipped)
	}

	if got := report.MissingChecks["tls_encryption"]; got != "not_recorded" {
		t.Fatalf("missing tls reason = %q, want not_recorded", got)
	}

	if got := report.Unavailable["lua_control_risk"].Reason; got != "not_observe_safe" {
		t.Fatalf("unavailable reason = %q, want not_observe_safe", got)
	}
}

func TestDecisionContextReportsUnsafeObserveChecksUnavailable(t *testing.T) {
	ctx := NewDecisionContext(testObserveSnapshot(), policy.OperationAuthenticate, nil)
	ctx.CompleteStage(policy.StagePreAuth, AuthStateUnauthenticated)

	report := ctx.Report()
	if got := report.Unavailable["lua_control_risk"].Reason; got != "not_observe_safe" {
		t.Fatalf("unavailable reason = %q, want not_observe_safe", got)
	}

	if _, exists := report.MissingChecks["lua_control_risk"]; exists {
		t.Fatal("unsafe observe check was also recorded as missing")
	}

	if got := report.MissingChecks["tls_encryption"]; got != "not_recorded" {
		t.Fatalf("safe missing reason = %q, want not_recorded", got)
	}
}

func TestScriptSinkRecordsOneCheckPerLuaScript(t *testing.T) {
	ctx := NewDecisionContext(testSnapshot(), policy.OperationAuthenticate, nil)
	sink := NewScriptSink(ctx)

	sink.RecordScriptResult(context.Background(), ScriptResult{
		Kind:          ScriptKindControl,
		Name:          "risk",
		Triggered:     true,
		StatusMessage: "Denied by Lua",
	})
	sink.RecordScriptResult(context.Background(), ScriptResult{
		Kind:   ScriptKindFilter,
		Name:   "billing",
		Action: true,
	})

	report := ctx.Report()
	if _, ok := report.Checks["lua_control_risk"]; !ok {
		t.Fatal("missing Lua control check result")
	}

	if _, ok := report.Checks["lua_filter_billing"]; !ok {
		t.Fatal("missing Lua filter check result")
	}

	if got := report.Attributes["auth.lua.control.risk.triggered"].Details["status_message"].Value; got != "Denied by Lua" {
		t.Fatalf("Lua status detail = %v, want Denied by Lua", got)
	}

	if got := report.Attributes["auth.lua.filter.billing.rejected"].Value; got != true {
		t.Fatalf("Lua filter rejected attribute = %v, want true", got)
	}
}

func TestScriptSinkUsesRunIfForLuaFilterScheduling(t *testing.T) {
	ctx := NewDecisionContext(testSnapshot(), policy.OperationAuthenticate, nil)
	sink := NewScriptSink(ctx)

	if sink.ScriptScheduled(ScriptKindFilter, "billing", AuthStateUnauthenticated) {
		t.Fatal("filter should not be scheduled for unauthenticated auth state")
	}

	if !sink.ScriptScheduled(ScriptKindFilter, "billing", AuthStateAuthenticated) {
		t.Fatal("filter should be scheduled for authenticated auth state")
	}
}

func TestDecisionContextDefaultSetAuthorityRequiresNoConfiguredRules(t *testing.T) {
	ctx := NewDecisionContext(testSnapshot(), policy.OperationAuthenticate, nil)
	if !ctx.BuiltinDefaultAuthoritative() {
		t.Fatal("default set should be authoritative when no configured rules exist")
	}

	withRule := testSnapshot()
	withRule.StagePlans[policy.OperationAuthenticate][policy.StageAuthDecision] = policyruntime.CompiledStagePlan{
		Stage: policy.StageAuthDecision,
		Policies: []policyruntime.CompiledPolicy{
			{
				Name:       "operator_rule",
				Stage:      policy.StageAuthDecision,
				Operations: []policy.Operation{policy.OperationAuthenticate},
			},
		},
	}

	ctx = NewDecisionContext(withRule, policy.OperationAuthenticate, nil)
	if ctx.BuiltinDefaultAuthoritative() {
		t.Fatal("configured rules must keep the default set from taking production authority")
	}
}

func TestDecisionContextObserveModeKeepsDefaultSetAuthoritative(t *testing.T) {
	ctx := NewDecisionContext(testObserveSnapshot(), policy.OperationAuthenticate, nil)
	if !ctx.BuiltinDefaultAuthoritative() {
		t.Fatal("observe mode must keep the default set authoritative with configured rules")
	}
}

func TestDecisionContextConfiguredPreAuthAuthorityUsesEnforceMode(t *testing.T) {
	ctx := NewDecisionContext(testObserveSnapshot(), policy.OperationAuthenticate, nil)
	if ctx.ConfiguredPreAuthAuthoritative() {
		t.Fatal("observe mode must not let configured pre-auth rules decide production output")
	}

	snapshot := testObserveSnapshot()
	snapshot.Mode = modeEnforce
	ctx = NewDecisionContext(snapshot, policy.OperationAuthenticate, nil)
	if !ctx.ConfiguredPreAuthAuthoritative() {
		t.Fatal("enforce mode should let configured pre-auth rules decide production output")
	}
}

func testSnapshot() *policyruntime.Snapshot {
	return &policyruntime.Snapshot{
		Generation:    42,
		Mode:          modeEnforce,
		DefaultPolicy: policy.BuiltinDefaultSet,
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationAuthenticate: {
				policy.StagePreAuth: {
					Stage: policy.StagePreAuth,
					Checks: []policyruntime.CompiledCheck{
						{
							Name:       "tls_encryption",
							Type:       policy.CheckTypeTLSEncryption,
							Stage:      policy.StagePreAuth,
							Operations: []policy.Operation{policy.OperationAuthenticate},
							RunIf:      policyruntime.RunIfPlan{AuthState: policy.RunIfAny},
						},
						{
							Name:       "lua_control_auth_only",
							Type:       policy.CheckTypeLuaControl,
							Stage:      policy.StagePreAuth,
							Operations: []policy.Operation{policy.OperationAuthenticate},
							RunIf:      policyruntime.RunIfPlan{AuthState: policy.RunIfAuthenticated},
						},
					},
				},
				policy.StageAuthFilters: {
					Stage: policy.StageAuthFilters,
					Checks: []policyruntime.CompiledCheck{
						{
							Name:       "lua_filter_billing",
							Type:       policy.CheckTypeLuaFilter,
							ConfigRef:  "auth.controls.lua.filters.billing",
							Stage:      policy.StageAuthFilters,
							Operations: []policy.Operation{policy.OperationAuthenticate},
							RunIf:      policyruntime.RunIfPlan{AuthState: policy.RunIfAuthenticated},
						},
					},
				},
			},
		},
	}
}

func testObserveSnapshot() *policyruntime.Snapshot {
	snapshot := testSnapshot()
	snapshot.Mode = modeObserve
	snapshot.StagePlans[policy.OperationAuthenticate][policy.StagePreAuth] = policyruntime.CompiledStagePlan{
		Stage: policy.StagePreAuth,
		Checks: []policyruntime.CompiledCheck{
			{
				Name:        "lua_control_risk",
				Type:        policy.CheckTypeLuaControl,
				Stage:       policy.StagePreAuth,
				Operations:  []policy.Operation{policy.OperationAuthenticate},
				RunIf:       policyruntime.RunIfPlan{AuthState: policy.RunIfAny},
				ObserveSafe: false,
			},
			{
				Name:        "tls_encryption",
				Type:        policy.CheckTypeTLSEncryption,
				Stage:       policy.StagePreAuth,
				Operations:  []policy.Operation{policy.OperationAuthenticate},
				RunIf:       policyruntime.RunIfPlan{AuthState: policy.RunIfAny},
				ObserveSafe: true,
			},
		},
		Policies: []policyruntime.CompiledPolicy{
			{
				Name:          "custom_deny_risk",
				Stage:         policy.StagePreAuth,
				Operations:    []policy.Operation{policy.OperationAuthenticate},
				RequireChecks: []string{"lua_control_risk"},
			},
		},
	}

	return snapshot
}

type recordingRecorder struct {
	checks []observability.CheckMeasurement
}

func (r *recordingRecorder) RecordCheck(_ context.Context, measurement observability.CheckMeasurement) {
	r.checks = append(r.checks, measurement)
}

func (r *recordingRecorder) RecordSnapshotBuild(context.Context, observability.SnapshotBuildMeasurement) {
}
func (r *recordingRecorder) RecordReloadFailure(context.Context, observability.ReloadFailureMeasurement) {
}
func (r *recordingRecorder) RecordStageEvaluation(context.Context, observability.StageMeasurement) {}
func (r *recordingRecorder) RecordDecision(context.Context, observability.DecisionMeasurement)     {}
func (r *recordingRecorder) RecordRequireCheck(context.Context, observability.RequireCheckMeasurement) {
}
func (r *recordingRecorder) RecordObserveComparison(context.Context, observability.ObserveMeasurement) {
}
func (r *recordingRecorder) RecordObserveUnavailable(context.Context, observability.ObserveUnavailableMeasurement) {
}
func (r *recordingRecorder) RecordFSMTransition(context.Context, observability.FSMMeasurement) {}
func (r *recordingRecorder) RecordResponseRender(context.Context, observability.RendererMeasurement) {
}
func (r *recordingRecorder) RecordObligation(context.Context, observability.ObligationMeasurement) {}
func (r *recordingRecorder) RecordAdvice(context.Context, observability.AdviceMeasurement)         {}
