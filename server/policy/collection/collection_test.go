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
	ctx.MarkUnavailable("lua_environment_risk", "not_observe_safe")
	ctx.CompleteStage(policy.StagePreAuth, AuthStateUnauthenticated)

	report := ctx.Report()
	if got := report.Checks["lua_environment_auth_only"].Status; got != policy.CheckStatusSkipped {
		t.Fatalf("skipped status = %q, want %q", got, policy.CheckStatusSkipped)
	}

	if got := report.MissingChecks["tls_encryption"]; got != "not_recorded" {
		t.Fatalf("missing tls reason = %q, want not_recorded", got)
	}

	if got := report.Unavailable["lua_environment_risk"].Reason; got != "not_observe_safe" {
		t.Fatalf("unavailable reason = %q, want not_observe_safe", got)
	}
}

func TestDecisionContextReportsUnsafeObserveChecksUnavailable(t *testing.T) {
	ctx := NewDecisionContext(testObserveSnapshot(), policy.OperationAuthenticate, nil)
	ctx.CompleteStage(policy.StagePreAuth, AuthStateUnauthenticated)

	report := ctx.Report()
	if got := report.Unavailable["lua_environment_risk"].Reason; got != "not_observe_safe" {
		t.Fatalf("unavailable reason = %q, want not_observe_safe", got)
	}

	if _, exists := report.MissingChecks["lua_environment_risk"]; exists {
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
		Kind:          ScriptKindEnvironment,
		Name:          "risk",
		Triggered:     true,
		StatusMessage: "Denied by Lua",
	})
	sink.RecordScriptResult(context.Background(), ScriptResult{
		Kind:   ScriptKindSubject,
		Name:   "billing",
		Action: true,
	})

	report := ctx.Report()
	if _, ok := report.Checks["lua_environment_risk"]; !ok {
		t.Fatal("missing Lua environment check result")
	}

	if _, ok := report.Checks["lua_subject_billing"]; !ok {
		t.Fatal("missing Lua subject check result")
	}

	if got := report.Attributes["auth.lua.environment.risk.triggered"].Details["status_message"].Value; got != "Denied by Lua" {
		t.Fatalf("Lua status detail = %v, want Denied by Lua", got)
	}

	if got := report.Attributes["auth.lua.subject.billing.rejected"].Value; got != true {
		t.Fatalf("Lua subject rejected attribute = %v, want true", got)
	}
}

func TestScriptSinkResolvesLuaResultByConfigRef(t *testing.T) {
	ctx := NewDecisionContext(testCustomLuaNameSnapshot(), policy.OperationAuthenticate, nil)
	sink := NewScriptSink(ctx)

	sink.RecordScriptResult(context.Background(), ScriptResult{
		Kind:      ScriptKindEnvironment,
		Name:      "geoip",
		Triggered: true,
	})

	report := ctx.Report()
	if _, ok := report.Checks["geoip_policy_gate"]; !ok {
		t.Fatal("missing configured Lua check result")
	}

	if _, ok := report.Checks["lua_environment_geoip"]; ok {
		t.Fatal("Lua result was recorded under fallback check name")
	}
}

func TestScriptSinkUsesRunIfForLuaSubjectSourceScheduling(t *testing.T) {
	ctx := NewDecisionContext(testSnapshot(), policy.OperationAuthenticate, nil)
	sink := NewScriptSink(ctx)

	if sink.ScriptScheduled(ScriptKindSubject, "billing", AuthStateUnauthenticated) {
		t.Fatal("filter should not be scheduled for unauthenticated auth state")
	}

	if !sink.ScriptScheduled(ScriptKindSubject, "billing", AuthStateAuthenticated) {
		t.Fatal("filter should be scheduled for authenticated auth state")
	}
}

func TestScriptSinkBuildsPolicyScriptSchedule(t *testing.T) {
	ctx := NewDecisionContext(testScriptScheduleSnapshot(), policy.OperationAuthenticate, nil)
	sink := NewScriptSink(ctx)

	plan := sink.ScriptPlan(ScriptKindEnvironment, AuthStateUnauthenticated)
	if !plan.Configured {
		t.Fatal("script plan should be configured")
	}

	if len(plan.Schedules) != 2 {
		t.Fatalf("script schedules = %#v, want 2 entries", plan.Schedules)
	}

	if got := plan.Schedules[0].Name; got != "context" {
		t.Fatalf("first script = %q, want context", got)
	}

	if got := plan.Schedules[1].Name; got != "policy_only" {
		t.Fatalf("second script = %q, want policy_only", got)
	}

	if got := plan.Schedules[1].After; len(got) != 1 || got[0] != "context" {
		t.Fatalf("second script dependencies = %#v, want context", got)
	}

	if sink.ScriptScheduled(ScriptKindEnvironment, "auth_only", AuthStateUnauthenticated) {
		t.Fatal("auth-only script must not be scheduled for unauthenticated state")
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

func TestDecisionContextDefaultSetAuthorityIsStageScoped(t *testing.T) {
	withAuthRule := testSnapshot()
	withAuthRule.StagePlans[policy.OperationAuthenticate][policy.StageAuthDecision] = policyruntime.CompiledStagePlan{
		Stage: policy.StageAuthDecision,
		Policies: []policyruntime.CompiledPolicy{
			{
				Name:       "operator_rule",
				Stage:      policy.StageAuthDecision,
				Operations: []policy.Operation{policy.OperationAuthenticate},
			},
		},
	}

	ctx := NewDecisionContext(withAuthRule, policy.OperationAuthenticate, nil)
	if !ctx.BuiltinDefaultAuthoritativeForStage(policy.StagePreAuth) {
		t.Fatal("default set should own pre-auth when only final auth rules are configured")
	}

	if ctx.BuiltinDefaultAuthoritativeForStage(policy.StageAuthDecision) {
		t.Fatal("default set should not own final auth when final auth rules are configured")
	}

	withPreAuthRule := testObserveSnapshot()
	withPreAuthRule.Mode = modeEnforce
	ctx = NewDecisionContext(withPreAuthRule, policy.OperationAuthenticate, nil)
	if ctx.BuiltinDefaultAuthoritativeForStage(policy.StagePreAuth) {
		t.Fatal("default set should not own pre-auth when pre-auth rules are configured")
	}

	if !ctx.BuiltinDefaultAuthoritativeForStage(policy.StageAuthDecision) {
		t.Fatal("default set should own final auth when only pre-auth rules are configured")
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
							Name:       "lua_environment_auth_only",
							Type:       policy.CheckTypeLuaEnvironment,
							Stage:      policy.StagePreAuth,
							Operations: []policy.Operation{policy.OperationAuthenticate},
							RunIf:      policyruntime.RunIfPlan{AuthState: policy.RunIfAuthenticated},
						},
					},
				},
				policy.StageSubjectAnalysis: {
					Stage: policy.StageSubjectAnalysis,
					Checks: []policyruntime.CompiledCheck{
						{
							Name:       "lua_subject_billing",
							Type:       policy.CheckTypeLuaSubjectSource,
							ConfigRef:  "auth.policy.attribute_sources.lua.subject.billing",
							Stage:      policy.StageSubjectAnalysis,
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
				Name:        "lua_environment_risk",
				Type:        policy.CheckTypeLuaEnvironment,
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
				RequireChecks: []string{"lua_environment_risk"},
			},
		},
	}

	return snapshot
}

func testScriptScheduleSnapshot() *policyruntime.Snapshot {
	return &policyruntime.Snapshot{
		Generation:    43,
		Mode:          modeEnforce,
		DefaultPolicy: policy.BuiltinDefaultSet,
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationAuthenticate: {
				policy.StagePreAuth: {
					Stage: policy.StagePreAuth,
					Checks: []policyruntime.CompiledCheck{
						{
							Name:       "lua_environment_context",
							Type:       policy.CheckTypeLuaEnvironment,
							ConfigRef:  "auth.policy.attribute_sources.lua.environment.context",
							Stage:      policy.StagePreAuth,
							Operations: []policy.Operation{policy.OperationAuthenticate},
							RunIf:      policyruntime.RunIfPlan{AuthState: policy.RunIfAny},
						},
						{
							Name:       "lua_environment_policy_only",
							Type:       policy.CheckTypeLuaEnvironment,
							ConfigRef:  "auth.policy.attribute_sources.lua.environment.policy_only",
							Stage:      policy.StagePreAuth,
							Operations: []policy.Operation{policy.OperationAuthenticate},
							RunIf:      policyruntime.RunIfPlan{AuthState: policy.RunIfUnauthenticated},
							After:      []string{"lua_environment_context"},
						},
						{
							Name:       "lua_environment_auth_only",
							Type:       policy.CheckTypeLuaEnvironment,
							ConfigRef:  "auth.policy.attribute_sources.lua.environment.auth_only",
							Stage:      policy.StagePreAuth,
							Operations: []policy.Operation{policy.OperationAuthenticate},
							RunIf:      policyruntime.RunIfPlan{AuthState: policy.RunIfAuthenticated},
						},
					},
				},
			},
		},
	}
}

func testCustomLuaNameSnapshot() *policyruntime.Snapshot {
	return &policyruntime.Snapshot{
		Generation:    44,
		Mode:          modeEnforce,
		DefaultPolicy: policy.BuiltinDefaultSet,
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationAuthenticate: {
				policy.StagePreAuth: {
					Stage: policy.StagePreAuth,
					Checks: []policyruntime.CompiledCheck{
						{
							Name:       "geoip_policy_gate",
							Type:       policy.CheckTypeLuaEnvironment,
							ConfigRef:  "auth.policy.attribute_sources.lua.environment.geoip",
							Stage:      policy.StagePreAuth,
							Operations: []policy.Operation{policy.OperationAuthenticate},
							RunIf:      policyruntime.RunIfPlan{AuthState: policy.RunIfAny},
						},
					},
				},
			},
		},
	}
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
