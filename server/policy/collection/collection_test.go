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

	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/evaluation"
	"github.com/croessner/nauthilus/v3/server/policy/observability"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
	"github.com/croessner/nauthilus/v3/server/policy/report"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const (
	testMissingNotRecorded           = "not_recorded"
	testSchedulerGuardInsecureReason = "scheduler_guard:insecure_connection"
	testTLSCheckConfigRef            = "auth.controls.tls_encryption"
	testTLSCheckName                 = "tls_encryption"
)

func TestDecisionContextRecordsCheckResultAndAttributes(t *testing.T) {
	recorder := &recordingRecorder{}
	ctx := NewDecisionContext(testSnapshot(), policy.OperationAuthenticate, recorder)
	check := ctx.BeginCheck(context.Background(), CheckSelector{
		CheckType: policy.CheckTypeTLSEncryption,
		Stage:     policy.StagePreAuth,
		Name:      testTLSCheckName,
	})

	check.Finish(CheckResult{
		Matched:      true,
		DecisionHint: policy.DecisionTempFail,
		Attributes: []AttributeValue{
			BoolAttribute("auth.tls.secure", policy.StagePreAuth, policy.OperationAuthenticate, false, nil),
		},
	})

	report := ctx.Report()
	if got := report.Checks[testTLSCheckName].Status; got != policy.CheckStatusOK {
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

func TestDecisionContextReturnsDetachedAttributeDefinition(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.AttributeRegistry = map[string]policyregistry.AttributeDefinition{
		"lua.plugin.test.value": {
			ID:         "lua.plugin.test.value",
			Operations: []policy.Operation{policy.OperationAuthenticate},
			Details: map[string]policyregistry.DetailDefinition{
				"message": {Type: policyregistry.AttributeTypeString},
			},
		},
	}
	ctx := NewDecisionContext(snapshot, policy.OperationAuthenticate, nil)

	definition, ok := ctx.AttributeDefinition("lua.plugin.test.value")
	if !ok {
		t.Fatal("registered attribute definition missing")
	}

	definition.Operations[0] = policy.OperationListAccounts
	definition.Details["message"] = policyregistry.DetailDefinition{Type: policyregistry.AttributeTypeBool}

	original := snapshot.AttributeRegistry["lua.plugin.test.value"]
	if original.Operations[0] != policy.OperationAuthenticate {
		t.Fatalf("snapshot operation = %q, want %q", original.Operations[0], policy.OperationAuthenticate)
	}

	if original.Details["message"].Type != policyregistry.AttributeTypeString {
		t.Fatalf("snapshot detail type = %q, want %q", original.Details["message"].Type, policyregistry.AttributeTypeString)
	}

	if _, exists := ctx.AttributeDefinition("lua.plugin.test.missing"); exists {
		t.Fatal("missing attribute definition reported as registered")
	}
}

func TestDecisionContextEvaluatesConfiguredWithCapturedState(t *testing.T) {
	snapshot := testSnapshot()
	ctx := NewDecisionContext(snapshot, policy.OperationAuthenticate, nil)
	wantReport := ctx.Report()
	calls := 0

	evaluator := configuredDecisionEvaluator(func(
		_ context.Context,
		gotSnapshot *policyruntime.Snapshot,
		gotReport *report.DecisionReport,
		input evaluation.CompareInput,
	) evaluation.Result {
		calls++

		if gotSnapshot != snapshot {
			t.Fatal("configured evaluator did not receive the captured snapshot")
		}

		if gotReport != wantReport {
			t.Fatal("configured evaluator did not receive the request report")
		}

		if input.Generation != snapshot.Generation {
			t.Fatalf("generation = %d, want %d", input.Generation, snapshot.Generation)
		}

		return evaluation.Result{Mismatch: true}
	})

	result := ctx.evaluateConfigured(context.Background(), evaluator, evaluation.CompareInput{Generation: snapshot.Generation})
	if !result.Mismatch {
		t.Fatal("configured evaluator result was not returned")
	}

	if calls != 1 {
		t.Fatalf("configured evaluator calls = %d, want 1", calls)
	}
}

func TestDecisionContextConfiguredEvaluationAllocatesNothing(t *testing.T) {
	ctx := NewDecisionContext(testSnapshot(), policy.OperationAuthenticate, nil)
	evaluator := configuredDecisionEvaluator(func(
		context.Context,
		*policyruntime.Snapshot,
		*report.DecisionReport,
		evaluation.CompareInput,
	) evaluation.Result {
		return evaluation.Result{}
	})
	background := context.Background()
	input := evaluation.CompareInput{}

	allocations := testing.AllocsPerRun(1000, func() {
		ctx.evaluateConfigured(background, evaluator, input)
	})
	if allocations != 0 {
		t.Fatalf("configured evaluation allocations = %.2f, want 0", allocations)
	}
}

func TestDecisionContextNarrowSnapshotOperationsHandleMissingState(t *testing.T) {
	var nilContext *DecisionContext

	if result := nilContext.evaluateConfigured(context.Background(), nil, evaluation.CompareInput{}); result != (evaluation.Result{}) {
		t.Fatalf("nil context configured result = %#v, want empty", result)
	}

	ctx := NewDecisionContext(nil, policy.OperationAuthenticate, nil)
	if result := ctx.evaluateConfigured(context.Background(), nil, evaluation.CompareInput{}); result != (evaluation.Result{}) {
		t.Fatalf("nil evaluator configured result = %#v, want empty", result)
	}

	if result := ctx.CompareCustomObserve(context.Background(), evaluation.CompareInput{}); result != (evaluation.CompareResult{}) {
		t.Fatalf("missing snapshot observe result = %#v, want empty", result)
	}

	if settings := nilContext.ReportSettings(); settings != (policyruntime.ReportSettings{}) {
		t.Fatalf("nil context report settings = %#v, want empty", settings)
	}
}

func TestDecisionContextReturnsReportSettingsByValue(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.Report = policyruntime.ReportSettings{
		Enabled:           true,
		IncludeFSM:        true,
		IncludeChecks:     true,
		IncludeAttributes: true,
	}
	ctx := NewDecisionContext(snapshot, policy.OperationAuthenticate, nil)

	settings := ctx.ReportSettings()
	if settings != snapshot.Report {
		t.Fatalf("report settings = %#v, want %#v", settings, snapshot.Report)
	}

	settings.Enabled = false
	if !snapshot.Report.Enabled {
		t.Fatal("mutating returned report settings changed the captured snapshot")
	}
}

func TestDecisionContextRecordsAttributeBatch(t *testing.T) {
	ctx := NewDecisionContext(testSnapshot(), policy.OperationAuthenticate, nil)
	ctx.RecordAttributes([]AttributeValue{
		BoolAttribute("lua.plugin.batch.first", policy.StagePreAuth, policy.OperationAuthenticate, true, nil),
		{},
		BoolAttribute("lua.plugin.batch.second", policy.StagePreAuth, policy.OperationAuthenticate, false, nil),
	})

	attributes := ctx.Report().Attributes
	if len(attributes) != 2 {
		t.Fatalf("recorded attributes = %#v, want two non-empty attributes", attributes)
	}

	if got := attributes["lua.plugin.batch.first"].Value; got != true {
		t.Fatalf("first batch attribute = %#v, want true", got)
	}

	if got := attributes["lua.plugin.batch.second"].Value; got != false {
		t.Fatalf("second batch attribute = %#v, want false", got)
	}
}

func TestCheckMatchesSelectorKeepsPluginSubjectConfigRefPrecise(t *testing.T) {
	selector := CheckSelector{
		CheckType: policy.CheckTypePluginSubjectSource,
		Stage:     policy.StageSubjectAnalysis,
		Name:      "plugin_subject_example_auth_policy",
		ConfigRef: "plugins.modules.example_auth.subject",
	}
	check := policyruntime.CompiledCheck{
		Name:      "plugin_subject_example_auth_policy",
		Type:      policy.CheckTypePluginSubjectSource,
		Stage:     policy.StageSubjectAnalysis,
		ConfigRef: "plugins.modules.example_auth.subject",
	}

	if !checkMatchesSelector(check, selector) {
		t.Fatal("selector did not match the intended plugin subject check")
	}

	check.Name = "plugin_subject_example_auth_other"
	if checkMatchesSelector(check, selector) {
		t.Fatal("selector matched a different plugin subject check with the same config_ref")
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

	if got := report.MissingChecks[testTLSCheckName]; got != testMissingNotRecorded {
		t.Fatalf("missing tls reason = %q, want %s", got, testMissingNotRecorded)
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

	if got := report.MissingChecks[testTLSCheckName]; got != testMissingNotRecorded {
		t.Fatalf("safe missing reason = %q, want %s", got, testMissingNotRecorded)
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
		t.Fatal("subject source should not be scheduled for unauthenticated auth state")
	}

	if !sink.ScriptScheduled(ScriptKindSubject, "billing", AuthStateAuthenticated) {
		t.Fatal("subject source should be scheduled for authenticated auth state")
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

func TestDecisionContextSchedulerGuardSkipsCheckBeforeAdapter(t *testing.T) {
	recorder := &recordingRecorder{}
	ctx := NewDecisionContext(testSchedulerGuardSnapshot(modeEnforce, testSchedulerGuardCheck(
		policy.RunIfAny,
		"insecure_connection",
	)), policy.OperationAuthenticate, recorder)
	ctx.RecordAttribute(BoolAttribute(policy.AttributeRequestConnectionTLS, policy.StagePreAuth, policy.OperationAuthenticate, false, nil))

	adapterCalled := false
	if ctx.CheckScheduled(context.Background(), testTLSSchedulerSelector(), AuthStateUnauthenticated) {
		adapterCalled = true
		check := ctx.BeginCheck(context.Background(), testTLSSchedulerSelector())
		check.Finish(CheckResult{Matched: true})
	}

	if adapterCalled {
		t.Fatal("adapter was called although scheduler guard matched")
	}

	report := ctx.Report()

	checkResult := report.Checks[testTLSCheckName]
	if checkResult.Status != policy.CheckStatusSkipped {
		t.Fatalf("check status = %q, want %q", checkResult.Status, policy.CheckStatusSkipped)
	}

	if checkResult.Reason != testSchedulerGuardInsecureReason {
		t.Fatalf("check reason = %q, want %s", checkResult.Reason, testSchedulerGuardInsecureReason)
	}

	if len(recorder.checks) != 1 {
		t.Fatalf("recorded checks = %d, want 1", len(recorder.checks))
	}

	if got := recorder.checks[0].ReasonCode; got != testSchedulerGuardInsecureReason {
		t.Fatalf("metric reason = %q, want %s", got, testSchedulerGuardInsecureReason)
	}
}

func TestDecisionContextSchedulerGuardRunsCheckWhenGuardDoesNotMatch(t *testing.T) {
	ctx := NewDecisionContext(testSchedulerGuardSnapshot(modeEnforce, testSchedulerGuardCheck(
		policy.RunIfAny,
		"insecure_connection",
	)), policy.OperationAuthenticate, nil)
	ctx.RecordAttribute(BoolAttribute(policy.AttributeRequestConnectionTLS, policy.StagePreAuth, policy.OperationAuthenticate, true, nil))

	if !ctx.CheckScheduled(context.Background(), testTLSSchedulerSelector(), AuthStateUnauthenticated) {
		t.Fatal("check should be scheduled when scheduler guard does not match")
	}

	check := ctx.BeginCheck(context.Background(), testTLSSchedulerSelector())
	check.Finish(CheckResult{Matched: false})

	if got := ctx.Report().Checks[testTLSCheckName].Status; got != policy.CheckStatusOK {
		t.Fatalf("check status = %q, want %q", got, policy.CheckStatusOK)
	}
}

func TestDecisionContextSchedulerGuardsAreORCombined(t *testing.T) {
	ctx := NewDecisionContext(testSchedulerGuardSnapshot(modeEnforce, testSchedulerGuardCheck(
		policy.RunIfAny,
		"internal_listener",
		"insecure_connection",
	)), policy.OperationAuthenticate, nil)
	ctx.RecordAttribute(StringAttribute(policy.AttributeRequestListenerName, policy.StagePreAuth, policy.OperationAuthenticate, "external"))
	ctx.RecordAttribute(BoolAttribute(policy.AttributeRequestConnectionTLS, policy.StagePreAuth, policy.OperationAuthenticate, false, nil))

	if ctx.CheckScheduled(context.Background(), testTLSSchedulerSelector(), AuthStateUnauthenticated) {
		t.Fatal("check should be skipped when any scheduler guard matches")
	}

	if got := ctx.Report().Checks[testTLSCheckName].Reason; got != testSchedulerGuardInsecureReason {
		t.Fatalf("skip reason = %q, want %s", got, testSchedulerGuardInsecureReason)
	}
}

func TestDecisionContextRunIfSkipRemainsDistinctFromSchedulerGuardSkip(t *testing.T) {
	ctx := NewDecisionContext(testSchedulerGuardSnapshot(modeEnforce, testSchedulerGuardCheck(
		policy.RunIfAuthenticated,
		"insecure_connection",
	)), policy.OperationAuthenticate, nil)
	ctx.RecordAttribute(BoolAttribute(policy.AttributeRequestConnectionTLS, policy.StagePreAuth, policy.OperationAuthenticate, false, nil))

	if ctx.CheckScheduled(context.Background(), testTLSSchedulerSelector(), AuthStateUnauthenticated) {
		t.Fatal("auth-state run_if should skip the check")
	}

	if got := ctx.Report().Checks[testTLSCheckName].Reason; got != "run_if" {
		t.Fatalf("skip reason = %q, want run_if", got)
	}
}

func TestDecisionContextObserveModeRecordsSchedulerGuardSkip(t *testing.T) {
	ctx := NewDecisionContext(testSchedulerGuardSnapshot(modeObserve, testSchedulerGuardCheck(
		policy.RunIfAny,
		"insecure_connection",
	)), policy.OperationAuthenticate, nil)
	ctx.RecordAttribute(BoolAttribute(policy.AttributeRequestConnectionTLS, policy.StagePreAuth, policy.OperationAuthenticate, false, nil))

	if ctx.CheckScheduled(context.Background(), testTLSSchedulerSelector(), AuthStateUnauthenticated) {
		t.Fatal("check should be skipped in the observe report when scheduler guard matches")
	}

	report := ctx.Report()
	if report.Final != nil {
		t.Fatalf("scheduler guard set final decision = %#v, want nil", report.Final)
	}

	if got := report.Checks[testTLSCheckName].Reason; got != testSchedulerGuardInsecureReason {
		t.Fatalf("skip reason = %q, want %s", got, testSchedulerGuardInsecureReason)
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
							Name:       testTLSCheckName,
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
				Name:        testTLSCheckName,
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

func testSchedulerGuardSnapshot(mode string, checks ...policyruntime.CompiledCheck) *policyruntime.Snapshot {
	return &policyruntime.Snapshot{
		Generation:    45,
		Mode:          mode,
		DefaultPolicy: policy.BuiltinDefaultSet,
		SchedulerGuards: map[string]policyruntime.CompiledSchedulerGuard{
			"insecure_connection": {
				Root: policyruntime.CompiledExpr{
					Kind:        policyruntime.ExprKindAttribute,
					AttributeID: policy.AttributeRequestConnectionTLS,
					Operator:    "is",
					Expected:    policyruntime.TypedValue{Value: false},
				},
				OnMissingAttribute: "run",
			},
			"internal_listener": {
				Root: policyruntime.CompiledExpr{
					Kind:        policyruntime.ExprKindAttribute,
					AttributeID: policy.AttributeRequestListenerName,
					Operator:    "is",
					Expected:    policyruntime.TypedValue{Value: "internal"},
				},
				OnMissingAttribute: "run",
			},
		},
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationAuthenticate: {
				policy.StagePreAuth: {
					Stage:  policy.StagePreAuth,
					Checks: checks,
				},
			},
		},
	}
}

func testSchedulerGuardCheck(runIf string, skipIf ...string) policyruntime.CompiledCheck {
	return policyruntime.CompiledCheck{
		Name:       testTLSCheckName,
		Type:       policy.CheckTypeTLSEncryption,
		ConfigRef:  testTLSCheckConfigRef,
		Stage:      policy.StagePreAuth,
		Operations: []policy.Operation{policy.OperationAuthenticate},
		RunIf:      policyruntime.RunIfPlan{AuthState: runIf},
		SkipIf:     append([]string(nil), skipIf...),
	}
}

func testTLSSchedulerSelector() CheckSelector {
	return CheckSelector{
		CheckType: policy.CheckTypeTLSEncryption,
		Stage:     policy.StagePreAuth,
		Name:      testTLSCheckName,
		ConfigRef: testTLSCheckConfigRef,
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
