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

package core

import (
	"strings"
	"sync"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/report"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"

	"github.com/gin-gonic/gin"
)

const (
	policyAuthorityTestI18NKey      = "auth.policy.company.account_blocked"
	policyAuthorityTestI18NFallback = "Login failed because the account is locked."
	policyAuthorityPluginEffectID   = "customer.sync_obligation"
)

func TestAuthBoundaryDefaultSetSelectsPreAuthDecisionDuringEnvironmentHandling(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlTLSEncryption)
	cfg.ClearTextList = nil

	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation:    101,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
	})

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)

	got := auth.HandleEnvironment(ctx)
	if got != definitions.AuthResultPreAuthTLS {
		t.Fatalf("pre-auth result = %v, want %v", got, definitions.AuthResultPreAuthTLS)
	}

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	if policyCtx.Report().Final == nil {
		t.Fatal("missing authoritative pre-auth decision")
	}

	if got := policyCtx.Report().Final.PolicyName; got != "standard_tls_enforcement" {
		t.Fatalf("policy = %q, want standard_tls_enforcement", got)
	}
}

func TestAuthBoundaryDefaultSetSelectsFinalDecisionDuringPasswordHandling(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation:    102,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
	})

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	passDBResult := GetPassDBResultFromPool()
	passDBResult.Authenticated = false
	passDBResult.UserFound = true

	passDBResult.Backend = definitions.BackendTest
	defer PutPassDBResultToPool(passDBResult)

	auth.recordPolicyBackendResult(ctx, definitions.AuthResultFail, passDBResult, nil)

	got := auth.defaultPolicyAuthResult(ctx, definitions.AuthResultOK)
	if got != definitions.AuthResultFail {
		t.Fatalf("auth result = %v, want %v", got, definitions.AuthResultFail)
	}

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	if policyCtx.Report().Final == nil {
		t.Fatal("missing authoritative final decision")
	}

	if got := policyCtx.Report().Final.PolicyName; got != "standard_auth_failure" {
		t.Fatalf("policy = %q, want standard_auth_failure", got)
	}
}

func TestAuthBoundaryStandardAuthFailureAllowsIDPDelayedResponse(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	storeConfiguredAuthDecision(ctx, &report.FinalDecision{
		PolicyName:     "standard_auth_failure",
		Stage:          policy.StageAuthDecision,
		Effect:         policy.DecisionDeny,
		OutcomeMarker:  policy.OutcomeMarkerAuthFailure,
		FSMEventMarker: policy.FSMEventMarkerAuthDeny,
		ResponseMarker: policy.ResponseMarkerFail,
	})

	if !auth.ConfiguredPolicyAllowsIDPDelayedResponse(ctx) {
		t.Fatal("standard password failures must stay eligible for IDP delayed_response")
	}
}

func TestAuthBoundaryDefaultSetAppliesTargetFSMForDirectPreAuthDecision(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlTLSEncryption)
	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation:    104,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
	})

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.recordPolicyTLS(ctx, true)

	if !auth.ApplyDefaultPreAuthDecision(ctx) {
		t.Fatal("default pre-auth decision was not applied")
	}

	wantPath := strings.Join([]string{
		policy.FSMEventMarkerParseOK,
		policy.FSMEventMarkerPreAuthTempFail,
	}, ",")
	if got := strings.Join(auth.Runtime.AuthFSMEventPath, ","); got != wantPath {
		t.Fatalf("fsm event path = %q, want %q", got, wantPath)
	}

	if got := auth.Runtime.AuthFSMTerminalState; got != "auth_tempfail" {
		t.Fatalf("terminal state = %q, want auth_tempfail", got)
	}
}

func TestAuthBoundaryDefaultSetAuthDecisionDoesNotEmitObserveReportInEnforceMode(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation:    103,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
	})

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	passDBResult := GetPassDBResultFromPool()
	passDBResult.Authenticated = false
	passDBResult.UserFound = true

	passDBResult.Backend = definitions.BackendTest
	defer PutPassDBResultToPool(passDBResult)

	auth.recordPolicyBackendResult(ctx, definitions.AuthResultFail, passDBResult, nil)

	got := auth.defaultPolicyAuthResult(ctx, definitions.AuthResultOK)
	if got != definitions.AuthResultFail {
		t.Fatalf("auth result = %v, want %v", got, definitions.AuthResultFail)
	}

	auth.AuthFail(ctx)

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	if policyCtx.Report().Observe != nil {
		t.Fatalf("observe report = %#v, want nil in enforce mode", policyCtx.Report().Observe)
	}
}

func TestAuthBoundaryDefaultPreAuthAppliesWhenConfiguredFinalRulesExist(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlTLSEncryption)
	cfg.ClearTextList = nil

	activatePolicySnapshotForTest(t, customEnforceAuthSnapshotForTest())

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)

	got := auth.HandleEnvironment(ctx)
	if got != definitions.AuthResultPreAuthTLS {
		t.Fatalf("pre-auth result = %v, want %v", got, definitions.AuthResultPreAuthTLS)
	}

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	if policyCtx.Report().Final == nil || policyCtx.Report().Final.PolicyName != "standard_tls_enforcement" {
		t.Fatalf("final = %#v, want standard_tls_enforcement", policyCtx.Report().Final)
	}
}

func TestAuthBoundaryDefaultFinalDecisionAppliesWhenConfiguredPreAuthRulesExist(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, customEnforceTLSSnapshot(customEnforceTLSDenyPolicy(true)))

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	passDBResult := GetPassDBResultFromPool()
	passDBResult.Authenticated = false
	passDBResult.UserFound = true

	passDBResult.Backend = definitions.BackendTest
	defer PutPassDBResultToPool(passDBResult)

	auth.recordPolicyBackendResult(ctx, definitions.AuthResultFail, passDBResult, nil)

	got := auth.defaultPolicyAuthResult(ctx, definitions.AuthResultOK)
	if got != definitions.AuthResultFail {
		t.Fatalf("auth result = %v, want %v", got, definitions.AuthResultFail)
	}

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	if policyCtx.Report().Final == nil || policyCtx.Report().Final.PolicyName != "standard_auth_failure" {
		t.Fatalf("final = %#v, want standard_auth_failure", policyCtx.Report().Final)
	}
}

func TestAuthBoundaryConfiguredFinalDecisionOverridesBackendSuccess(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, customEnforceAuthSnapshotForTest())

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	passDBResult := GetPassDBResultFromPool()
	passDBResult.Authenticated = true
	passDBResult.UserFound = true

	passDBResult.Backend = definitions.BackendTest
	defer PutPassDBResultToPool(passDBResult)

	auth.recordPolicyBackendResult(ctx, definitions.AuthResultOK, passDBResult, nil)

	got, ok := auth.configuredPolicyAuthResult(ctx, definitions.AuthResultOK)
	if !ok {
		t.Fatal("configured auth decision was not evaluated")
	}

	if got != definitions.AuthResultFail {
		t.Fatalf("auth result = %v, want %v", got, definitions.AuthResultFail)
	}

	if got := auth.Runtime.StatusMessage; got != "Custom backend deny" {
		t.Fatalf("status message = %q, want configured message", got)
	}

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	if policyCtx.Report().Final == nil || policyCtx.Report().Final.PolicyName != "custom_deny_backend_success" {
		t.Fatalf("final = %#v, want custom_deny_backend_success", policyCtx.Report().Final)
	}
}

func TestAuthBoundaryConfiguredFinalDecisionAppliesResponseMetadata(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	snapshot := customEnforceAuthSnapshotForTest()
	compiled := snapshot.StagePlans[policy.OperationAuthenticate][policy.StageAuthDecision]
	compiled.Policies[0].Then.ResponseMessage = policyruntime.ResponseMessagePlan{
		Source:    policy.ResponseSourceI18N,
		I18NKey:   policyAuthorityTestI18NKey,
		Fallback:  policyAuthorityTestI18NFallback,
		MaxLength: 256,
	}
	compiled.Policies[0].Then.ResponseLanguage = policyruntime.ResponseLanguagePlan{
		Source:   policy.ResponseSourceLiteral,
		Language: "de",
	}
	snapshot.StagePlans[policy.OperationAuthenticate][policy.StageAuthDecision] = compiled
	activatePolicySnapshotForTest(t, snapshot)

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	passDBResult := GetPassDBResultFromPool()
	passDBResult.Authenticated = true
	passDBResult.UserFound = true

	passDBResult.Backend = definitions.BackendTest
	defer PutPassDBResultToPool(passDBResult)

	auth.recordPolicyBackendResult(ctx, definitions.AuthResultOK, passDBResult, nil)

	if _, ok := auth.configuredPolicyAuthResult(ctx, definitions.AuthResultOK); !ok {
		t.Fatal("configured auth decision was not evaluated")
	}

	if got := auth.Runtime.StatusMessage; got != policyAuthorityTestI18NFallback {
		t.Fatalf("status message = %q, want configured fallback", got)
	}

	if got := auth.Runtime.StatusMessageI18NKey; got != policyAuthorityTestI18NKey {
		t.Fatalf("i18n key = %q, want configured key", got)
	}

	if got := auth.Runtime.ResponseLanguage; got != "de" {
		t.Fatalf("response language = %q, want de", got)
	}
}

func TestAuthBoundaryConfiguredFinalDecisionRunsPostActionObligation(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	snapshot := customEnforceAuthSnapshotForTest()
	compiled := snapshot.StagePlans[policy.OperationAuthenticate][policy.StageAuthDecision]
	compiled.Policies[0].Then.Obligations = []policyruntime.EffectRequest{
		{ID: policy.ObligationLuaPostActionEnqueue},
	}
	snapshot.StagePlans[policy.OperationAuthenticate][policy.StageAuthDecision] = compiled
	activatePolicySnapshotForTest(t, snapshot)

	postAction := &countingPostAction{}
	previousPostAction := getPostAction()

	RegisterPostAction(postAction)
	t.Cleanup(func() {
		RegisterPostAction(previousPostAction)
	})

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	passDBResult := GetPassDBResultFromPool()
	passDBResult.Authenticated = true
	passDBResult.UserFound = true

	passDBResult.Backend = definitions.BackendTest
	defer PutPassDBResultToPool(passDBResult)

	auth.recordPolicyBackendResult(ctx, definitions.AuthResultOK, passDBResult, nil)
	auth.storePolicyPostActionResult(ctx, passDBResult)

	if _, ok := auth.configuredPolicyAuthResult(ctx, definitions.AuthResultOK); !ok {
		t.Fatal("configured auth decision was not evaluated")
	}

	if got := postAction.Count(); got != 1 {
		t.Fatalf("post actions = %d, want 1", got)
	}

	if _, release := takePolicyPostActionResult(ctx); release {
		t.Fatal("stored post-action result was not released")
	}
}

func TestAuthBoundaryConfiguredPreAuthDecisionWithoutLuaActionObligationSkipsSynchronousAction(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlTLSEncryption)
	cfg.ClearTextList = nil
	cfg.Lua = policyActionTestLuaConfig(definitions.LuaActionTLSName)

	activatePolicySnapshotForTest(t, customEnforceTLSSnapshot(customEnforceTLSDenyPolicy(false)))

	dispatcher := &recordingActionDispatcher{}
	previous := getActionDispatcher()

	RegisterActionDispatcher(dispatcher)
	t.Cleanup(func() {
		RegisterActionDispatcher(previous)
	})

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.HandleEnvironment(ctx)

	if got := dispatcher.Count(); got != 0 {
		t.Fatalf("lua actions = %d, want no synchronous action without selected obligation", got)
	}
}

func TestAuthBoundaryConfiguredPreAuthDecisionRunsSelectedLuaActionObligationOnce(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlTLSEncryption)
	cfg.ClearTextList = nil
	cfg.Lua = policyActionTestLuaConfig(definitions.LuaActionTLSName)

	compiled := customEnforceTLSDenyPolicy(false)
	compiled.Then.Obligations = []policyruntime.EffectRequest{
		{
			ID: policy.ObligationLuaActionDispatch,
			Args: map[string]any{
				policy.ObligationArgAction:      definitions.LuaActionTLSName,
				policy.ObligationArgEnvironment: "selected_tls_action",
			},
		},
	}
	activatePolicySnapshotForTest(t, customEnforceTLSSnapshot(compiled))

	dispatcher := &recordingActionDispatcher{}
	previous := getActionDispatcher()

	RegisterActionDispatcher(dispatcher)
	t.Cleanup(func() {
		RegisterActionDispatcher(previous)
	})

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.HandleEnvironment(ctx)

	if got := dispatcher.Count(); got != 1 {
		t.Fatalf("lua actions = %d, want one selected obligation dispatch", got)
	}

	call := dispatcher.Last()
	if call.action != definitions.LuaActionTLS {
		t.Fatalf("lua action = %v, want TLS action", call.action)
	}

	if call.environment != "selected_tls_action" {
		t.Fatalf("environment = %q, want selected obligation environment", call.environment)
	}
}

func TestPolicyObligationExecutorSkipsMutableEffectsInObserveMode(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation:    106,
		Mode:          "observe",
		DefaultPolicy: policy.BuiltinDefaultSet,
	})

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	_ = auth.requestPolicyContext(ctx)

	calls := &recordingObligationHandlers{}
	executor := newPolicyObligationExecutor(auth)
	executor.handlers = policyObligationHandlers{
		updateBruteForce: calls.updateBruteForce,
		dispatchLua:      calls.dispatchLua,
		enqueuePost:      calls.enqueuePost,
	}
	final := reportFinalWithMutableObligations()
	executor.Execute(ctx, final)

	if got := calls.Total(); got != 0 {
		t.Fatalf("mutable obligation calls = %d, want none in observe mode", got)
	}
}

func TestPolicyObligationExecutorSkipsMutableEffectsWithoutPolicyContext(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)

	calls := &recordingObligationHandlers{}
	executor := newPolicyObligationExecutor(auth)
	executor.handlers = policyObligationHandlers{
		updateBruteForce: calls.updateBruteForce,
		dispatchLua:      calls.dispatchLua,
		enqueuePost:      calls.enqueuePost,
	}
	executor.Execute(ctx, reportFinalWithMutableObligations())

	if got := calls.Total(); got != 0 {
		t.Fatalf("mutable obligation calls = %d, want none without policy context", got)
	}
}

func TestPolicyObligationExecutorRunsPluginEffectBridge(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation:    108,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
	})

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	_ = auth.requestPolicyContext(ctx)

	bridge := &recordingPluginEffectBridge{ok: true}
	previous := getPluginEffectBridge()

	RegisterPluginEffectBridge(bridge)

	t.Cleanup(func() {
		RegisterPluginEffectBridge(previous)
	})

	newPolicyObligationExecutor(auth).Execute(ctx, &report.FinalDecision{
		Obligations: []report.EffectRequest{
			{ID: policyAuthorityPluginEffectID, Args: map[string]any{"message": "hello"}},
		},
	})

	if bridge.calls != 1 {
		t.Fatalf("plugin effect calls = %d, want 1", bridge.calls)
	}

	if bridge.last.ID != policyAuthorityPluginEffectID {
		t.Fatalf("plugin effect = %q, want %s", bridge.last.ID, policyAuthorityPluginEffectID)
	}
}

func TestPolicyObligationExecutorRecordsPluginEffectFailure(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation:    109,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
	})

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	_ = auth.requestPolicyContext(ctx)

	bridge := &recordingPluginEffectBridge{ok: false}
	previous := getPluginEffectBridge()

	RegisterPluginEffectBridge(bridge)

	t.Cleanup(func() {
		RegisterPluginEffectBridge(previous)
	})

	newPolicyObligationExecutor(auth).Execute(ctx, &report.FinalDecision{
		Obligations: []report.EffectRequest{{ID: policyAuthorityPluginEffectID}},
	})

	if bridge.calls != 1 {
		t.Fatalf("plugin effect calls = %d, want 1", bridge.calls)
	}
}

func TestPolicyBruteForceLuaActionPreservesCommonRequestShape(t *testing.T) {
	const ruleName = "existing_block"

	cfg := newCurrentBehaviorConfig(t)
	cfg.Lua = policyActionTestLuaConfig(definitions.LuaActionBruteForceName)

	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation:    107,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
	})

	dispatcher := &recordingActionDispatcher{}
	previous := getActionDispatcher()

	RegisterActionDispatcher(dispatcher)
	t.Cleanup(func() {
		RegisterActionDispatcher(previous)
	})

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	_ = auth.requestPolicyContext(ctx)
	auth.Security.BruteForceName = ruleName + ",guessed"
	auth.Security.BruteForceCounter = map[string]uint{ruleName: 3}
	auth.Runtime.BFClientNet = "203.0.113.0/24"
	auth.Runtime.BFRepeating = true
	auth.Runtime.EnvironmentName = definitions.ControlBruteForce

	newPolicyObligationExecutor(auth).Execute(ctx, bruteForceActionFinalDecision())

	if got := dispatcher.Count(); got != 1 {
		t.Fatalf("lua actions = %d, want one brute-force action", got)
	}

	call := dispatcher.Last()
	if call.common.bruteForceName != ruleName {
		t.Fatalf("brute-force name = %q, want rule name", call.common.bruteForceName)
	}

	if call.common.bruteForceCounter != 3 {
		t.Fatalf("brute-force counter = %d, want 3", call.common.bruteForceCounter)
	}

	if call.common.clientNet != "203.0.113.0/24" {
		t.Fatalf("client net = %q, want stored brute-force network", call.common.clientNet)
	}

	if !call.common.repeating {
		t.Fatal("repeating = false, want true")
	}

	if call.common.environmentName != definitions.ControlBruteForce {
		t.Fatalf("environment name = %q, want brute_force", call.common.environmentName)
	}
}

func TestBruteForceLuaActionAccountRefreshPreservesCommonRequestAccountField(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	auth, _, mock := newCurrentBehaviorAuthState(t, cfg)
	mock.Regexp().ExpectHGet(".*", ".*").SetVal("account-from-cache")

	auth.refreshBruteForceLuaActionAccount()

	if got := auth.Runtime.AccountName; got != "account-from-cache" {
		t.Fatalf("account = %q, want refreshed account", got)
	}

	if got := auth.Runtime.AccountField; got != definitions.MetaUserAccount {
		t.Fatalf("account field = %q, want %q", got, definitions.MetaUserAccount)
	}

	attr, ok := auth.GetAttribute(definitions.MetaUserAccount)
	if !ok || len(attr) == 0 || attr[0] != "account-from-cache" {
		t.Fatalf("account attribute = %#v, want refreshed account", attr)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations were not met: %v", err)
	}
}

func bruteForceActionFinalDecision() *report.FinalDecision {
	return &report.FinalDecision{
		PolicyName:     "standard_brute_force_deny",
		Stage:          policy.StagePreAuth,
		Effect:         policy.DecisionDeny,
		FSMEventMarker: policy.FSMEventMarkerPreAuthDeny,
		ResponseMarker: policy.ResponseMarkerFail,
		Obligations: []report.EffectRequest{
			{
				ID: policy.ObligationLuaActionDispatch,
				Args: map[string]any{
					policy.ObligationArgAction: policy.LuaActionDispatchBruteForce,
				},
			},
		},
	}
}

func customEnforceAuthSnapshotForTest() *policyruntime.Snapshot {
	return &policyruntime.Snapshot{
		Generation:    105,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationAuthenticate: {
				policy.StageAuthDecision: {
					Stage: policy.StageAuthDecision,
					Policies: []policyruntime.CompiledPolicy{
						{
							Name:       "custom_deny_backend_success",
							Stage:      policy.StageAuthDecision,
							Operations: []policy.Operation{policy.OperationAuthenticate},
							Root: policyruntime.CompiledExpr{
								Kind:        policyruntime.ExprKindAttribute,
								AttributeID: policy.AttributeAuthenticated,
								Operator:    "is",
								Expected:    policyruntime.TypedValue{Value: true},
							},
							Then: policyruntime.DecisionPlan{
								Decision:       policy.DecisionDeny,
								OutcomeMarker:  "auth.outcome.custom_backend_deny",
								FSMEventMarker: policy.FSMEventMarkerAuthDeny,
								ResponseMarker: policy.ResponseMarkerFail,
								ResponseMessage: policyruntime.ResponseMessagePlan{
									Source:  policy.ResponseSourceLiteral,
									Literal: "Custom backend deny",
								},
							},
						},
					},
				},
			},
		},
	}
}

func policyActionTestLuaConfig(actionName string) *config.LuaSection {
	return &config.LuaSection{
		Actions: []config.LuaAction{
			{
				ActionType: actionName,
				ScriptName: actionName + "_script",
				ScriptPath: "/tmp/policy-action-test.lua",
			},
		},
	}
}

type recordedActionDispatch struct {
	common      recordedCommonRequest
	environment string
	action      definitions.LuaAction
}

type recordingPluginEffectBridge struct {
	last  report.EffectRequest
	calls int
	ok    bool
}

func (b *recordingPluginEffectBridge) ExecutePolicyEffect(_ *gin.Context, _ *StateView, effect report.EffectRequest) (bool, bool) {
	b.calls++
	b.last = effect

	return true, b.ok
}

type recordedCommonRequest struct {
	environmentName   string
	clientNet         string
	bruteForceName    string
	bruteForceCounter uint
	repeating         bool
	userFound         bool
	authenticated     bool
	noAuth            bool
}

type recordingActionDispatcher struct {
	mu    sync.Mutex
	calls []recordedActionDispatch
}

func (d *recordingActionDispatcher) Dispatch(view *StateView, environmentName string, luaAction definitions.LuaAction) {
	d.mu.Lock()
	defer d.mu.Unlock()

	call := recordedActionDispatch{environment: environmentName, action: luaAction}

	if view != nil {
		auth := view.Auth()

		commonRequest := lualib.GetCommonRequest()
		defer lualib.PutCommonRequest(commonRequest)

		auth.FillCommonRequest(commonRequest)
		commonRequest.UserFound = auth.GetAccount() != ""
		commonRequest.EnvironmentName = environmentName
		call.common = recordedCommonRequest{
			environmentName:   commonRequest.EnvironmentName,
			clientNet:         commonRequest.ClientNet,
			bruteForceName:    commonRequest.BruteForceName,
			bruteForceCounter: commonRequest.BruteForceCounter,
			repeating:         commonRequest.Repeating,
			userFound:         commonRequest.UserFound,
			authenticated:     commonRequest.Authenticated,
			noAuth:            commonRequest.NoAuth,
		}
	}

	d.calls = append(d.calls, call)
}

func (d *recordingActionDispatcher) Count() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	return len(d.calls)
}

func (d *recordingActionDispatcher) Last() recordedActionDispatch {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.calls) == 0 {
		return recordedActionDispatch{}
	}

	return d.calls[len(d.calls)-1]
}

type recordingObligationHandlers struct {
	mu              sync.Mutex
	updateCount     int
	dispatchCount   int
	postActionCount int
}

func (h *recordingObligationHandlers) updateBruteForce(*gin.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.updateCount++
}

func (h *recordingObligationHandlers) dispatchLua(*gin.Context, luaActionObligation) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.dispatchCount++

	return true
}

func (h *recordingObligationHandlers) enqueuePost(*gin.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.postActionCount++
}

func (h *recordingObligationHandlers) Total() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.updateCount + h.dispatchCount + h.postActionCount
}

func reportFinalWithMutableObligations() *report.FinalDecision {
	return &report.FinalDecision{
		PolicyName:     "custom_observe_mutable_outputs",
		Stage:          policy.StagePreAuth,
		Effect:         policy.DecisionDeny,
		FSMEventMarker: policy.FSMEventMarkerPreAuthDeny,
		ResponseMarker: policy.ResponseMarkerFail,
		Obligations: []report.EffectRequest{
			{ID: policy.ObligationBruteForceUpdate},
			{ID: policy.ObligationLuaActionDispatch, Args: map[string]any{policy.ObligationArgAction: definitions.LuaActionTLSName}},
			{ID: policy.ObligationLuaPostActionEnqueue},
		},
	}
}
