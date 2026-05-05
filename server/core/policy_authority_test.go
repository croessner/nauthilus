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
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/policy"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"
)

func TestAuthBoundaryDefaultSetSelectsPreAuthDecisionDuringFeatureHandling(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.FeatureTLSEncryption)
	cfg.ClearTextList = nil
	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation:    101,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
	})

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	got := auth.HandleFeatures(ctx)
	if got != definitions.AuthResultFeatureTLS {
		t.Fatalf("feature result = %v, want %v", got, definitions.AuthResultFeatureTLS)
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

func TestAuthBoundaryDefaultSetAppliesTargetFSMForDirectPreAuthDecision(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.FeatureTLSEncryption)
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
	cfg := newCurrentBehaviorConfig(t, definitions.FeatureTLSEncryption)
	cfg.ClearTextList = nil
	activatePolicySnapshotForTest(t, customEnforceAuthSnapshotForTest())

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	got := auth.HandleFeatures(ctx)
	if got != definitions.AuthResultFeatureTLS {
		t.Fatalf("feature result = %v, want %v", got, definitions.AuthResultFeatureTLS)
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
									Source:  "literal",
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
