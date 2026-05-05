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
	"net/http"
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/policy"
	policycollection "github.com/croessner/nauthilus/server/policy/collection"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"
)

func TestAuthPathCollectsTLSCheckWithoutChangingFeatureDecision(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.FeatureTLSEncryption)
	cfg.ClearTextList = nil
	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation:    73,
		Mode:          "enforce",
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
					},
				},
			},
		},
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

	report := policyCtx.Report()
	if got := report.Checks["tls_encryption"].Status; got != policy.CheckStatusOK {
		t.Fatalf("tls check status = %q, want %q", got, policy.CheckStatusOK)
	}

	if got := report.Attributes["auth.tls.secure"].Value; got != false {
		t.Fatalf("tls secure attribute = %v, want false", got)
	}
}

func TestAuthBoundaryCustomObserveDoesNotChangeDefaultDecision(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.FeatureTLSEncryption)
	cfg.ClearTextList = nil
	activatePolicySnapshotForTest(t, customObserveTLSSnapshot())

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.Service = definitions.ServJSON
	auth.SetStatusCodes(auth.Request.Service)

	auth.runAuthPipelineFSM(ctx)

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	report := policyCtx.Report()
	if report.Final == nil || report.Final.PolicyName != "standard_tls_enforcement" {
		t.Fatalf("final = %#v, want authoritative TLS default", report.Final)
	}

	if report.Observe == nil || !report.Observe.Mismatch {
		t.Fatalf("observe report = %#v, want custom mismatch", report.Observe)
	}

	if report.Observe.Shadow == nil || report.Observe.Shadow.PolicyName != "custom_deny_tls" {
		t.Fatalf("custom shadow = %#v, want custom_deny_tls", report.Observe.Shadow)
	}

	if got := ctx.Writer.Status(); got != http.StatusInternalServerError {
		t.Fatalf("HTTP status = %d, want default tempfail status", got)
	}
}

func TestAuthBoundaryConfiguredPreAuthEnforceOverridesCurrentTLSResult(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.FeatureTLSEncryption)
	cfg.ClearTextList = nil
	activatePolicySnapshotForTest(t, customEnforceTLSSnapshot(customEnforceTLSDenyPolicy(false)))

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.Service = definitions.ServJSON
	auth.SetStatusCodes(auth.Request.Service)

	auth.runAuthPipelineFSM(ctx)

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	report := policyCtx.Report()
	if report.Final == nil || report.Final.PolicyName != "custom_deny_tls" {
		t.Fatalf("final = %#v, want configured TLS denial", report.Final)
	}

	if got := ctx.Writer.Status(); got != http.StatusForbidden {
		t.Fatalf("HTTP status = %d, want configured denial status", got)
	}

	if got := auth.Runtime.StatusMessage; got != "Custom TLS deny" {
		t.Fatalf("status message = %q, want configured message", got)
	}
}

func TestAuthBoundaryConfiguredPreAuthEnforceLetsUnmatchedTLSContinue(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.FeatureTLSEncryption)
	cfg.ClearTextList = nil
	activatePolicySnapshotForTest(t, customEnforceTLSSnapshot(customEnforceTLSDenyPolicy(true)))

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)

	got := auth.HandleFeatures(ctx)
	if got != definitions.AuthResultOK {
		t.Fatalf("feature result = %v, want OK", got)
	}

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	if policyCtx.Report().Final != nil {
		t.Fatalf("final = %#v, want nil", policyCtx.Report().Final)
	}
}

func TestConfiguredPreAuthControlAtBruteForceSkipsLaterChecks(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.FeatureTLSEncryption)
	cfg.ClearTextList = nil
	activatePolicySnapshotForTest(t, customEnforcePreAuthControlSnapshot())

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.recordPolicyBruteForce(ctx, true)

	if auth.applyConfiguredPreAuthDecision(ctx) {
		t.Fatal("neutral pre-auth control must not apply a terminal decision")
	}

	if !auth.applyConfiguredPreAuthControl(ctx, definitions.AuthResultFail) {
		t.Fatal("configured brute-force control was not applied")
	}

	got := auth.HandleFeatures(ctx)
	if got != definitions.AuthResultOK {
		t.Fatalf("feature result = %v, want OK", got)
	}

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	if _, exists := policyCtx.Report().Checks["tls_encryption"]; exists {
		t.Fatal("tls check was collected after pre-auth control skipped remaining checks")
	}

	if got := len(policyCtx.Report().Policies); got != 1 {
		t.Fatalf("selected policies = %d, want one configured control decision", got)
	}
}

func customObserveTLSSnapshot() *policyruntime.Snapshot {
	return &policyruntime.Snapshot{
		Generation:    74,
		Mode:          "observe",
		DefaultPolicy: policy.BuiltinDefaultSet,
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationAuthenticate: {
				policy.StagePreAuth: customObserveTLSStagePlan(),
			},
		},
	}
}

func customEnforcePreAuthControlSnapshot() *policyruntime.Snapshot {
	return &policyruntime.Snapshot{
		Generation:    76,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationAuthenticate: {
				policy.StagePreAuth: {
					Stage: policy.StagePreAuth,
					Checks: []policyruntime.CompiledCheck{
						{
							Name:       "brute_force",
							Type:       policy.CheckTypeBruteForce,
							Stage:      policy.StagePreAuth,
							Operations: []policy.Operation{policy.OperationAuthenticate},
							RunIf:      policyruntime.RunIfPlan{AuthState: policy.RunIfAny},
						},
						customObserveTLSCheck(),
					},
					Policies: []policyruntime.CompiledPolicy{customBruteForceSkipPolicy()},
				},
			},
		},
	}
}

func customEnforceTLSSnapshot(compiled policyruntime.CompiledPolicy) *policyruntime.Snapshot {
	return &policyruntime.Snapshot{
		Generation:    75,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
		StagePlans: map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan{
			policy.OperationAuthenticate: {
				policy.StagePreAuth: {
					Stage:    policy.StagePreAuth,
					Checks:   []policyruntime.CompiledCheck{customObserveTLSCheck()},
					Policies: []policyruntime.CompiledPolicy{compiled},
				},
			},
		},
	}
}

func customObserveTLSStagePlan() policyruntime.CompiledStagePlan {
	return policyruntime.CompiledStagePlan{
		Stage:    policy.StagePreAuth,
		Checks:   []policyruntime.CompiledCheck{customObserveTLSCheck()},
		Policies: []policyruntime.CompiledPolicy{customObserveTLSDenyPolicy()},
	}
}

func customObserveTLSCheck() policyruntime.CompiledCheck {
	return policyruntime.CompiledCheck{
		Name:        "tls_encryption",
		Type:        policy.CheckTypeTLSEncryption,
		Stage:       policy.StagePreAuth,
		Operations:  []policy.Operation{policy.OperationAuthenticate},
		RunIf:       policyruntime.RunIfPlan{AuthState: policy.RunIfAny},
		ObserveSafe: true,
	}
}

func customObserveTLSDenyPolicy() policyruntime.CompiledPolicy {
	return policyruntime.CompiledPolicy{
		Name:          "custom_deny_tls",
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
			Decision:       policy.DecisionDeny,
			OutcomeMarker:  "auth.outcome.custom_tls_deny",
			FSMEventMarker: policy.FSMEventMarkerPreAuthDeny,
			ResponseMarker: policy.ResponseMarkerFail,
		},
	}
}

func customEnforceTLSDenyPolicy(expected bool) policyruntime.CompiledPolicy {
	compiled := customObserveTLSDenyPolicy()
	compiled.Then.ResponseMessage = policyruntime.ResponseMessagePlan{
		Source:  "literal",
		Literal: "Custom TLS deny",
	}
	compiled.Root.Expected = policyruntime.TypedValue{Value: expected}

	return compiled
}

func customBruteForceSkipPolicy() policyruntime.CompiledPolicy {
	return policyruntime.CompiledPolicy{
		Name:          "custom_brute_force_skip",
		Stage:         policy.StagePreAuth,
		Operations:    []policy.Operation{policy.OperationAuthenticate},
		RequireChecks: []string{"brute_force"},
		Root: policyruntime.CompiledExpr{
			Kind:        policyruntime.ExprKindAttribute,
			AttributeID: policy.AttributeBruteForceTriggered,
			Operator:    "is",
			Expected:    policyruntime.TypedValue{Value: true},
		},
		Then: policyruntime.DecisionPlan{
			Decision:       policy.DecisionNeutral,
			OutcomeMarker:  "auth.outcome.custom_brute_force_skip",
			FSMEventMarker: policy.FSMEventMarkerPreAuthOK,
			Control:        policyruntime.DecisionControl{SkipRemainingStageChecks: true},
		},
	}
}

func activatePolicySnapshotForTest(t *testing.T, snapshot *policyruntime.Snapshot) {
	t.Helper()

	store := policyruntime.DefaultStore()
	previous := store.Active()
	if err := store.Activate(snapshot); err != nil {
		t.Fatalf("activate policy snapshot: %v", err)
	}

	t.Cleanup(func() {
		if previous == nil {
			previous = &policyruntime.Snapshot{}
		}

		if err := store.Activate(previous); err != nil {
			t.Fatalf("restore policy snapshot: %v", err)
		}
	})
}

func policyDecisionContext(ctx interface {
	Get(any) (any, bool)
}) (*policycollection.DecisionContext, bool) {
	value, ok := ctx.Get(policyCollectionContextKey)
	if !ok {
		return nil, false
	}

	policyCtx, ok := value.(*policycollection.DecisionContext)

	return policyCtx, ok
}
