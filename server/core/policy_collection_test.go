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
