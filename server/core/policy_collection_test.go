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
