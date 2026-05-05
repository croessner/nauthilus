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

func TestAuthBoundaryKeepsDirectOutcomeDiagnosticWhenDefaultSetOverrides(t *testing.T) {
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

	if policyCtx.Report().Observe == nil {
		t.Fatal("missing direct outcome diagnostic")
	}

	if !policyCtx.Report().Observe.Mismatch {
		t.Fatalf("observe report = %#v, want mismatch against direct outcome", policyCtx.Report().Observe)
	}

	if got := policyCtx.Report().Observe.MismatchType; got != "multiple" {
		t.Fatalf("mismatch type = %q, want multiple", got)
	}
}
