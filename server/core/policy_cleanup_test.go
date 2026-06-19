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

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/policy"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const cleanupStandardTLSEnforcementPolicy = "standard_tls_enforcement"

func TestAuthBoundaryDefaultSetDoesNotCreateMigrationObserveReportForTLSTempfail(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlTLSEncryption)
	cfg.ClearTextList = nil
	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation:    91,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
	})

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.Service = definitions.ServJSON
	auth.SetStatusCodes(auth.Request.Service)

	auth.runAuthPipelineFSM(ctx)

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	policyReport := policyCtx.Report()
	if policyReport.Final == nil {
		t.Fatal("missing final policy decision")
	}

	if policyReport.Final.PolicyName != cleanupStandardTLSEnforcementPolicy {
		t.Fatalf("policy = %q, want %s", policyReport.Final.PolicyName, cleanupStandardTLSEnforcementPolicy)
	}

	if policyReport.Final.ResponseMarker != policy.ResponseMarkerTempFailNoTLS {
		t.Fatalf("response marker = %q, want no TLS tempfail", policyReport.Final.ResponseMarker)
	}

	if policyReport.Observe != nil {
		t.Fatalf("observe report = %#v, want nil outside configured observe mode", policyReport.Observe)
	}

	if ctx.Writer.Status() != http.StatusInternalServerError {
		t.Fatalf("HTTP status = %d, want current tempfail status", ctx.Writer.Status())
	}
}
