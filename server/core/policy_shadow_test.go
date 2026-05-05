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
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"
)

func TestAuthBoundaryRecordsStandardAuthShadowForTLSTempfail(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.FeatureTLSEncryption)
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
		t.Fatal("missing shadow final decision")
	}

	if policyReport.Final.PolicyName != "standard_tls_enforcement" {
		t.Fatalf("shadow policy = %q, want standard_tls_enforcement", policyReport.Final.PolicyName)
	}

	if policyReport.Final.ResponseMarker != "auth.response.tempfail.no_tls" {
		t.Fatalf("response marker = %q, want no TLS tempfail", policyReport.Final.ResponseMarker)
	}

	if policyReport.Observe == nil || policyReport.Observe.Mismatch {
		t.Fatalf("observe report = %#v, want no mismatch", policyReport.Observe)
	}

	if ctx.Writer.Status() != http.StatusInternalServerError {
		t.Fatalf("HTTP status = %d, want current tempfail status", ctx.Writer.Status())
	}
}
