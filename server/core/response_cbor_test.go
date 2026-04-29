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

package core_test

import (
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	corepkg "github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/encoding/cborcodec"

	"github.com/gin-gonic/gin"
)

func TestResponseWriter_OK_CBORBody(t *testing.T) {
	setupConfigForResponseTests(t)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("POST", "/api/v1/auth/cbor", nil)

	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	deps := corepkg.AuthDeps{Cfg: cfg}
	a := corepkg.NewAuthStateFromContextWithDeps(ctx, deps).(*corepkg.AuthState)
	a.Request.Service = definitions.ServCBOR
	a.Request.Protocol = config.NewProtocol("imap")
	a.Runtime.GUID = "guid-cbor-ok"
	a.Runtime.SourcePassDBBackend = definitions.BackendLDAP
	a.Runtime.AccountField = "account"
	a.Runtime.TOTPSecretField = "totp"
	a.ReplaceAllAttributes(map[string][]any{"dn": {"cn=user,dc=example,dc=org"}})
	a.SetStatusCodes(a.Request.Service)

	a.AuthOK(ctx)

	if got, want := w.Header().Get("Content-Type"), "application/cbor"; got != want {
		t.Fatalf("Content-Type = %q, want %q", got, want)
	}

	var body map[string]any
	if err := cborcodec.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid CBOR body: %v", err)
	}

	if ok, _ := body["ok"].(bool); !ok {
		t.Fatalf("expected ok=true in body, got %#v", body["ok"])
	}
	if got, _ := body["account_field"].(string); got != "account" {
		t.Fatalf("account_field = %q, want %q", got, "account")
	}
}

func TestResponseWriter_Fail_CBORBodyNull(t *testing.T) {
	setupConfigForResponseTests(t)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("POST", "/api/v1/auth/cbor", nil)

	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	deps := corepkg.AuthDeps{Cfg: cfg}
	a := corepkg.NewAuthStateFromContextWithDeps(ctx, deps).(*corepkg.AuthState)
	a.Request.Service = definitions.ServCBOR
	a.Request.Protocol = config.NewProtocol("imap")
	a.Runtime.GUID = "guid-cbor-fail"
	a.SetStatusCodes(a.Request.Service)

	a.AuthFail(ctx)

	if got, want := w.Header().Get("Content-Type"), "application/cbor"; got != want {
		t.Fatalf("Content-Type = %q, want %q", got, want)
	}
	if got := w.Header().Get("Auth-Status"); got != definitions.PasswordFail {
		t.Fatalf("Auth-Status header = %q, want %q", got, definitions.PasswordFail)
	}

	var body any
	if err := cborcodec.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid CBOR body: %v", err)
	}
	if body != nil {
		t.Fatalf("expected CBOR null body, got %#v", body)
	}
}

func TestResponseWriter_TempFail_CBORErrorBody(t *testing.T) {
	setupConfigForResponseTests(t)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("POST", "/api/v1/auth/cbor", nil)

	reason := "Temporary server problem"
	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	deps := corepkg.AuthDeps{Cfg: cfg}
	a := corepkg.NewAuthStateFromContextWithDeps(ctx, deps).(*corepkg.AuthState)
	a.Request.Service = definitions.ServCBOR
	a.Request.Protocol = config.NewProtocol("imap")
	a.Runtime.GUID = "guid-cbor-tempfail"
	a.SetStatusCodes(a.Request.Service)

	a.AuthTempFail(ctx, reason)

	if got, want := w.Header().Get("Content-Type"), "application/cbor"; got != want {
		t.Fatalf("Content-Type = %q, want %q", got, want)
	}

	var body map[string]string
	if err := cborcodec.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid CBOR body: %v", err)
	}
	if body["error"] != reason {
		t.Fatalf("error = %q, want %q", body["error"], reason)
	}
}
