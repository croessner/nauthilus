// Copyright (C) 2024 Christian Rößner
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
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	corepkg "github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"

	"github.com/gin-gonic/gin"
)

func setupConfigForResponseTests(t *testing.T) {
	t.Helper()
	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())
	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	config.SetTestFile(cfg)
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")
}

func TestResponseWriter_Fail_JSONBodyNullAndHeaders(t *testing.T) {
	setupConfigForResponseTests(t)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)

	a := &corepkg.AuthState{
		Request: corepkg.AuthRequest{
			Service:  definitions.ServJSON,
			Protocol: config.NewProtocol("imap"),
		},
		Runtime: corepkg.AuthRuntime{
			GUID: "guid-fail-json",
		},
	}
	a.SetStatusCodes(a.Request.Service)

	// Trigger failure path
	a.AuthFail(ctx)

	if w.Code != a.Runtime.StatusCodeFail {
		t.Fatalf("status code = %d, want %d", w.Code, a.Runtime.StatusCodeFail)
	}
	// Expect Auth-Status header set to default password fail message
	if got := w.Header().Get("Auth-Status"); got != definitions.PasswordFail {
		t.Fatalf("Auth-Status header = %q, want %q", got, definitions.PasswordFail)
	}
	// Expect session header
	if got := w.Header().Get("X-Nauthilus-Session"); got != a.Runtime.GUID {
		t.Fatalf("X-Nauthilus-Session = %q, want %q", got, a.Runtime.GUID)
	}

	// Body should be JSON null
	var body any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON body: %v", err)
	}
	if body != nil {
		t.Fatalf("expected JSON null body, got %#v", body)
	}
}

func TestResponseWriter_TempFail_JSONErrorBody(t *testing.T) {
	setupConfigForResponseTests(t)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/auth", nil)

	reason := "Temporary server problem"
	a := &corepkg.AuthState{
		Request: corepkg.AuthRequest{
			Service:  definitions.ServJSON,
			Protocol: config.NewProtocol("imap"),
		},
		Runtime: corepkg.AuthRuntime{
			GUID: "guid-tempfail-json",
		},
	}
	a.SetStatusCodes(a.Request.Service)

	a.AuthTempFail(ctx, reason)

	if w.Code != a.Runtime.StatusCodeInternalError {
		t.Fatalf("status code = %d, want %d", w.Code, a.Runtime.StatusCodeInternalError)
	}

	if got := w.Header().Get("Auth-Status"); got != reason {
		t.Fatalf("Auth-Status header = %q, want %q", got, reason)
	}
	if got := w.Header().Get("X-Nauthilus-Session"); got != a.Runtime.GUID {
		t.Fatalf("X-Nauthilus-Session = %q, want %q", got, a.Runtime.GUID)
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON body: %v", err)
	}
	if msg, ok := body["error"].(string); !ok || msg != reason {
		t.Fatalf("expected error field %q, got %v (present=%v)", reason, body["error"], ok)
	}
}
