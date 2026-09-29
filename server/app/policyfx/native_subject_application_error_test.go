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

package policyfx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	authhandler "github.com/croessner/nauthilus/v4/server/handler/auth"
	handlerdeps "github.com/croessner/nauthilus/v4/server/handler/deps"

	"github.com/gin-gonic/gin"
)

const nativeSubjectApplicationErrorCorrelation = "native-subject-application-error"

// errNativeSubjectOverload mirrors the live subject plugin failure raised by an overloaded LDAP queue.
var errNativeSubjectOverload = errors.New("backend_temporary_failure: LDAP request dropped from the queue")

// nativeSubjectApplicationErrorRuntime commits one production generation whose host_sync subject source fails.
func nativeSubjectApplicationErrorRuntime(t *testing.T) (core.AuthApplicationService, *config.FileSettings) {
	t.Helper()

	core.InitPassDBResultPool()
	core.SetDefaultLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))

	probe := &nativeAuthExecutionProbe{subjectErr: errNativeSubjectOverload}
	configured, state := nativeAuthGenerationCandidateFromFixture(
		t, fmt.Sprintf(nativeSubjectBackendFixture, nativeSubjectRunIf("any")), probe,
	)
	runtime := newNativeAuthGenerationRuntime(t, configured, state)
	application := newNativeAuthApplicationWithVerifier(
		t, configured, runtime.service, nativeAuthOutcomeVerifier{authenticated: true},
	)

	return application, configured
}

// TestNativeSubjectProviderErrorSurfacesAsApplicationError pins the production cause: a failing host_sync subject
// provider aborts the admitted Policy session with an unexpected application error instead of a decision.
func TestNativeSubjectProviderErrorSurfacesAsApplicationError(t *testing.T) {
	application, _ := nativeSubjectApplicationErrorRuntime(t)

	outcome, err := authenticateNativeSubjectRequest(t, application)
	if err == nil || !strings.Contains(err.Error(), "LDAP request dropped from the queue") || outcome != nil {
		t.Fatalf("Authenticate() = %#v / %v, want the subject provider failure as application error", outcome, err)
	}
}

// TestNativeSubjectProviderErrorAnswersJSONTempFail proves the JSON endpoint answers that application error as a
// regular fail-closed temporary failure instead of a bare HTTP 500.
func TestNativeSubjectProviderErrorAnswersJSONTempFail(t *testing.T) {
	gin.SetMode(gin.TestMode)

	application, configured := nativeSubjectApplicationErrorRuntime(t)

	var logs bytes.Buffer

	deps := &handlerdeps.Deps{
		Cfg:    configured,
		Env:    config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	router := gin.New()
	router.Use(func(ctx *gin.Context) {
		requestContext, gate := core.ContextWithHTTPPostActionExecutionGate(ctx.Request.Context())
		ctx.Request = ctx.Request.WithContext(requestContext)
		ctx.Set(definitions.CtxGUIDKey, nativeSubjectApplicationErrorCorrelation)
		ctx.Next()
		gate.Complete()
	})
	authhandler.NewWithApplicationService(deps, application).Register(router.Group("/api/v1"))

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, nativeSubjectJSONRequest(t))

	assertNativeSubjectJSONTempFail(t, recorder)

	if !strings.Contains(logs.String(), "Authentication application failed") ||
		!strings.Contains(logs.String(), "LDAP request dropped from the queue") {
		t.Fatalf("application failure log = %q, want the exact subject provider cause", logs.String())
	}
}

// nativeSubjectJSONRequest builds one real JSON authentication request.
func nativeSubjectJSONRequest(t *testing.T) *http.Request {
	t.Helper()

	body, err := json.Marshal(map[string]string{
		"username":  "native@example.test",
		"password":  "native-auth-test-password",
		"client_ip": "192.0.2.35",
		"protocol":  definitions.ProtoIMAP,
	})
	if err != nil {
		t.Fatalf("marshal JSON auth request: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/json", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "192.0.2.35:43210"

	return request
}

// assertNativeSubjectJSONTempFail verifies the regular JSON temporary-failure representation.
func assertNativeSubjectJSONTempFail(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()

	if got := recorder.Header().Get("Auth-Status"); got != definitions.TempFailDefault {
		t.Fatalf("Auth-Status = %q, want %q; status=%d body=%q",
			got, definitions.TempFailDefault, recorder.Code, recorder.Body.String())
	}

	if got := recorder.Header().Get("X-Nauthilus-Session"); got != nativeSubjectApplicationErrorCorrelation {
		t.Fatalf("X-Nauthilus-Session = %q, want request correlation", got)
	}

	wantBody := `{"error":"` + definitions.TempFailDefault + `"}`
	if recorder.Code != http.StatusInternalServerError || strings.TrimSpace(recorder.Body.String()) != wantBody {
		t.Fatalf("response = %d %q, want JSON tempfail %q", recorder.Code, recorder.Body.String(), wantBody)
	}
}
