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

package auth

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy/admission"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"

	"github.com/gin-gonic/gin"
)

// capacityRejectedHTTPRouter builds real HTTP auth routes whose Policy session admission is exhausted.
func capacityRejectedHTTPRouter(t *testing.T, logs *bytes.Buffer) (*gin.Engine, *recordingAuthApplicationService) {
	t.Helper()

	current := &recordingAuthApplicationService{}
	factory := &httpRecordingDecisionSessionFactory{
		openErr: errors.Join(decisionservice.ErrDecisionAdmission, admission.ErrConcurrencyLimitExceeded),
	}

	candidate, err := core.NewAuthnCandidateApplicationServiceWithInternalProfiles(
		current, factory, mustHTTPAuthnInternalProfiles(t),
	)
	if err != nil {
		t.Fatalf("construct candidate application service: %v", err)
	}

	deps := applicationBoundaryDeps()
	deps.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	return applicationBoundaryRouter(deps, candidate), current
}

func TestBackchannelHTTPCapacityAdmissionRejectionRendersTempFail(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		service    string
		protocol   string
		wantStatus int
		wantBody   string
		wantCode   string
	}{
		{
			name: "json", service: definitions.ServJSON, wantStatus: http.StatusInternalServerError,
			wantBody: `{"error":"` + definitions.TempFailDefault + `"}`,
		},
		{
			name: "header", service: definitions.ServHeader, wantStatus: http.StatusInternalServerError,
			wantBody: definitions.TempFailDefault,
		},
		{
			name: "nginx imap", service: definitions.ServNginx, protocol: definitions.ProtoIMAP,
			wantStatus: http.StatusOK, wantBody: definitions.TempFailDefault,
		},
		{
			name: "nginx smtp", service: definitions.ServNginx, protocol: definitions.ProtoSMTP,
			wantStatus: http.StatusOK, wantBody: definitions.TempFailDefault, wantCode: definitions.TempFailCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var logs bytes.Buffer

			router, current := capacityRejectedHTTPRouter(t, &logs)
			request := applicationBoundaryRequest(t, test.service, "")

			if test.protocol != "" {
				request.Header.Set("Auth-Protocol", test.protocol)
			}

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)

			assertCapacityTempFailResponse(t, recorder, test.wantStatus, test.wantBody, test.wantCode)

			if current.totalCalls() != 0 {
				t.Fatalf("current application calls = %d, want 0 without admission", current.totalCalls())
			}

			if strings.Contains(logs.String(), "Authentication application failed") {
				t.Fatalf("capacity rejection logged as application failure: %q", logs.String())
			}
		})
	}
}

// assertCapacityTempFailResponse verifies the established temporary-failure HTTP surface.
func assertCapacityTempFailResponse(
	t *testing.T,
	recorder *httptest.ResponseRecorder,
	wantStatus int,
	wantBody string,
	wantCode string,
) {
	t.Helper()

	if recorder.Code != wantStatus {
		t.Fatalf("HTTP status = %d, want %d; body=%q", recorder.Code, wantStatus, recorder.Body.String())
	}

	if got := recorder.Header().Get("Auth-Status"); got != definitions.TempFailDefault {
		t.Fatalf("Auth-Status = %q, want %q", got, definitions.TempFailDefault)
	}

	if got := recorder.Header().Get("X-Nauthilus-Session"); got != applicationBoundaryCorrelation {
		t.Fatalf("X-Nauthilus-Session = %q, want request correlation", got)
	}

	if got := recorder.Header().Get("Auth-Error-Code"); got != wantCode {
		t.Fatalf("Auth-Error-Code = %q, want %q", got, wantCode)
	}

	if got := strings.TrimSpace(recorder.Body.String()); got != wantBody {
		t.Fatalf("body = %q, want %q", got, wantBody)
	}
}
