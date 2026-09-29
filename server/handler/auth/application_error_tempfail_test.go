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
	handlerdeps "github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/monitoring/authmetrics"
	"github.com/croessner/nauthilus/v4/server/stats"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const applicationErrorLogMessage = "Authentication application failed"

// errHTTPApplicationFailure mirrors an unexpected host-provider failure below the application boundary.
var errHTTPApplicationFailure = errors.New(
	`authn Policy decision session: execute authn host provider "plugin_subject": LDAP request dropped from the queue`,
)

// applicationErrorRouter serves real auth routes and records the terminal outcome published for metrics.
func applicationErrorRouter(
	deps *handlerdeps.Deps,
	service core.AuthApplicationService,
	observed *string,
) *gin.Engine {
	router := gin.New()
	router.Use(func(ctx *gin.Context) {
		requestContext, gate := core.ContextWithHTTPPostActionExecutionGate(ctx.Request.Context())
		ctx.Request = ctx.Request.WithContext(requestContext)
		ctx.Set(definitions.CtxGUIDKey, applicationBoundaryCorrelation)
		ctx.Next()
		*observed = ctx.GetString(definitions.CtxAuthOutcomeKey)

		gate.Complete()
	})
	NewWithApplicationService(deps, service).Register(router.Group("/api/v1"))

	return router
}

// applicationErrorDeps returns boundary dependencies whose logger writes into logs.
func applicationErrorDeps(logs *bytes.Buffer) *handlerdeps.Deps {
	deps := applicationBoundaryDeps()
	deps.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	return deps
}

// httpApplicationErrorCount reads the HTTP application error counter.
func httpApplicationErrorCount() float64 {
	return testutil.ToFloat64(stats.GetMetrics().GetAuthApplicationErrorsTotal().WithLabelValues(authmetrics.TransportHTTP))
}

func TestHTTPUnexpectedApplicationErrorRendersTempFail(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, surface := range httpTempFailSurfaceCases() {
		for _, mode := range []string{"", "no-auth", "list-accounts"} {
			t.Run(surface.name+"/mode="+mode, func(t *testing.T) {
				var (
					logs     bytes.Buffer
					observed string
				)

				router := applicationErrorRouter(
					applicationErrorDeps(&logs), failingAuthApplicationService{err: errHTTPApplicationFailure}, &observed,
				)
				before := httpApplicationErrorCount()
				recorder := httptest.NewRecorder()

				router.ServeHTTP(recorder, surface.request(t, mode))

				surface.assert(t, recorder)

				if observed != string(core.AuthDecisionTempFail) {
					t.Fatalf("published auth outcome = %q, want %q", observed, core.AuthDecisionTempFail)
				}

				if delta := httpApplicationErrorCount() - before; delta != 1 {
					t.Fatalf("HTTP application error counter delta = %v, want 1", delta)
				}

				for _, want := range []string{
					"level=ERROR", applicationErrorLogMessage, "LDAP request dropped from the queue",
					applicationBoundaryCorrelation, "transport=" + authmetrics.TransportHTTP,
				} {
					if !strings.Contains(logs.String(), want) {
						t.Fatalf("application failure log = %q, want %q", logs.String(), want)
					}
				}
			})
		}
	}
}

func TestHTTPTypedApplicationErrorsKeepTheirMapping(t *testing.T) {
	gin.SetMode(gin.TestMode)

	rejected := recordingAuthOutcome(core.AuthInput{})
	rejected.Decision = core.AuthDecisionFail
	rejected.HTTPStatus = http.StatusForbidden
	rejected.StatusMessage = "preprocess rejected"

	tests := []struct {
		err        error
		name       string
		wantStatus int
	}{
		{name: "input", err: &core.AuthInputError{Field: "username", Reason: "required"}, wantStatus: http.StatusBadRequest},
		{name: "permission", err: &core.AuthPermissionDeniedError{Reason: "scope"}, wantStatus: http.StatusForbidden},
		{name: "preprocess", err: &core.AuthPreprocessRejectedError{Outcome: rejected}, wantStatus: http.StatusForbidden},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var (
				logs     bytes.Buffer
				observed string
			)

			router := applicationErrorRouter(applicationErrorDeps(&logs), failingAuthApplicationService{err: test.err}, &observed)
			before := httpApplicationErrorCount()
			recorder := httptest.NewRecorder()

			router.ServeHTTP(recorder, applicationBoundaryRequest(t, definitions.ServJSON, ""))

			if recorder.Code != test.wantStatus {
				t.Fatalf("HTTP status = %d, want %d", recorder.Code, test.wantStatus)
			}

			if recorder.Header().Get("Auth-Status") == definitions.TempFailDefault {
				t.Fatal("typed application error rendered as temporary failure")
			}

			if delta := httpApplicationErrorCount() - before; delta != 0 {
				t.Fatalf("HTTP application error counter delta = %v, want 0 for typed errors", delta)
			}

			if strings.Contains(logs.String(), applicationErrorLogMessage) {
				t.Fatalf("typed application error logged as internal failure: %q", logs.String())
			}
		})
	}
}
