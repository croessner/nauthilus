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
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/monitoring/authmetrics"
	"github.com/croessner/nauthilus/v3/server/stats"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestCaptureResponseWriter_OKCapturesOutcomeWithoutHTTPRendering(t *testing.T) {
	logs := &countingLogHandler{}
	capture := NewCaptureResponseWriter(slog.New(logs))
	auth, ctx, rec := newCaptureWriterTestState(t, "/api/v1/auth/json", capture)
	auth.SetLoginAttempts(3)
	auth.Runtime.AccountField = "account"
	auth.Runtime.TOTPSecretField = "totp"
	auth.Runtime.SourcePassDBBackend = definitions.BackendLDAP
	auth.ReplaceAllAttributes(map[string][]any{
		"dn": {"cn=user,dc=example,dc=org"},
	})

	acceptedBefore := protocolCounterValue(stats.GetMetrics().GetAcceptedProtocols(), "imap")
	successBefore := loginCounterValue(definitions.LabelSuccess)

	auth.AuthOK(ctx)
	assertAuthMetricMarker(t, ctx, authmetrics.OutcomeOK, "imap")

	assertNoHTTPRendering(t, rec)

	if got := auth.GetFailCount(); got != 0 {
		t.Fatalf("expected reset login attempts to 0, got %d", got)
	}

	assertCounterDelta(t, "accepted protocol", acceptedBefore, protocolCounterValue(stats.GetMetrics().GetAcceptedProtocols(), "imap"), 1)
	assertCounterDelta(t, "successful login", successBefore, loginCounterValue(definitions.LabelSuccess), 1)

	if logs.Count() == 0 {
		t.Fatal("expected structured success logging side effect")
	}

	outcome := capture.Outcome()

	assertDecisionStatusAndFSMState(t, outcome, CapturedAuthDecisionOK, authFSMStateAuthOK, auth.Runtime.StatusCodeOK)

	if outcome.Session != auth.Runtime.GUID {
		t.Fatalf("session = %q, want %q", outcome.Session, auth.Runtime.GUID)
	}

	if outcome.AccountField != "account" {
		t.Fatalf("account field = %q, want account", outcome.AccountField)
	}

	if outcome.TOTPSecretField != "totp" {
		t.Fatalf("totp secret field = %q, want totp", outcome.TOTPSecretField)
	}

	if outcome.Backend != definitions.BackendLDAP {
		t.Fatalf("backend = %v, want %v", outcome.Backend, definitions.BackendLDAP)
	}

	if len(outcome.Attributes["dn"]) != 1 {
		t.Fatalf("expected captured attributes, got %v", outcome.Attributes)
	}
}

func TestCaptureResponseWriter_FailCapturesOutcomeWithoutHTTPRendering(t *testing.T) {
	logs := &countingLogHandler{}
	capture := NewCaptureResponseWriter(slog.New(logs))
	auth, ctx, rec := newCaptureWriterTestState(t, "/api/v1/auth/json", capture)
	rejectedBefore := protocolCounterValue(stats.GetMetrics().GetRejectedProtocols(), "imap")
	failureBefore := loginCounterValue(definitions.LabelFailure)

	auth.AuthFail(ctx)
	assertAuthMetricMarker(t, ctx, authmetrics.OutcomeFail, "imap")

	assertNoHTTPRendering(t, rec)

	outcome := capture.Outcome()
	assertDecisionStatusAndFSMState(t, outcome, CapturedAuthDecisionFail, authFSMStateAuthFail, auth.Runtime.StatusCodeFail)

	if outcome.StatusMessage != definitions.PasswordFail {
		t.Fatalf("status message = %q, want %q", outcome.StatusMessage, definitions.PasswordFail)
	}

	if got := auth.GetFailCount(); got != 1 {
		t.Fatalf("expected failed login attempts to be 1, got %d", got)
	}

	assertCounterDelta(t, "rejected protocol", rejectedBefore, protocolCounterValue(stats.GetMetrics().GetRejectedProtocols(), "imap"), 1)
	assertCounterDelta(t, "failed login", failureBefore, loginCounterValue(definitions.LabelFailure), 1)

	if logs.Count() == 0 {
		t.Fatal("expected structured failure logging side effect")
	}
}

func TestCaptureResponseWriter_TempFailCapturesOutcomeWithoutHTTPRendering(t *testing.T) {
	logs := &countingLogHandler{}
	capture := NewCaptureResponseWriter(slog.New(logs))
	auth, ctx, rec := newCaptureWriterTestState(t, "/api/v1/auth/cbor", capture)

	const reason = "Temporary server problem"

	auth.AuthTempFail(ctx, reason)
	assertAuthMetricMarker(t, ctx, authmetrics.OutcomeTempFail, "imap")

	assertNoHTTPRendering(t, rec)

	outcome := capture.Outcome()
	assertDecisionStatusAndFSMState(t, outcome, CapturedAuthDecisionTempFail, authFSMStateAuthTempFail, auth.Runtime.StatusCodeInternalError)

	if outcome.StatusMessage != reason {
		t.Fatalf("status message = %q, want %q", outcome.StatusMessage, reason)
	}

	if outcome.Error != reason {
		t.Fatalf("error = %q, want %q", outcome.Error, reason)
	}

	if logs.Count() == 0 {
		t.Fatal("expected structured tempfail logging side effect")
	}
}

func TestCaptureResponseWriter_EnvironmentRejectionPreservesPostActionAndCapturesFail(t *testing.T) {
	postAction := &countingPostAction{}
	previousPostAction := getPostAction()

	RegisterPostAction(postAction)
	t.Cleanup(func() {
		RegisterPostAction(previousPostAction)
	})

	capture := NewCaptureResponseWriter(slog.New(&countingLogHandler{}))
	auth, ctx, rec := newCaptureWriterTestState(t, "/api/v1/auth/json?mode=auth", capture)

	handled := auth.applyPreAuthFSMOutcome(ctx, authFSMStateAuthFail, definitions.AuthResultPreAuthRelayDomain)
	if !handled {
		t.Fatal("expected auth FSM pre-auth outcome to be handled")
	}

	if !ctx.IsAborted() {
		t.Fatal("expected context to be aborted for environment-rejection auth fail")
	}

	assertNoHTTPRendering(t, rec)

	if postAction.Count() != 1 {
		t.Fatalf("expected one Lua post-action dispatch, got %d", postAction.Count())
	}

	outcome := capture.Outcome()
	assertDecisionStatusAndFSMState(t, outcome, CapturedAuthDecisionFail, authFSMStateAuthFail, auth.Runtime.StatusCodeFail)
}

func TestCaptureResponseWriter_InstancesKeepOutcomesIsolated(t *testing.T) {
	failCapture := NewCaptureResponseWriter(slog.New(&countingLogHandler{}))
	okCapture := NewCaptureResponseWriter(slog.New(&countingLogHandler{}))

	failAuth, failCtx, failRec := newCaptureWriterTestState(t, "/api/v1/auth/json", failCapture)
	okAuth, okCtx, okRec := newCaptureWriterTestState(t, "/api/v1/auth/json", okCapture)

	failAuth.AuthFail(failCtx)
	okAuth.AuthOK(okCtx)

	assertNoHTTPRendering(t, failRec)
	assertNoHTTPRendering(t, okRec)
	assertDecisionStatusAndFSMState(t, failCapture.Outcome(), CapturedAuthDecisionFail, authFSMStateAuthFail, failAuth.Runtime.StatusCodeFail)
	assertDecisionStatusAndFSMState(t, okCapture.Outcome(), CapturedAuthDecisionOK, authFSMStateAuthOK, okAuth.Runtime.StatusCodeOK)
}

func newCaptureWriterTestState(
	t *testing.T,
	path string,
	writer ResponseWriter,
) (*AuthState, *gin.Context, *httptest.ResponseRecorder) {
	t.Helper()

	setupMinimalTestConfig(t)

	if cfg, ok := config.GetFile().(*config.FileSettings); ok {
		cfg.Server.MaxLoginAttempts = 5
	}

	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPost, path, nil)

	logger := slog.Default()
	if capture, ok := writer.(*CaptureResponseWriter); ok && capture.logger != nil {
		logger = capture.logger
	}

	auth := NewAuthStateFromContextWithDeps(ctx, AuthDeps{
		Cfg:    config.GetFile(),
		Logger: logger,
		Resp:   writer,
	}).(*AuthState)

	auth.Request.Service = definitions.ServJSON
	if path == "/api/v1/auth/cbor" {
		auth.Request.Service = definitions.ServCBOR
	}

	auth.Request.Protocol = config.NewProtocol("imap")
	auth.Runtime.GUID = "guid-capture-test"
	auth.SetStatusCodes(auth.Request.Service)

	return auth, ctx, rec
}

func assertNoHTTPRendering(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()

	if rec.Body.Len() != 0 {
		t.Fatalf("expected empty HTTP body, got %q", rec.Body.String())
	}

	if len(rec.Header()) != 0 {
		t.Fatalf("expected no HTTP headers, got %v", rec.Header())
	}
}

// assertAuthMetricMarker verifies request-local terminal metric metadata.
func assertAuthMetricMarker(t *testing.T, ctx *gin.Context, wantOutcome string, wantProtocol string) {
	t.Helper()

	if got := ctx.GetString(definitions.CtxAuthOutcomeKey); got != wantOutcome {
		t.Fatalf("auth metric outcome = %q, want %q", got, wantOutcome)
	}

	if got := ctx.GetString(definitions.CtxAuthProtocolKey); got != wantProtocol {
		t.Fatalf("auth metric protocol = %q, want %q", got, wantProtocol)
	}
}

func assertDecisionStatusAndFSMState(
	t *testing.T,
	outcome CapturedAuthOutcome,
	wantDecision CapturedAuthDecision,
	wantState authFSMState,
	wantStatus int,
) {
	t.Helper()

	if outcome.Decision != wantDecision {
		t.Fatalf("decision = %q, want %q", outcome.Decision, wantDecision)
	}

	if outcome.TerminalState != string(wantState) {
		t.Fatalf("terminal state = %q, want %q", outcome.TerminalState, wantState)
	}

	if outcome.HTTPStatus != wantStatus {
		t.Fatalf("HTTP status = %d, want %d", outcome.HTTPStatus, wantStatus)
	}
}

func protocolCounterValue(counter *prometheus.CounterVec, label string) float64 {
	return testutil.ToFloat64(counter.WithLabelValues(label))
}

func loginCounterValue(label string) float64 {
	return testutil.ToFloat64(stats.GetMetrics().GetLoginsCounter().WithLabelValues(label))
}

func assertCounterDelta(t *testing.T, name string, before, after, want float64) {
	t.Helper()

	if got := after - before; got != want {
		t.Fatalf("%s delta = %v, want %v", name, got, want)
	}
}

type countingLogHandler struct {
	count atomic.Int64
}

func (h *countingLogHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *countingLogHandler) Handle(context.Context, slog.Record) error {
	h.count.Add(1)

	return nil
}

func (h *countingLogHandler) WithAttrs([]slog.Attr) slog.Handler {
	return h
}

func (h *countingLogHandler) WithGroup(string) slog.Handler {
	return h
}

func (h *countingLogHandler) Count() int64 {
	return h.count.Load()
}

type countingPostAction struct {
	count atomic.Int64
}

func (p *countingPostAction) Run(PostActionInput) {
	p.count.Add(1)
}

func (p *countingPostAction) Count() int64 {
	return p.count.Load()
}
