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
	"slices"
	"sync/atomic"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
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

	if logs.Count() != 0 {
		t.Fatalf("CBOR tempfail logs = %d, want established no-log behavior", logs.Count())
	}
}

func TestCaptureResponseWriter_EnvironmentRejectionCapturesFail(t *testing.T) {
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

func TestCaptureResponseWriter_CapturesDetachedHeaderMutationsAndResponseSettings(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.FileSettings{Server: &config.ServerSection{
		IMAPBackendAddress: "generation-one.example.test",
		IMAPBackendPort:    1993,
		NginxWaitDelay:     4,
		Frontend:           config.Frontend{DefaultLanguage: "de"},
	}}
	logger := slog.New(&countingLogHandler{})
	capture := NewDefaultCaptureResponseWriter(ResponseDeps{Cfg: cfg, Logger: logger})
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/json", nil)
	auth := NewAuthStateFromContextWithDeps(ctx, AuthDeps{Cfg: cfg, Logger: logger, Resp: capture}).(*AuthState)
	auth.Request.Service = definitions.ServJSON
	auth.Request.Protocol = config.NewProtocol(definitions.ProtoIMAP)
	auth.Runtime.GUID = "capture-mutation-session"
	auth.SetStatusCodes(auth.Request.Service)

	recorder.Header().Set("X-Delete-Me", "synthetic")
	auth.ApplyPluginResponseMutation(ctx, pluginapi.ResponseMutation{
		Headers: pluginapi.ResponseHeaderMutation{
			Set: map[string][]string{
				"X-Keep-Me":   {"one", "two"},
				"X-Cancel-Me": {"before-delete"},
			},
			Delete: []string{"X-Delete-Me", "X-Cancel-Me"},
		},
	})
	auth.ApplyPluginResponseMutation(ctx, pluginapi.ResponseMutation{
		Headers: pluginapi.ResponseHeaderMutation{
			Set: map[string][]string{"X-Cancel-Me": {"restored"}},
		},
	})

	cfg.Server.IMAPBackendAddress = "generation-two.example.test"
	cfg.Server.IMAPBackendPort = 2993
	cfg.Server.NginxWaitDelay = 9
	cfg.Server.Frontend.DefaultLanguage = "en"

	auth.AuthFail(ctx)

	outcome := capture.Outcome()
	assertCapturedHeaderMutationOutcome(t, outcome)

	outcome.ResponseHeaders.Set("X-Keep-Me", "mutated")
	outcome.ResponseHeaderDeletes[0] = "X-Mutated"
	second := capture.Outcome()
	assertDetachedHeaderMutationOutcome(t, second)
}

func TestListAccountsOutcomeFromCapturedPreservesCompleteTerminalProjection(t *testing.T) {
	captured := CapturedAuthOutcome{
		ResponseHeaders:         http.Header{"X-List-Policy": {"selected"}},
		ResponseHeaderDeletes:   []string{"X-Delete-List"},
		ResponseSettings:        AuthResponseSettings{DefaultLanguage: "de", Captured: true},
		FSMEventPath:            []string{"parse_ok", "policy_terminal"},
		Decision:                CapturedAuthDecisionTempFail,
		TerminalState:           string(authFSMStateAuthTempFail),
		Session:                 "list-terminal-session",
		StatusMessage:           definitions.TempFailDefault,
		StatusMessageI18NKey:    "auth.list.tempfail",
		ResponseLanguage:        "de",
		Error:                   definitions.TempFailDefault,
		Protocol:                definitions.ProtoIMAP,
		HTTPStatus:              http.StatusInternalServerError,
		LoginAttempts:           3,
		MemoryCacheHit:          true,
		DelayedResponseEligible: true,
	}

	outcome := listAccountsOutcomeFromCaptured(captured)
	captured.ResponseHeaders.Set("X-List-Policy", "mutated")
	captured.ResponseHeaderDeletes[0] = "X-Mutated"
	captured.FSMEventPath[0] = "mutated"

	if outcome.Decision != AuthDecisionTempFail ||
		outcome.TerminalState != string(authFSMStateAuthTempFail) ||
		outcome.Protocol != definitions.ProtoIMAP ||
		outcome.LoginAttempts != 3 ||
		!outcome.MemoryCacheHit ||
		!outcome.DelayedResponseEligible {
		t.Fatalf("list terminal projection = %#v, want complete captured metadata", outcome)
	}

	if got := outcome.ResponseHeaders.Get("X-List-Policy"); got != "selected" {
		t.Fatalf("detached list response header = %q, want selected", got)
	}

	if got := outcome.ResponseHeaderDeletes; len(got) != 1 || got[0] != "X-Delete-List" {
		t.Fatalf("detached list deletes = %#v, want [X-Delete-List]", got)
	}

	if got := outcome.FSMEventPath; len(got) != 2 || got[0] != "parse_ok" {
		t.Fatalf("detached list FSM path = %#v, want original path", got)
	}
}

func TestListAccountsSuccessOutcomeCapturesResponseMutationsWithoutTerminalWriter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/auth/json?mode=list-accounts", nil)
	ctx.Set(definitions.CtxLocalCacheAuthKey, true)
	auth := NewAuthStateFromContextWithDeps(ctx, AuthDeps{Cfg: cfg, Logger: slog.Default()}).(*AuthState)
	auth.Request.Service = definitions.ServJSON
	auth.Request.Protocol = config.NewProtocol(definitions.ProtoIMAP)
	auth.Runtime.GUID = "list-success-session"

	recorder.Header().Set("X-Delete-List", "synthetic")
	auth.ApplyPluginResponseMutation(ctx, pluginapi.ResponseMutation{
		Headers: pluginapi.ResponseHeaderMutation{
			Set:    map[string][]string{"X-List-Policy": {"selected"}},
			Delete: []string{"X-Delete-List"},
		},
	})

	accounts := AccountList{"alice@example.test"}
	outcome := listAccountsSuccessOutcome(auth, ctx, accounts)
	accounts[0] = "mutated"

	if outcome.Decision != AuthDecisionOK || !outcome.MemoryCacheHit {
		t.Fatalf("list success metadata = %#v, want success/cache hit", outcome)
	}

	if got := outcome.ResponseHeaders.Get("X-List-Policy"); got != "selected" {
		t.Fatalf("X-List-Policy = %q, want selected", got)
	}

	if got := outcome.ResponseHeaderDeletes; len(got) != 1 || got[0] != "X-Delete-List" {
		t.Fatalf("list success deletes = %#v, want [X-Delete-List]", got)
	}

	if got := outcome.Accounts[0]; got != "alice@example.test" {
		t.Fatalf("detached account = %q, want alice@example.test", got)
	}
}

// assertCapturedHeaderMutationOutcome verifies the captured response mutation and config snapshot.
func assertCapturedHeaderMutationOutcome(t *testing.T, outcome CapturedAuthOutcome) {
	t.Helper()

	if got := outcome.ResponseHeaderDeletes; !slices.Equal(got, []string{"X-Delete-Me"}) {
		t.Fatalf("response header deletes = %#v, want [X-Delete-Me]", got)
	}

	if got := outcome.ResponseHeaders.Values("X-Keep-Me"); !slices.Equal(got, []string{"one", "two"}) {
		t.Fatalf("captured X-Keep-Me = %#v, want [one two]", got)
	}

	if got := outcome.ResponseHeaders.Get("X-Cancel-Me"); got != "restored" {
		t.Fatalf("captured X-Cancel-Me = %q, want restored", got)
	}

	settings := outcome.ResponseSettings

	if !settings.Captured {
		t.Fatalf("response settings = %#v, want captured generation-one snapshot", settings)
	}

	if settings.IMAPBackendAddress != "generation-one.example.test" {
		t.Fatalf("IMAP backend address = %q, want generation-one.example.test", settings.IMAPBackendAddress)
	}

	if settings.IMAPBackendPort != 1993 {
		t.Fatalf("IMAP backend port = %d, want 1993", settings.IMAPBackendPort)
	}

	if settings.NginxWaitDelay != 4 {
		t.Fatalf("nginx wait delay = %d, want 4", settings.NginxWaitDelay)
	}

	if settings.DefaultLanguage != "de" {
		t.Fatalf("default language = %q, want de", settings.DefaultLanguage)
	}
}

// assertDetachedHeaderMutationOutcome verifies that callers receive detached response metadata.
func assertDetachedHeaderMutationOutcome(t *testing.T, outcome CapturedAuthOutcome) {
	t.Helper()

	if got := outcome.ResponseHeaders.Values("X-Keep-Me"); !slices.Equal(got, []string{"one", "two"}) {
		t.Fatalf("detached X-Keep-Me = %#v, want [one two]", got)
	}

	if got := outcome.ResponseHeaderDeletes; !slices.Equal(got, []string{"X-Delete-Me"}) {
		t.Fatalf("detached deletes = %#v, want [X-Delete-Me]", got)
	}
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
		Cfg:          config.GetFile(),
		Logger:       logger,
		Resp:         writer,
		HostServices: registeredAuthnHostServices(),
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
