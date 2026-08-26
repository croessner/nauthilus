// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/encoding/cborcodec"

	"github.com/gin-gonic/gin"
)

type httpAuthSuccessSurfaceCase struct {
	name       string
	service    string
	wantHeader string
	wantServer string
	wantMedia  string
	wantCache  string
	cacheHit   bool
	wantBody   bool
}

type httpAuthTerminalSurfaceCase struct {
	name         string
	service      string
	protocol     string
	wantBody     string
	wantMedia    string
	decision     AuthDecision
	status       int
	wantSMTPCode bool
}

func TestHTTPAuthResponseRendererPreservesBackchannelSuccessSurfaces(t *testing.T) {
	gin.SetMode(gin.TestMode)

	renderer := NewHTTPAuthResponseRenderer(httpAuthResponseTestDeps())
	tests := []httpAuthSuccessSurfaceCase{
		{name: "json cache hit", service: definitions.ServJSON, cacheHit: true, wantBody: true, wantMedia: authMediaTypeJSON, wantCache: "Hit"},
		{name: "cbor cache miss", service: definitions.ServCBOR, wantBody: true, wantMedia: authMediaTypeCBOR, wantCache: "Miss"},
		{name: "header", service: definitions.ServHeader, wantHeader: "value", wantCache: "Miss"},
		{name: "nginx", service: definitions.ServNginx, wantServer: "imap.backend.test", wantCache: "Miss"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runHTTPAuthSuccessSurfaceCase(t, renderer, test)
		})
	}
}

// runHTTPAuthSuccessSurfaceCase renders and verifies one successful response surface.
func runHTTPAuthSuccessSurfaceCase(
	t *testing.T,
	renderer *HTTPAuthResponseRenderer,
	test httpAuthSuccessSurfaceCase,
) {
	t.Helper()

	ctx, recorder := newHTTPAuthResponseTestContext(http.MethodPost, "/api/v1/auth/"+test.service)
	input := AuthInput{
		Credentials: NewCredentials(WithUsername("alice@example.test")),
		Context:     NewAuthContext(WithProtocol(definitions.ProtoIMAP)),
		Mode:        AuthModeAuthenticate,
		Service:     test.service,
	}
	outcome := &AuthOutcome{
		Attributes: bktype.AttributeMapping{
			"uid":    {"alice@example.test"},
			"custom": {"value"},
		},
		Decision:        AuthDecisionOK,
		Session:         "response-session",
		Account:         "alice@example.test",
		AccountField:    "uid",
		TOTPSecretField: "totp_secret",
		Backend:         definitions.BackendTest,
		HTTPStatus:      http.StatusOK,
		MemoryCacheHit:  test.cacheHit,
	}

	renderer.RenderAuth(ctx, input, outcome)
	assertHTTPAuthSuccessSurface(t, recorder, test)
	assertHTTPAuthStructuredSuccessBody(t, recorder, test.service)
}

// assertHTTPAuthSuccessSurface verifies the common and service-specific success projection.
func assertHTTPAuthSuccessSurface(
	t *testing.T,
	recorder *httptest.ResponseRecorder,
	test httpAuthSuccessSurfaceCase,
) {
	t.Helper()

	if got := recorder.Header().Get("Auth-Status"); got != "OK" {
		t.Fatalf("Auth-Status = %q, want OK", got)
	}

	if got := recorder.Header().Get("Auth-User"); got != "alice@example.test" {
		t.Fatalf("Auth-User = %q, want mapped account", got)
	}

	if got := recorder.Header().Get("X-Nauthilus-Memory-Cache"); got != test.wantCache {
		t.Fatalf("memory-cache header = %q, want %q", got, test.wantCache)
	}

	if test.wantHeader != "" && recorder.Header().Get("X-Nauthilus-custom") != test.wantHeader {
		t.Fatalf("attribute header = %q, want %q", recorder.Header().Get("X-Nauthilus-custom"), test.wantHeader)
	}

	if test.wantServer != "" && recorder.Header().Get("Auth-Server") != test.wantServer {
		t.Fatalf("Auth-Server = %q, want %q", recorder.Header().Get("Auth-Server"), test.wantServer)
	}

	if test.wantMedia != "" && !strings.HasPrefix(recorder.Header().Get("Content-Type"), test.wantMedia) {
		t.Fatalf("Content-Type = %q, want prefix %q", recorder.Header().Get("Content-Type"), test.wantMedia)
	}

	if test.wantBody && recorder.Body.Len() == 0 {
		t.Fatal("structured response body is empty")
	}
}

// assertHTTPAuthStructuredSuccessBody verifies the stable JSON success envelope when selected.
func assertHTTPAuthStructuredSuccessBody(t *testing.T, recorder *httptest.ResponseRecorder, service string) {
	t.Helper()

	if service != definitions.ServJSON {
		return
	}

	var body authResponse

	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode JSON response: %v", err)
	}

	if !body.OK || body.AccountField != "uid" || body.TOTPSecret != "" {
		t.Fatalf("JSON response = %#v, want established success envelope", body)
	}
}

func TestHTTPAuthResponseRendererPreservesFailureAndTempFailSurfaces(t *testing.T) {
	gin.SetMode(gin.TestMode)

	renderer := NewHTTPAuthResponseRenderer(httpAuthResponseTestDeps())
	tests := []httpAuthTerminalSurfaceCase{
		{name: "json deny", service: definitions.ServJSON, protocol: definitions.ProtoIMAP, decision: AuthDecisionFail, status: http.StatusForbidden, wantBody: "null", wantMedia: authMediaTypeJSON},
		{name: "cbor deny", service: definitions.ServCBOR, protocol: definitions.ProtoIMAP, decision: AuthDecisionFail, status: http.StatusForbidden, wantMedia: authMediaTypeCBOR},
		{name: "header deny", service: definitions.ServHeader, protocol: definitions.ProtoIMAP, decision: AuthDecisionFail, status: http.StatusForbidden, wantBody: "null", wantMedia: authMediaTypeJSON},
		{name: "nginx deny", service: definitions.ServNginx, protocol: definitions.ProtoIMAP, decision: AuthDecisionFail, status: http.StatusOK, wantBody: "null", wantMedia: authMediaTypeJSON},
		{name: "json tempfail", service: definitions.ServJSON, protocol: definitions.ProtoIMAP, decision: AuthDecisionTempFail, status: http.StatusInternalServerError, wantMedia: authMediaTypeJSON},
		{name: "cbor tempfail", service: definitions.ServCBOR, protocol: definitions.ProtoIMAP, decision: AuthDecisionTempFail, status: http.StatusInternalServerError, wantMedia: authMediaTypeCBOR},
		{name: "header tempfail", service: definitions.ServHeader, protocol: definitions.ProtoIMAP, decision: AuthDecisionTempFail, status: http.StatusInternalServerError, wantBody: definitions.TempFailDefault, wantMedia: authMediaTypeText},
		{name: "nginx smtp tempfail", service: definitions.ServNginx, protocol: definitions.ProtoSMTP, decision: AuthDecisionTempFail, status: http.StatusOK, wantBody: definitions.TempFailDefault, wantMedia: authMediaTypeText, wantSMTPCode: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runHTTPAuthTerminalSurfaceCase(t, renderer, test)
		})
	}
}

// runHTTPAuthTerminalSurfaceCase renders and verifies one terminal response surface.
func runHTTPAuthTerminalSurfaceCase(
	t *testing.T,
	renderer *HTTPAuthResponseRenderer,
	test httpAuthTerminalSurfaceCase,
) {
	t.Helper()

	ctx, recorder := newHTTPAuthResponseTestContext(http.MethodGet, "/api/v1/auth/"+test.service)
	input := AuthInput{
		Context: NewAuthContext(WithProtocol(test.protocol)),
		Mode:    AuthModeAuthenticate,
		Service: test.service,
	}
	outcome := &AuthOutcome{
		Decision:      test.decision,
		Session:       "terminal-session",
		StatusMessage: terminalResponseMessage(test.decision),
		Error:         definitions.TempFailDefault,
		HTTPStatus:    test.status,
		LoginAttempts: 3,
	}

	renderer.RenderAuth(ctx, input, outcome)
	assertHTTPAuthTerminalSurface(t, recorder, test)
	assertTerminalResponseBody(t, recorder, test.service, test.decision, test.wantBody)
}

// assertHTTPAuthTerminalSurface verifies status and headers for one terminal response.
func assertHTTPAuthTerminalSurface(
	t *testing.T,
	recorder *httptest.ResponseRecorder,
	test httpAuthTerminalSurfaceCase,
) {
	t.Helper()

	if recorder.Code != test.status {
		t.Fatalf("HTTP status = %d, want %d", recorder.Code, test.status)
	}

	if got := recorder.Header().Get("Auth-Status"); got != terminalResponseMessage(test.decision) {
		t.Fatalf("Auth-Status = %q, want %q", got, terminalResponseMessage(test.decision))
	}

	if test.decision == AuthDecisionFail && recorder.Header().Get("Auth-Wait") == "" {
		t.Fatal("Auth-Wait is missing")
	}

	if test.wantSMTPCode && recorder.Header().Get("Auth-Error-Code") != definitions.TempFailCode {
		t.Fatalf("Auth-Error-Code = %q, want %q", recorder.Header().Get("Auth-Error-Code"), definitions.TempFailCode)
	}

	if test.wantMedia != "" && !strings.HasPrefix(recorder.Header().Get("Content-Type"), test.wantMedia) {
		t.Fatalf("Content-Type = %q, want prefix %q", recorder.Header().Get("Content-Type"), test.wantMedia)
	}
}

func TestHTTPAuthResponseRendererReplaysLocalizationAndHeaderMutations(t *testing.T) {
	gin.SetMode(gin.TestMode)

	resolver := &httpAuthResponseRecordingResolver{
		wantDefault: "de",
		resolved: localization.ResolvedStatusMessage{
			Text:     "Lokalisierte Ablehnung",
			Language: "de",
		},
	}
	deps := httpAuthResponseTestDeps()
	deps.Resolver = resolver
	renderer := NewHTTPAuthResponseRenderer(deps)
	ctx, recorder := newHTTPAuthResponseTestContext(http.MethodPost, "/api/v1/auth/json")
	ctx.Request.Header.Set("Accept-Language", "en")
	recorder.Header().Set("X-Delete-Me", "transport-value")

	outcome := &AuthOutcome{
		ResponseHeaders:       http.Header{"X-Plugin-Selected": {"one", "two"}},
		ResponseHeaderDeletes: []string{"X-Delete-Me"},
		ResponseSettings: AuthResponseSettings{
			DefaultLanguage: "de",
			Captured:        true,
		},
		Decision:             AuthDecisionFail,
		Session:              "localized-session",
		StatusMessage:        "Policy denial",
		StatusMessageI18NKey: "auth.policy.denied",
		HTTPStatus:           http.StatusForbidden,
	}

	renderer.RenderAuth(ctx, AuthInput{Mode: AuthModeAuthenticate, Service: definitions.ServJSON}, outcome)

	if resolver.calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", resolver.calls)
	}

	if got := recorder.Header().Values("X-Plugin-Selected"); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("plugin header values = %#v, want [one two]", got)
	}

	if got := recorder.Header().Get("X-Delete-Me"); got != "" {
		t.Fatalf("deleted header = %q, want empty", got)
	}

	if got := recorder.Header().Get("Auth-Status"); got != "Lokalisierte Ablehnung" {
		t.Fatalf("Auth-Status = %q, want localized value", got)
	}

	if got := recorder.Header().Get("Content-Language"); got != "de" {
		t.Fatalf("Content-Language = %q, want de", got)
	}
}

func TestHTTPAuthResponseRendererUsesCapturedOutcomeResolver(t *testing.T) {
	gin.SetMode(gin.TestMode)

	captured := &httpAuthResponseRecordingResolver{
		wantDefault: "de",
		resolved: localization.ResolvedStatusMessage{
			Text:     "Generation eins",
			Language: "de",
		},
	}
	fallback := &httpAuthResponseRecordingResolver{
		wantDefault: "de",
		resolved: localization.ResolvedStatusMessage{
			Text:     "Generation zwei",
			Language: "de",
		},
	}
	deps := httpAuthResponseTestDeps()
	deps.Resolver = fallback
	renderer := NewHTTPAuthResponseRenderer(deps)
	ctx, recorder := newHTTPAuthResponseTestContext(http.MethodPost, "/api/v1/auth/json")
	outcome := &AuthOutcome{
		MessageResolver:      captured,
		ResponseSettings:     AuthResponseSettings{DefaultLanguage: "de", Captured: true},
		Decision:             AuthDecisionFail,
		Session:              "captured-resolver-session",
		StatusMessage:        "Policy denial",
		StatusMessageI18NKey: "auth.policy.denied",
		HTTPStatus:           http.StatusForbidden,
	}

	renderer.RenderAuth(ctx, AuthInput{Mode: AuthModeAuthenticate, Service: definitions.ServJSON}, outcome)

	if captured.calls != 1 || fallback.calls != 0 {
		t.Fatalf("captured/fallback resolver calls = %d/%d, want 1/0", captured.calls, fallback.calls)
	}

	if got := recorder.Header().Get("Auth-Status"); got != "Generation eins" {
		t.Fatalf("Auth-Status = %q, want captured-generation message", got)
	}
}

func TestHTTPAuthResponseRendererUsesCapturedResponseSettingsGeneration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	renderer := newCapturedSettingsTestRenderer()
	settings := AuthResponseSettings{
		IMAPBackendAddress: "old.backend.test",
		DefaultLanguage:    "de",
		IMAPBackendPort:    1993,
		NginxWaitDelay:     2,
		Captured:           true,
	}

	t.Run("nginx fallback", func(t *testing.T) {
		assertCapturedNginxFallback(t, renderer, settings)
	})

	t.Run("wait and default language", func(t *testing.T) {
		assertCapturedFailureSettings(t, renderer, settings)
	})
}

// newCapturedSettingsTestRenderer creates a renderer whose live settings differ from the captured generation.
func newCapturedSettingsTestRenderer() *HTTPAuthResponseRenderer {
	current := httpAuthResponseTestDeps()
	current.WaitDelay = snapshotWaitBruteForceService{}.WaitDelay
	current.Cfg = &config.FileSettings{Server: &config.ServerSection{
		IMAPBackendAddress: "new.backend.test",
		IMAPBackendPort:    2993,
		NginxWaitDelay:     9,
		Frontend:           config.Frontend{DefaultLanguage: "en"},
	}}
	current.Resolver = &httpAuthResponseRecordingResolver{
		wantDefault: "de",
		resolved: localization.ResolvedStatusMessage{
			Text:     "Alt",
			Language: "de",
		},
	}

	return NewHTTPAuthResponseRenderer(current)
}

// assertCapturedNginxFallback verifies backend selection from the captured generation.
func assertCapturedNginxFallback(
	t *testing.T,
	renderer *HTTPAuthResponseRenderer,
	settings AuthResponseSettings,
) {
	t.Helper()

	ctx, recorder := newHTTPAuthResponseTestContext(http.MethodPost, "/api/v1/auth/nginx")
	outcome := &AuthOutcome{
		ResponseSettings: settings,
		Decision:         AuthDecisionOK,
		Session:          "snapshot-success",
		Protocol:         definitions.ProtoIMAP,
		HTTPStatus:       http.StatusOK,
	}

	renderer.RenderAuth(ctx, AuthInput{Service: definitions.ServNginx}, outcome)

	if got := recorder.Header().Get("Auth-Server"); got != "old.backend.test" {
		t.Fatalf("Auth-Server = %q, want captured generation", got)
	}

	if got := recorder.Header().Get("Auth-Port"); got != "1993" {
		t.Fatalf("Auth-Port = %q, want captured generation", got)
	}
}

// assertCapturedFailureSettings verifies delay and localization from the captured generation.
func assertCapturedFailureSettings(
	t *testing.T,
	renderer *HTTPAuthResponseRenderer,
	settings AuthResponseSettings,
) {
	t.Helper()

	ctx, recorder := newHTTPAuthResponseTestContext(http.MethodPost, "/api/v1/auth/json")
	outcome := &AuthOutcome{
		ResponseSettings:     settings,
		Decision:             AuthDecisionFail,
		Session:              "snapshot-failure",
		StatusMessage:        "Old denial",
		StatusMessageI18NKey: "auth.old.denial",
		HTTPStatus:           http.StatusForbidden,
		LoginAttempts:        3,
	}

	renderer.RenderAuth(ctx, AuthInput{Service: definitions.ServJSON}, outcome)

	if got, want := recorder.Header().Get("Auth-Wait"), "2"; got != want {
		t.Fatalf("Auth-Wait = %q, want captured maximum %q", got, want)
	}
}

func TestHTTPAuthResponseRendererPreservesBackendHealthAffinity(t *testing.T) {
	gin.SetMode(gin.TestMode)
	BackendServers.Update([]*config.BackendServer{{Host: "127.0.0.1", Port: 993, Protocol: definitions.ProtoIMAP}})
	t.Cleanup(func() { BackendServers.Update(nil) })

	renderer := NewHTTPAuthResponseRenderer(httpAuthResponseTestDeps())
	ctx, recorder := newHTTPAuthResponseTestContext(http.MethodPost, "/api/v1/auth/nginx")
	outcome := &AuthOutcome{
		ResponseSettings: AuthResponseSettings{BackendHealthChecks: true, Captured: true},
		Decision:         AuthDecisionOK,
		Session:          "affinity-session",
		UsedBackendIP:    "10.0.0.17",
		UsedBackendPort:  1993,
		HTTPStatus:       http.StatusOK,
	}

	renderer.RenderAuth(ctx, AuthInput{Service: definitions.ServNginx}, outcome)

	if got := recorder.Header().Get("Auth-Server"); got != "10.0.0.17" {
		t.Fatalf("Auth-Server = %q, want selected backend", got)
	}

	if got := recorder.Header().Get("Auth-Port"); got != "1993" {
		t.Fatalf("Auth-Port = %q, want selected backend port", got)
	}
}

func TestHTTPAuthResponseRendererPreservesListAccountsNegotiation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		accept     string
		wantStatus int
		wantMedia  string
		wantBody   string
	}{
		{name: "json", accept: authMediaTypeJSON, wantStatus: http.StatusOK, wantMedia: authMediaTypeJSON, wantBody: `["alpha@example.test","zeta@example.test"]`},
		{name: "cbor", accept: authMediaTypeCBOR, wantStatus: http.StatusOK, wantMedia: authMediaTypeCBOR},
		{name: "text", accept: authMediaTypeText, wantStatus: http.StatusOK, wantMedia: authMediaTypeText, wantBody: "alpha@example.test\r\nzeta@example.test\r\n"},
		{name: "form", accept: authMediaTypeForm, wantStatus: http.StatusOK, wantMedia: authMediaTypeForm, wantBody: "alpha@example.test\r\nzeta@example.test\r\n"},
		{name: "unsupported", accept: "image/png", wantStatus: http.StatusUnsupportedMediaType},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			renderer := NewHTTPAuthResponseRenderer(httpAuthResponseTestDeps())
			ctx, recorder := newHTTPAuthResponseTestContext(http.MethodGet, "/api/v1/auth/json?mode=list-accounts")
			ctx.Request.Header.Set("Accept", test.accept)

			input := AuthInput{Mode: AuthModeListAccounts, Service: definitions.ServJSON}
			outcome := &ListAccountsOutcome{
				Accounts:   AccountList{"alpha@example.test", "zeta@example.test"},
				Decision:   AuthDecisionOK,
				Session:    "list-session",
				HTTPStatus: http.StatusOK,
			}

			renderer.RenderListAccounts(ctx, input, outcome)

			if recorder.Code != test.wantStatus {
				t.Fatalf("HTTP status = %d, want %d", recorder.Code, test.wantStatus)
			}

			if test.wantMedia != "" && !strings.HasPrefix(recorder.Header().Get("Content-Type"), test.wantMedia) {
				t.Fatalf("Content-Type = %q, want prefix %q", recorder.Header().Get("Content-Type"), test.wantMedia)
			}

			if test.wantBody != "" && strings.TrimSpace(recorder.Body.String()) != strings.TrimSpace(test.wantBody) {
				t.Fatalf("body = %q, want %q", recorder.Body.String(), test.wantBody)
			}

			if test.accept == authMediaTypeCBOR {
				var accounts AccountList
				if err := cborcodec.Unmarshal(recorder.Body.Bytes(), &accounts); err != nil {
					t.Fatalf("decode CBOR account list: %v", err)
				}

				if len(accounts) != 2 || accounts[0] != "alpha@example.test" || accounts[1] != "zeta@example.test" {
					t.Fatalf("CBOR accounts = %#v, want stable list", accounts)
				}
			}
		})
	}
}

func TestHTTPAuthResponseRendererPreservesListTerminalOutcomes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name     string
		decision AuthDecision
		status   int
	}{
		{name: "deny", decision: AuthDecisionFail, status: http.StatusForbidden},
		{name: "tempfail", decision: AuthDecisionTempFail, status: http.StatusInternalServerError},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			renderer := NewHTTPAuthResponseRenderer(httpAuthResponseTestDeps())
			ctx, recorder := newHTTPAuthResponseTestContext(http.MethodGet, "/api/v1/auth/json?mode=list-accounts")
			recorder.Header().Set("X-Delete-List", "transport")

			outcome := &ListAccountsOutcome{
				ResponseHeaders:         http.Header{"X-List-Policy": {"selected"}},
				ResponseHeaderDeletes:   []string{"X-Delete-List"},
				FSMEventPath:            []string{"parse_ok", "policy_terminal"},
				Decision:                test.decision,
				TerminalState:           "terminal",
				Session:                 "list-terminal-session",
				StatusMessage:           terminalResponseMessage(test.decision),
				Error:                   definitions.TempFailDefault,
				Protocol:                definitions.ProtoIMAP,
				HTTPStatus:              test.status,
				LoginAttempts:           2,
				MemoryCacheHit:          true,
				DelayedResponseEligible: true,
			}

			renderer.RenderListAccounts(ctx, AuthInput{Mode: AuthModeListAccounts, Service: definitions.ServJSON}, outcome)

			if recorder.Code != test.status {
				t.Fatalf("HTTP status = %d, want %d", recorder.Code, test.status)
			}

			if got := recorder.Header().Get("X-List-Policy"); got != "selected" {
				t.Fatalf("X-List-Policy = %q, want selected", got)
			}

			if got := recorder.Header().Get("X-Delete-List"); got != "" {
				t.Fatalf("X-Delete-List = %q, want deleted", got)
			}
		})
	}
}

func TestHTTPAuthResponseRendererListTempFailUsesRuntimeProtocol(t *testing.T) {
	gin.SetMode(gin.TestMode)

	renderer := NewHTTPAuthResponseRenderer(httpAuthResponseTestDeps())
	ctx, recorder := newHTTPAuthResponseTestContext(http.MethodGet, "/api/v1/auth/nginx?mode=list-accounts")
	input := AuthInput{
		Context: NewAuthContext(WithProtocol(definitions.ProtoSMTP)),
		Mode:    AuthModeListAccounts,
		Service: definitions.ServNginx,
	}
	outcome := &ListAccountsOutcome{
		Decision:      AuthDecisionTempFail,
		Session:       "list-runtime-protocol",
		StatusMessage: definitions.TempFailDefault,
		Error:         definitions.TempFailDefault,
		Protocol:      definitions.ProtoAccountProvider,
		HTTPStatus:    http.StatusOK,
	}

	renderer.RenderListAccounts(ctx, input, outcome)

	if got := recorder.Header().Get("Auth-Error-Code"); got != "" {
		t.Fatalf("Auth-Error-Code = %q, want absent for runtime account-provider protocol", got)
	}
}

// terminalResponseMessage returns the established message for one terminal decision.
func terminalResponseMessage(decision AuthDecision) string {
	if decision == AuthDecisionFail {
		return definitions.PasswordFail
	}

	return definitions.TempFailDefault
}

// assertTerminalResponseBody verifies the established body shape for one terminal surface.
func assertTerminalResponseBody(
	t *testing.T,
	recorder *httptest.ResponseRecorder,
	service string,
	decision AuthDecision,
	wantBody string,
) {
	t.Helper()

	if service == definitions.ServCBOR {
		if decision == AuthDecisionTempFail {
			var body map[string]string
			if err := cborcodec.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode CBOR tempfail response: %v", err)
			}

			if body[responseBodyFieldError] != definitions.TempFailDefault {
				t.Fatalf("CBOR tempfail body = %#v, want error message", body)
			}

			return
		}

		var body any
		if err := cborcodec.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode CBOR terminal response: %v", err)
		}

		if body != nil {
			t.Fatalf("CBOR deny body = %#v, want nil", body)
		}

		return
	}

	if decision == AuthDecisionTempFail && service == definitions.ServJSON {
		var body map[string]string
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode JSON tempfail response: %v", err)
		}

		if body[responseBodyFieldError] != definitions.TempFailDefault {
			t.Fatalf("JSON tempfail body = %#v, want error message", body)
		}

		return
	}

	if got := strings.TrimSpace(recorder.Body.String()); got != strings.TrimSpace(wantBody) {
		t.Fatalf("terminal body = %q, want %q", recorder.Body.String(), wantBody)
	}
}

type snapshotWaitBruteForceService struct{}

// WaitDelay returns the configured maximum so generation choice is observable.
func (snapshotWaitBruteForceService) WaitDelay(maxWaitDelay, _ uint) int {
	return int(maxWaitDelay)
}

// LoadHistories is unused by response projection tests.
func (snapshotWaitBruteForceService) LoadHistories(*gin.Context, *AuthState, string) {}

type httpAuthResponseRecordingResolver struct {
	wantDefault string
	resolved    localization.ResolvedStatusMessage
	calls       int
}

// ResolveStatusMessage records the snapshotted default language used by rendering.
func (r *httpAuthResponseRecordingResolver) ResolveStatusMessage(
	_ context.Context,
	_ localization.StatusMessage,
	preference localization.LanguagePreference,
) localization.ResolvedStatusMessage {
	r.calls++

	if preference.Default != r.wantDefault {
		return localization.ResolvedStatusMessage{Text: "wrong default: " + preference.Default}
	}

	return r.resolved
}

// httpAuthResponseTestDeps creates deterministic response dependencies.
func httpAuthResponseTestDeps() ResponseDeps {
	return ResponseDeps{
		Cfg: &config.FileSettings{Server: &config.ServerSection{
			IMAPBackendAddress: "imap.backend.test",
			IMAPBackendPort:    993,
			NginxWaitDelay:     5,
		}},
		Env:    config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		WaitDelay: func(maxWaitDelay, _ uint) int {
			return int(maxWaitDelay)
		},
	}
}

// newHTTPAuthResponseTestContext creates one isolated Gin response context.
func newHTTPAuthResponseTestContext(method string, target string) (*gin.Context, *httptest.ResponseRecorder) {
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(method, target, nil)

	return ctx, recorder
}
