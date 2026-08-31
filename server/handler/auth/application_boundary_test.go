// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	stdjson "encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/encoding/cborcodec"
	handlerdeps "github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/model/authdto"
	"github.com/gin-gonic/gin"
)

const (
	applicationBoundaryCorrelation = "http-application-correlation"
	applicationBoundaryPeer        = "192.0.2.40"
	applicationBoundaryUsername    = "alice@example.test"
	applicationBoundaryPassword    = "boundary-password"
)

type recordedAuthApplicationCall struct {
	input     core.AuthInput
	operation core.AuthMode
}

type recordingAuthApplicationService struct {
	mu    sync.Mutex
	calls []recordedAuthApplicationCall
}

type nilOutcomeAuthApplicationService struct{}

// Authenticate returns an invalid empty terminal result for fail-closed boundary coverage.
func (nilOutcomeAuthApplicationService) Authenticate(context.Context, core.AuthInput) (*core.AuthOutcome, error) {
	return nil, nil
}

// LookupIdentity returns an invalid empty terminal result for fail-closed boundary coverage.
func (nilOutcomeAuthApplicationService) LookupIdentity(context.Context, core.AuthInput) (*core.AuthOutcome, error) {
	return nil, nil
}

// ListAccounts returns an invalid empty terminal result for fail-closed boundary coverage.
func (nilOutcomeAuthApplicationService) ListAccounts(context.Context, core.AuthInput) (*core.ListAccountsOutcome, error) {
	return nil, nil
}

// Authenticate records an HTTP authenticate application call.
func (s *recordingAuthApplicationService) Authenticate(_ context.Context, input core.AuthInput) (*core.AuthOutcome, error) {
	s.record(core.AuthModeAuthenticate, input)

	return recordingAuthOutcome(input), nil
}

// LookupIdentity records an HTTP identity lookup application call.
func (s *recordingAuthApplicationService) LookupIdentity(_ context.Context, input core.AuthInput) (*core.AuthOutcome, error) {
	s.record(core.AuthModeLookupIdentity, input)

	return recordingAuthOutcome(input), nil
}

// ListAccounts records an HTTP account-list application call.
func (s *recordingAuthApplicationService) ListAccounts(_ context.Context, input core.AuthInput) (*core.ListAccountsOutcome, error) {
	s.record(core.AuthModeListAccounts, input)

	return &core.ListAccountsOutcome{
		Accounts:   core.AccountList{applicationBoundaryUsername},
		Decision:   core.AuthDecisionOK,
		Session:    applicationBoundaryCorrelation,
		HTTPStatus: http.StatusOK,
	}, nil
}

// record appends one detached application call.
func (s *recordingAuthApplicationService) record(operation core.AuthMode, input core.AuthInput) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls = append(s.calls, recordedAuthApplicationCall{operation: operation, input: input})
}

// onlyCall returns the single recorded application call.
func (s *recordingAuthApplicationService) onlyCall(t *testing.T) recordedAuthApplicationCall {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.calls) != 1 {
		t.Fatalf("application calls = %d, want 1", len(s.calls))
	}

	return s.calls[0]
}

// totalCalls returns the number of current application invocations.
func (s *recordingAuthApplicationService) totalCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.calls)
}

type protectedHTTPTransport struct{}

// Protected supplies server-observed trusted transport evidence to the HTTP adapter.
func (protectedHTTPTransport) Protected(*gin.Context) bool { return true }

func TestBackchannelHTTPSurfacesConsumeAuthApplicationBoundary(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name      string
		service   string
		mode      core.AuthMode
		queryMode string
	}{
		{name: "json authenticate", service: definitions.ServJSON, mode: core.AuthModeAuthenticate},
		{name: "json lookup identity", service: definitions.ServJSON, mode: core.AuthModeLookupIdentity, queryMode: "no-auth"},
		{name: "json list accounts", service: definitions.ServJSON, mode: core.AuthModeListAccounts, queryMode: "list-accounts"},
		{name: "cbor authenticate", service: definitions.ServCBOR, mode: core.AuthModeAuthenticate},
		{name: "cbor lookup identity", service: definitions.ServCBOR, mode: core.AuthModeLookupIdentity, queryMode: "no-auth"},
		{name: "cbor list accounts", service: definitions.ServCBOR, mode: core.AuthModeListAccounts, queryMode: "list-accounts"},
		{name: "header authenticate", service: definitions.ServHeader, mode: core.AuthModeAuthenticate},
		{name: "header lookup identity", service: definitions.ServHeader, mode: core.AuthModeLookupIdentity, queryMode: "no-auth"},
		{name: "header list accounts", service: definitions.ServHeader, mode: core.AuthModeListAccounts, queryMode: "list-accounts"},
		{name: "nginx authenticate", service: definitions.ServNginx, mode: core.AuthModeAuthenticate},
		{name: "nginx lookup identity", service: definitions.ServNginx, mode: core.AuthModeLookupIdentity, queryMode: "no-auth"},
		{name: "nginx list accounts", service: definitions.ServNginx, mode: core.AuthModeListAccounts, queryMode: "list-accounts"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &recordingAuthApplicationService{}
			deps := applicationBoundaryDeps()
			router := applicationBoundaryRouter(deps, service)
			request := applicationBoundaryRequest(t, test.service, test.queryMode)
			recorder := httptest.NewRecorder()

			router.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusOK {
				t.Fatalf("HTTP status = %d, want 200; body=%q", recorder.Code, recorder.Body.String())
			}

			call := service.onlyCall(t)
			if call.operation != test.mode || call.input.Mode != test.mode {
				t.Fatalf("operation/input mode = %q/%q, want %q", call.operation, call.input.Mode, test.mode)
			}

			assertBackchannelApplicationInput(t, call.input, test.service)
		})
	}
}

func TestBackchannelHTTPHeaderAdapterRemovesSecretsAndMapsConfiguredFacts(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &recordingAuthApplicationService{}
	deps := applicationBoundaryDeps()
	router := applicationBoundaryRouter(deps, service)
	request := applicationBoundaryRequest(t, definitions.ServHeader, "")
	request.Header.Set("Auth-Pass-Encoded", "1")
	request.Header.Set("Auth-Pass", "Ym91bmRhcnktcGFzc3dvcmQ")
	request.Header.Set("Authorization", "Basic forbidden")
	request.Header.Set("Cookie", "session=forbidden")
	request.Header.Set("X-Request-ID", "visible-request-id")

	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	call := service.onlyCall(t)
	assertBackchannelHeaderInput(t, call.input)
	assertBackchannelHeaderSanitization(t, request, call.input.Context.RequestMetadata)
}

// assertBackchannelHeaderInput verifies decoded header facts and credential ownership.
func assertBackchannelHeaderInput(t *testing.T, input core.AuthInput) {
	t.Helper()

	if got := input.Context.Method; got != "PLAIN" {
		t.Fatalf("auth method = %q, want PLAIN", got)
	}

	if got := input.AuthLoginAttempt; got != 2 {
		t.Fatalf("login attempt = %d, want 2", got)
	}

	if !input.DisableCache || !input.DisableMemoryCache {
		t.Fatalf("cache flags = %t/%t, want both disabled", input.DisableCache, input.DisableMemoryCache)
	}

	input.Credentials.Password.WithString(func(value string) {
		if value != applicationBoundaryPassword {
			t.Fatalf("decoded password = %q, want test password", value)
		}
	})
}

// assertBackchannelHeaderSanitization verifies consumed secrets and safe metadata filtering.
func assertBackchannelHeaderSanitization(t *testing.T, request *http.Request, metadata map[string][]string) {
	t.Helper()

	if request.Header.Get("Auth-Pass") != "" || request.Header.Get("Auth-Pass-Encoded") != "" {
		t.Fatal("credential headers were not removed after conversion")
	}

	if metadata["authorization"] != nil || metadata["cookie"] != nil || metadata["auth-pass"] != nil {
		t.Fatalf("secret request metadata escaped filtering: %#v", metadata)
	}

	if got := metadata["x-request-id"]; len(got) != 1 || got[0] != "visible-request-id" {
		t.Fatalf("safe request metadata = %#v, want cloned X-Request-ID", got)
	}
}

func TestBackchannelHTTPAuthOutcomeIsPublishedOnRealGinContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name      string
		queryMode string
		decision  core.AuthDecision
	}{
		{name: "authenticate success", decision: core.AuthDecisionOK},
		{name: "authenticate failure", decision: core.AuthDecisionFail},
		{name: "authenticate temporary failure", decision: core.AuthDecisionTempFail},
		{name: "lookup success", queryMode: "no-auth", decision: core.AuthDecisionOK},
		{name: "lookup failure", queryMode: "no-auth", decision: core.AuthDecisionFail},
		{name: "lookup temporary failure", queryMode: "no-auth", decision: core.AuthDecisionTempFail},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observed := ""
			service := &terminalOutcomeAuthApplicationService{decision: test.decision}
			router := gin.New()
			router.Use(func(ctx *gin.Context) {
				requestContext, gate := core.ContextWithHTTPPostActionExecutionGate(ctx.Request.Context())
				ctx.Request = ctx.Request.WithContext(requestContext)
				ctx.Set(definitions.CtxGUIDKey, applicationBoundaryCorrelation)
				ctx.Next()
				observed = ctx.GetString(definitions.CtxAuthOutcomeKey)

				gate.Complete()
			})
			NewWithApplicationService(applicationBoundaryDeps(), service).Register(router.Group("/api/v1"))

			recorder := httptest.NewRecorder()

			router.ServeHTTP(recorder, applicationBoundaryRequest(t, definitions.ServJSON, test.queryMode))

			if observed != string(test.decision) {
				t.Fatalf("real Gin auth outcome = %q, want %q", observed, test.decision)
			}
		})
	}
}

func TestBackchannelHTTPNilApplicationOutcomesFailClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name      string
		queryMode string
	}{
		{name: "authenticate"},
		{name: "lookup identity", queryMode: "no-auth"},
		{name: "list accounts", queryMode: "list-accounts"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			router := applicationBoundaryRouter(applicationBoundaryDeps(), nilOutcomeAuthApplicationService{})
			recorder := httptest.NewRecorder()

			router.ServeHTTP(recorder, applicationBoundaryRequest(t, definitions.ServJSON, test.queryMode))

			if recorder.Code != http.StatusInternalServerError {
				t.Fatalf("HTTP status = %d, want fail-closed 500", recorder.Code)
			}
		})
	}
}

type terminalOutcomeAuthApplicationService struct {
	decision core.AuthDecision
}

// Authenticate returns one configured terminal decision for real-context propagation coverage.
func (s *terminalOutcomeAuthApplicationService) Authenticate(_ context.Context, input core.AuthInput) (*core.AuthOutcome, error) {
	outcome := recordingAuthOutcome(input)
	outcome.Decision = s.decision

	switch s.decision {
	case core.AuthDecisionFail:
		outcome.HTTPStatus = http.StatusForbidden
		outcome.StatusMessage = "authentication failed"
	case core.AuthDecisionTempFail:
		outcome.HTTPStatus = http.StatusInternalServerError
		outcome.StatusMessage = "temporary failure"
	}

	return outcome, nil
}

// LookupIdentity delegates to the terminal authenticate result for interface completeness.
func (s *terminalOutcomeAuthApplicationService) LookupIdentity(ctx context.Context, input core.AuthInput) (*core.AuthOutcome, error) {
	return s.Authenticate(ctx, input)
}

// ListAccounts returns a valid empty list for interface completeness.
func (*terminalOutcomeAuthApplicationService) ListAccounts(context.Context, core.AuthInput) (*core.ListAccountsOutcome, error) {
	return &core.ListAccountsOutcome{Decision: core.AuthDecisionOK, HTTPStatus: http.StatusOK}, nil
}

// applicationBoundaryDeps constructs deterministic HTTP dependencies.
func applicationBoundaryDeps() *handlerdeps.Deps {
	return &handlerdeps.Deps{
		Cfg: &config.FileSettings{Server: &config.ServerSection{
			DefaultHTTPRequestHeader: config.DefaultHTTPRequestHeader{
				Username:          "Auth-User",
				Password:          "Auth-Pass",
				PasswordEncoded:   "Auth-Pass-Encoded",
				Protocol:          "Auth-Protocol",
				LoginAttempt:      "Auth-Login-Attempt",
				AuthMethod:        "Auth-Method",
				LocalIP:           "X-Local-IP",
				LocalPort:         "X-Local-Port",
				ClientIP:          "Client-IP",
				ClientPort:        "X-Client-Port",
				ClientHost:        "X-Client-Host",
				ClientID:          "X-Client-ID",
				ExternalSessionID: "X-External-Session-ID",
				SSL:               "X-SSL",
				SSLProtocol:       "X-SSL-Protocol",
			},
			IMAPBackendAddress: "imap.backend.test",
			IMAPBackendPort:    993,
			NginxWaitDelay:     5,
		}},
		Env:             config.NewTestEnvironmentConfig(),
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		PolicyTransport: protectedHTTPTransport{},
	}
}

// applicationBoundaryRouter registers the real HTTP auth routes with a recording service.
func applicationBoundaryRouter(deps *handlerdeps.Deps, service core.AuthApplicationService) *gin.Engine {
	router := gin.New()
	router.Use(func(ctx *gin.Context) {
		requestContext, gate := core.ContextWithHTTPPostActionExecutionGate(ctx.Request.Context())
		ctx.Request = ctx.Request.WithContext(requestContext)
		ctx.Set(definitions.CtxGUIDKey, applicationBoundaryCorrelation)
		ctx.Next()
		gate.Complete()
	})
	NewWithApplicationService(deps, service).Register(router.Group("/api/v1"))

	return router
}

// applicationBoundaryRequestDTO returns the shared request values for every HTTP surface.
func applicationBoundaryRequestDTO() authdto.Request {
	return authdto.Request{
		Username:          applicationBoundaryUsername,
		Password:          applicationBoundaryPassword,
		ClientIP:          "203.0.113.50",
		ClientPort:        "2143",
		ClientHostname:    "client.example.test",
		ClientID:          "mail-client",
		ExternalSessionID: "external-session",
		UserAgent:         "structured-user-agent",
		LocalIP:           "198.51.100.25",
		LocalPort:         "993",
		Protocol:          definitions.ProtoIMAP,
		Method:            "PLAIN",
		XSSL:              "on",
		XSSLProtocol:      "TLSv1.3",
		AuthLoginAttempt:  2,
	}
}

// applicationBoundaryRequest builds one real request surface for the route matrix.
func applicationBoundaryRequest(t *testing.T, service string, mode string) *http.Request {
	t.Helper()

	path := "/api/v1/auth/" + service + "?cache=0&in-memory=0"
	if mode != "" {
		path += "&mode=" + mode
	}

	request := applicationBoundarySurfaceRequest(t, service, path, applicationBoundaryRequestDTO())
	attachApplicationBoundaryTransport(t, request)

	return request
}

// applicationBoundarySurfaceRequest encodes request values for one HTTP response surface.
func applicationBoundarySurfaceRequest(
	t *testing.T,
	service string,
	path string,
	requestDTO authdto.Request,
) *http.Request {
	t.Helper()

	switch service {
	case definitions.ServJSON:
		return applicationBoundaryStructuredRequest(t, path, "application/json", requestDTO, stdjson.Marshal)
	case definitions.ServCBOR:
		return applicationBoundaryStructuredRequest(t, path, "application/cbor", requestDTO, cborcodec.Marshal)
	default:
		return applicationBoundaryHeaderRequest(path)
	}
}

// applicationBoundaryStructuredRequest marshals one DTO and assigns its media type.
func applicationBoundaryStructuredRequest(
	t *testing.T,
	path string,
	contentType string,
	requestDTO authdto.Request,
	marshal func(any) ([]byte, error),
) *http.Request {
	t.Helper()

	payload, err := marshal(requestDTO)
	if err != nil {
		t.Fatalf("marshal %s request: %v", contentType, err)
	}

	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(payload))
	request.Header.Set("Content-Type", contentType)

	return request
}

// applicationBoundaryHeaderRequest assigns the configured legacy header facts.
func applicationBoundaryHeaderRequest(path string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Auth-User", applicationBoundaryUsername)
	request.Header.Set("Auth-Pass", applicationBoundaryPassword)
	request.Header.Set("Auth-Protocol", definitions.ProtoIMAP)
	request.Header.Set("Auth-Method", "PLAIN")
	request.Header.Set("Auth-Login-Attempt", "2")
	request.Header.Set("Client-IP", "203.0.113.50")
	request.Header.Set("X-Client-Port", "2143")
	request.Header.Set("X-Client-Host", "client.example.test")
	request.Header.Set("X-Client-ID", "mail-client")
	request.Header.Set("X-External-Session-ID", "external-session")
	request.Header.Set("X-Local-IP", "198.51.100.25")
	request.Header.Set("X-Local-Port", "993")
	request.Header.Set("X-SSL", "on")
	request.Header.Set("X-SSL-Protocol", "TLSv1.3")

	return request
}

// attachApplicationBoundaryTransport adds direct-peer and verified mTLS evidence.
func attachApplicationBoundaryTransport(t *testing.T, request *http.Request) {
	t.Helper()

	identity, err := url.Parse("spiffe://example.test/backchannel-client")
	if err != nil {
		t.Fatalf("parse test mTLS identity: %v", err)
	}

	certificate := &x509.Certificate{URIs: []*url.URL{identity}}
	request.RemoteAddr = applicationBoundaryPeer + ":4242"
	request.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}},
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "header-user-agent")
}

// assertBackchannelApplicationInput verifies the transport-neutral request contract.
func assertBackchannelApplicationInput(t *testing.T, input core.AuthInput, service string) {
	t.Helper()

	if input.Service != service {
		t.Fatalf("service = %q, want %q", input.Service, service)
	}

	if input.CorrelationID != applicationBoundaryCorrelation {
		t.Fatalf("correlation ID = %q, want %q", input.CorrelationID, applicationBoundaryCorrelation)
	}

	if input.Credentials.Username != applicationBoundaryUsername {
		t.Fatalf("username = %q, want %q", input.Credentials.Username, applicationBoundaryUsername)
	}

	if input.Context.Protocol != definitions.ProtoIMAP || input.Context.Method != "PLAIN" {
		t.Fatalf("protocol/method = %q/%q, want imap/PLAIN", input.Context.Protocol, input.Context.Method)
	}

	transport := input.Context.Transport
	if transport.Kind != "http" || transport.Listener != "http" {
		t.Fatalf("transport kind/listener = %q/%q, want http/http", transport.Kind, transport.Listener)
	}

	wantRoute := "/api/v1/auth/" + service
	if transport.HTTPRoute != wantRoute || transport.Peer != applicationBoundaryPeer {
		t.Fatalf("transport route/peer = %q/%q, want %q/%q", transport.HTTPRoute, transport.Peer, wantRoute, applicationBoundaryPeer)
	}

	if !transport.Protected || transport.MTLSIdentity != "spiffe://example.test/backchannel-client" {
		t.Fatalf("protected/mTLS = %t/%q, want true/SPIFFE identity", transport.Protected, transport.MTLSIdentity)
	}
}

// recordingAuthOutcome returns a renderer-complete success result.
func recordingAuthOutcome(input core.AuthInput) *core.AuthOutcome {
	return &core.AuthOutcome{
		Decision:        core.AuthDecisionOK,
		Session:         applicationBoundaryCorrelation,
		Account:         input.Credentials.Username,
		AccountField:    "uid",
		TOTPSecretField: "totp_secret",
		Backend:         definitions.BackendTest,
		HTTPStatus:      http.StatusOK,
	}
}
