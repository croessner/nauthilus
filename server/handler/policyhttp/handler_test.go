// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyhttp

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/definitions"
	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/admission"
	"github.com/croessner/nauthilus/v3/server/policy/callerauth"
	"github.com/croessner/nauthilus/v3/server/policy/configinput"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v3/server/policy/decision/service"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/gin-gonic/gin"
)

func TestPolicyHTTPRejectsStrictJSONBeforeService(t *testing.T) {
	service := &recordingService{response: testResponse(t)}
	engine := policyEngine(service)

	for name, body := range map[string]string{
		"array":                `[]`,
		"duplicate":            `{"version":"1","version":"1","target":{"namespace":"dkim2","action":"sign-message"}}`,
		"unknown":              `{"version":"1","target":{"namespace":"dkim2","action":"sign-message"},"unknown":true}`,
		"nested value unknown": `{"version":"1","target":{"namespace":"dkim2","action":"sign-message"},"attributes":{"x":{"string":"a","extra":true}}}`,
		"plus integer":         `{"version":"1","target":{"namespace":"dkim2","action":"sign-message"},"attributes":{"x":{"integer":"+1"}}}`,
		"leading zero integer": `{"version":"1","target":{"namespace":"dkim2","action":"sign-message"},"attributes":{"x":{"integer":"01"}}}`,
		"null optional object": `{"version":"1","target":{"namespace":"dkim2","action":"sign-message"},"options":null}`,
		"multiple kind":        `{"version":"1","target":{"namespace":"dkim2","action":"sign-message"},"attributes":{"x":{"string":"a","boolean":true}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			response := servePolicyRequest(engine, body, "Bearer opaque")
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}

			if response.Header().Get("Cache-Control") != noStore {
				t.Fatalf("Cache-Control = %q, want %q", response.Header().Get("Cache-Control"), noStore)
			}
		})
	}

	if service.calls != 0 {
		t.Fatalf("service calls = %d, want zero", service.calls)
	}
}

func TestPolicyHTTPPreservesDoublePrecision(t *testing.T) {
	request, err := decodeRequest([]byte(`{"version":"1","target":{"namespace":"dkim2","action":"sign-message"},"attributes":{"x":{"double":16777217}}}`))
	if err != nil {
		t.Fatalf("decode precise double: %v", err)
	}

	value, found := request.Attributes["x"]
	if !found {
		t.Fatal("decoded double attribute missing")
	}

	decoded, ok := value.Double()
	if !ok || decoded != 16777217 {
		t.Fatalf("decoded double = %v, want 16777217", decoded)
	}

	values := policyValues(map[string]decision.Value{"x": value})
	if values["x"].Double == nil || *values["x"].Double != 16777217 {
		t.Fatalf("response double = %#v, want 16777217", values["x"].Double)
	}
}

func TestPolicyHTTPAcceptsSchemaValidNegativeZeroInteger(t *testing.T) {
	request, err := decodeRequest([]byte(`{"version":"1","target":{"namespace":"dkim2","action":"sign-message"},"attributes":{"x":{"integer":"-0"}}}`))
	if err != nil {
		t.Fatalf("decode schema-valid negative zero: %v", err)
	}

	value, found := request.Attributes["x"]
	if !found {
		t.Fatal("decoded integer attribute missing")
	}

	integer, ok := value.Integer()
	if !ok || integer != 0 {
		t.Fatalf("decoded integer = %d, want 0", integer)
	}
}

func TestPolicyHTTPRejectsNonJSONMediaType(t *testing.T) {
	service := &recordingService{response: testResponse(t)}
	engine := policyEngine(service)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/policy/decisions", strings.NewReader(validRequestJSON))
	request.Header.Set("Authorization", "Bearer opaque")
	request.Header.Set("Content-Type", "text/plain")

	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)

	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnsupportedMediaType)
	}

	if response.Header().Get("Cache-Control") != noStore {
		t.Fatalf("Cache-Control = %q, want %q", response.Header().Get("Cache-Control"), noStore)
	}

	if service.calls != 0 {
		t.Fatalf("service calls = %d, want zero", service.calls)
	}
}

func TestPolicyHTTPMapsApplicationErrorsAndFinalizesAfterCommit(t *testing.T) {
	t.Run("route disabled", func(t *testing.T) {
		response := servePolicyRequest(policyEngine(&recordingService{err: decisionservice.ErrDecisionRouteUnavailable}), validRequestJSON, "Bearer opaque")
		requirePolicyStatus(t, response, http.StatusNotFound)
	})

	t.Run("authentication", func(t *testing.T) {
		response := servePolicyRequest(policyEngine(&recordingService{err: decisionservice.ErrDecisionAuthentication}), validRequestJSON, "Bearer opaque")
		requirePolicyStatus(t, response, http.StatusUnauthorized)
	})

	t.Run("admission", func(t *testing.T) {
		response := servePolicyRequest(policyEngine(&recordingService{err: decisionservice.ErrDecisionAdmission}), validRequestJSON, "Basic dXNlcjpwYXNz")
		requirePolicyStatus(t, response, http.StatusForbidden)
	})

	t.Run("request limit", func(t *testing.T) {
		service := &recordingService{err: fmt.Errorf("%w: %w", decisionservice.ErrDecisionAdmission, admission.ErrRequestLimitExceeded)}
		response := servePolicyRequest(policyEngine(service), validRequestJSON, "Bearer opaque")
		requirePolicyStatus(t, response, http.StatusRequestEntityTooLarge)
	})

	t.Run("capacity limit", func(t *testing.T) {
		service := &recordingService{err: fmt.Errorf("%w: %w", decisionservice.ErrDecisionAdmission, admission.ErrCapacityLimitExceeded)}
		response := servePolicyRequest(policyEngine(service), validRequestJSON, "Bearer opaque")
		requirePolicyStatus(t, response, http.StatusTooManyRequests)
	})

	t.Run("service unavailable", func(t *testing.T) {
		response := servePolicyRequest(policyEngine(&recordingService{err: decisionservice.ErrDecisionGenerationUnavailable}), validRequestJSON, "Bearer opaque")
		requirePolicyStatus(t, response, http.StatusServiceUnavailable)
	})

	t.Run("commit gate", func(t *testing.T) {
		service := &recordingService{response: testResponse(t)}

		response := servePolicyRequest(policyEngine(service), validRequestJSON, "Bearer opaque")
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
		}

		if service.finalization == nil {
			t.Fatal("service did not receive finalization")
		}

		if !service.gatePendingDuringEvaluation {
			t.Fatal("response finalization gate was open while DecisionService evaluated")
		}

		select {
		case <-service.finalization.Done():
		default:
			t.Fatal("response finalization gate opened before the handler committed the response")
		}
	})
}

func TestPolicyHTTPDisabledRoutePrecedesRequestPreparation(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		body          string
		authorization string
	}{
		{name: "missing credentials", body: validRequestJSON},
		{name: "malformed payload", body: `{`, authorization: "Bearer opaque"},
		{name: "oversized payload", body: strings.Repeat("x", decision.MaximumOpaqueCredentialBytes+1), authorization: "Bearer opaque"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			service := &recordingService{err: decisionservice.ErrDecisionRouteUnavailable}
			response := servePolicyRequest(policyEngine(service), testCase.body, testCase.authorization)

			requirePolicyStatus(t, response, http.StatusNotFound)

			if service.transportKind != policyHTTPTransportKind {
				t.Fatalf("transport kind = %q, want %q", service.transportKind, policyHTTPTransportKind)
			}

			if service.calls != 0 {
				t.Fatalf("evaluation calls = %d, want zero", service.calls)
			}
		})
	}
}

func TestPolicyHTTPEvaluatesThroughRealGeneration(t *testing.T) {
	service, closeGeneration := newGeneratedDecisionService(t)
	t.Cleanup(closeGeneration)

	engine := policyEngine(service)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/policy/decisions", strings.NewReader(`{"version":"1","target":{"namespace":"mail","action":"submit"}}`))
	request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("policy-http:policy-http-secret")))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true}
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)

	requirePolicyStatus(t, response, http.StatusOK)

	if !strings.Contains(response.Body.String(), `"effect":"deny"`) {
		t.Fatalf("real generated decision response = %s, want deny", response.Body.String())
	}

	unprotected := httptest.NewRequest(http.MethodPost, "/api/v1/policy/decisions", strings.NewReader(`{"version":"1","target":{"namespace":"mail","action":"submit"}}`))
	unprotected.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("policy-http:policy-http-secret")))
	unprotected.Header.Set("Content-Type", "application/json")

	unprotectedResponse := httptest.NewRecorder()
	engine.ServeHTTP(unprotectedResponse, unprotected)
	requirePolicyStatus(t, unprotectedResponse, http.StatusUnauthorized)

	invalidVersion := httptest.NewRequest(http.MethodPost, "/api/v1/policy/decisions", strings.NewReader(`{"version":"2","target":{"namespace":"mail","action":"submit"}}`))
	invalidVersion.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("policy-http:policy-http-secret")))
	invalidVersion.Header.Set("Content-Type", "application/json")
	invalidVersion.TLS = &tls.ConnectionState{HandshakeComplete: true}
	invalidVersionResponse := httptest.NewRecorder()
	engine.ServeHTTP(invalidVersionResponse, invalidVersion)
	requirePolicyStatus(t, invalidVersionResponse, http.StatusBadRequest)

	for _, test := range []struct {
		name  string
		token string
		want  int
	}{
		{name: "admitted exact Bearer", token: "policy-valid", want: http.StatusOK},
		{name: "wrong audience", token: "policy-wrong-audience", want: http.StatusUnauthorized},
		{name: "multiple audiences", token: "policy-multiple-audience", want: http.StatusUnauthorized},
		{name: "missing evaluate scope", token: "policy-missing-scope", want: http.StatusUnauthorized},
		{name: "unregistered profile", token: "policy-unregistered", want: http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			bearerRequest := httptest.NewRequest(http.MethodPost, "/api/v1/policy/decisions", strings.NewReader(`{"version":"1","target":{"namespace":"mail","action":"submit"}}`))
			bearerRequest.Header.Set("Authorization", "Bearer "+test.token)
			bearerRequest.Header.Set("Content-Type", "application/json")
			bearerRequest.TLS = &tls.ConnectionState{HandshakeComplete: true}
			bearerResponse := httptest.NewRecorder()
			engine.ServeHTTP(bearerResponse, bearerRequest)
			requirePolicyStatus(t, bearerResponse, test.want)
		})
	}
}

func TestPolicyHTTPCoversEveryEffectDiagnosticsAndBodyLimit(t *testing.T) {
	for _, effect := range []decision.Effect{
		decision.EffectPermit,
		decision.EffectDeny,
		decision.EffectNotApplicable,
		decision.EffectIndeterminate,
	} {
		t.Run(string(effect), func(t *testing.T) {
			service := &recordingService{response: testResponseWithEffect(t, effect, true)}

			response := servePolicyRequest(policyEngine(service), validRequestJSON, "Bearer opaque")
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"effect":"`+string(effect)+`"`) {
				t.Fatalf("effect response = status %d body %s", response.Code, response.Body.String())
			}

			if !strings.Contains(response.Body.String(), `"diagnostics"`) || response.Header().Get("Cache-Control") != noStore {
				t.Fatalf("diagnostics/no-store missing from %s", response.Body.String())
			}
		})
	}

	response := servePolicyRequest(policyEngine(&recordingService{response: testResponse(t)}), `{"version":"1","target":{"namespace":"dkim2","action":"sign-message"},"attributes":{"x":{"string":"`+strings.Repeat("a", decision.MaximumOpaqueCredentialBytes)+`"}}}`, "Bearer opaque")
	if response.Code != http.StatusRequestEntityTooLarge || response.Header().Get("Cache-Control") != noStore {
		t.Fatalf("oversized status/cache = %d/%q", response.Code, response.Header().Get("Cache-Control"))
	}
}

func TestPolicyHTTPPostActionGateOpensOnlyAfterWriterCommit(t *testing.T) {
	probe := &commitProbe{ResponseRecorder: httptest.NewRecorder()}
	service := &commitProbeService{recordingService: recordingService{response: testResponse(t)}, probe: probe, done: make(chan struct{})}
	engine := policyEngine(service)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/policy/decisions", strings.NewReader(validRequestJSON))
	request.Header.Set("Authorization", "Bearer opaque")
	request.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(probe, request)

	<-service.done

	if !service.finalizedAfterCommit.Load() {
		t.Fatal("post-action gate opened before the HTTP response writer committed")
	}
}

//nolint:wsl_v5 // The compact transport matrix keeps the trusted-peer comparison visible.
func TestTrustedProxyTransportEvidenceRejectsSpoofedForwarding(t *testing.T) {
	evidence := NewTrustedProxyTransportEvidence([]string{"192.0.2.0/24"})
	for name, remoteAddress := range map[string]string{"trusted": "192.0.2.10:443", "untrusted": "198.51.100.10:443"} {
		t.Run(name, func(t *testing.T) {
			context, _ := gin.CreateTestContext(httptest.NewRecorder())
			context.Request = httptest.NewRequest(http.MethodPost, "/api/v1/policy/decisions", nil)
			context.Request.RemoteAddr = remoteAddress
			context.Request.Header.Set("X-Forwarded-Proto", "https")

			if got := evidence.Protected(context); got != (name == "trusted") {
				t.Fatalf("protected = %t", got)
			}
		})
	}
}

func TestPolicyHTTPDerivesTrustedProxyEvidenceFromCapturedConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &recordingService{
		response: testResponse(t),
		captured: &config.FileSettings{Server: &config.ServerSection{
			TrustedProxies: []string{"192.0.2.0/24"},
		}},
	}
	engine := gin.New()
	New(service, nil).Register(engine.Group("/api/v1"))

	request := httptest.NewRequest(http.MethodPost, "/api/v1/policy/decisions", strings.NewReader(validRequestJSON))
	request.RemoteAddr = "192.0.2.44:41234"
	request.Header.Set("Authorization", "Bearer opaque")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-Proto", "https")

	response := httptest.NewRecorder()

	engine.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}

	if !service.authentication.Protected() {
		t.Fatal("captured trusted-proxy configuration did not protect the prepared invocation")
	}
}

const validRequestJSON = `{"version":"1","target":{"namespace":"dkim2","action":"sign-message"}}`

type recordingService struct {
	response                    decision.DecisionResponse
	err                         error
	captured                    config.File
	invocation                  decision.Invocation
	authentication              decision.AuthenticationInput
	finalization                *decision.EvaluationFinalization
	gatePendingDuringEvaluation bool
	transportKind               string
	calls                       int
}

// Evaluate records adapter-owned invocation evidence without replacing service admission behavior.
//
//nolint:wsl_v5 // The observation sequence must remain adjacent to one invocation capture.
func (s *recordingService) Evaluate(_ context.Context, invocation decision.Invocation) (decision.DecisionResponse, error) {
	s.calls++
	s.invocation = invocation
	s.authentication = invocation.Authentication
	s.finalization = &invocation.Finalization
	select {
	case <-invocation.Finalization.Done():
		s.gatePendingDuringEvaluation = false
	default:
		s.gatePendingDuringEvaluation = true
	}

	return s.response, s.err
}

// EvaluatePrepared records the invocation prepared under a deterministic captured configuration.
func (s *recordingService) EvaluatePrepared(
	ctx context.Context,
	transportKind string,
	prepare func(config.File) (decision.Invocation, error),
) (decision.DecisionResponse, error) {
	s.transportKind = transportKind
	if errors.Is(s.err, decisionservice.ErrDecisionRouteUnavailable) {
		return decision.DecisionResponse{}, s.err
	}

	captured := s.captured
	if captured == nil {
		captured = enabledHTTPPolicyConfig()
	}

	invocation, err := prepare(captured)
	if err != nil {
		return decision.DecisionResponse{}, err
	}

	return s.Evaluate(ctx, invocation)
}

// policyEngine builds the real Gin route around a recording DecisionService seam.
func policyEngine(service decisionservice.PreparedService) *gin.Engine {
	gin.SetMode(gin.TestMode)

	engine := gin.New()
	New(service, DirectTLSTransportEvidence{}).Register(engine.Group("/api/v1"))

	return engine
}

// servePolicyRequest sends one raw JSON request without passing through generated serialization.
func servePolicyRequest(engine http.Handler, body string, authorization string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/policy/decisions", strings.NewReader(body))
	request.Header.Set("Authorization", authorization)
	request.Header.Set("Content-Type", "application/json")

	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)

	return response
}

// requirePolicyStatus checks shared HTTP policy response invariants.
func requirePolicyStatus(t *testing.T, response *httptest.ResponseRecorder, want int) {
	t.Helper()

	if response.Code != want {
		t.Fatalf("status = %d, want %d", response.Code, want)
	}

	if response.Header().Get("Cache-Control") != noStore {
		t.Fatalf("Cache-Control = %q, want %q", response.Header().Get("Cache-Control"), noStore)
	}
}

// testResponse constructs a complete application response for adapter tests.
func testResponse(t *testing.T) decision.DecisionResponse {
	return testResponseWithEffect(t, decision.EffectPermit, false)
}

// testResponseWithEffect constructs a complete application response for a selected closed effect.
//
//nolint:wsl_v5 // Optional diagnostics belong beside the fixture response construction.
func testResponseWithEffect(t *testing.T, effect decision.Effect, diagnostics bool) decision.DecisionResponse {
	t.Helper()

	status, err := decision.NewStatus(decision.StatusCodePermit, "permitted", nil)
	if err != nil {
		t.Fatalf("new status: %v", err)
	}

	metadata, err := decision.NewPolicyMetadata("dkim2/default", "v1", "permit", 1)
	if err != nil {
		t.Fatalf("new metadata: %v", err)
	}

	input := decision.DecisionResponseInput{RequestID: "request", DecisionID: "decision", Effect: effect, Status: status, Policy: metadata}
	if diagnostics {
		value := "selected"
		entry, valueErr := decision.NewValue(decision.ValueInput{String: &value})
		if valueErr != nil {
			t.Fatalf("new diagnostic value: %v", valueErr)
		}

		projection, projectionErr := decision.NewDiagnostics(map[string]decision.Value{"result": entry})
		if projectionErr != nil {
			t.Fatalf("new diagnostics: %v", projectionErr)
		}

		input.Diagnostics = &projection
	}

	response, err := decision.NewDecisionResponse(input)
	if err != nil {
		t.Fatalf("new response: %v", err)
	}

	return response
}

type commitProbe struct {
	*httptest.ResponseRecorder
	committed atomic.Bool
}

// WriteHeader records the concrete HTTP writer commit before forwarding it to the recorder.
func (p *commitProbe) WriteHeader(statusCode int) {
	p.committed.Store(true)
	p.ResponseRecorder.WriteHeader(statusCode)
}

type commitProbeService struct {
	recordingService
	probe                *commitProbe
	done                 chan struct{}
	finalizedAfterCommit atomic.Bool
}

// Evaluate observes the detached post-action boundary after the handler owns a committed response.
func (s *commitProbeService) Evaluate(ctx context.Context, invocation decision.Invocation) (decision.DecisionResponse, error) {
	response, err := s.recordingService.Evaluate(ctx, invocation)
	go func() {
		<-invocation.Finalization.Done()
		s.finalizedAfterCommit.Store(s.probe.committed.Load())
		close(s.done)
	}()

	return response, err
}

// EvaluatePrepared preserves the commit probe while preparing under one captured configuration.
func (s *commitProbeService) EvaluatePrepared(
	ctx context.Context,
	_ string,
	prepare func(config.File) (decision.Invocation, error),
) (decision.DecisionResponse, error) {
	invocation, err := prepare(enabledHTTPPolicyConfig())
	if err != nil {
		return decision.DecisionResponse{}, err
	}

	return s.Evaluate(ctx, invocation)
}

type acceptingPostAction struct{}

// Accept confirms ownership for a fixture without scheduling any post-action work.
func (acceptingPostAction) Accept(context.Context, effectsupervisor.Plan) (effectsupervisor.Receipt, error) {
	return effectsupervisor.Receipt{}, nil
}

type acceptingPolicyBasicThrottler struct{}

// BeforeAttempt accepts one focused adapter-fixture verification attempt.
func (*acceptingPolicyBasicThrottler) BeforeAttempt(context.Context, callerauth.BasicThrottleKey) error {
	return nil
}

// RecordFailure accepts one focused adapter-fixture verification failure.
func (*acceptingPolicyBasicThrottler) RecordFailure(context.Context, callerauth.BasicThrottleKey) error {
	return nil
}

// RecordSuccess accepts one focused adapter-fixture verification success.
func (*acceptingPolicyBasicThrottler) RecordSuccess(context.Context, callerauth.BasicThrottleKey) error {
	return nil
}

type generatedPolicyTokenValidator struct{}

// ValidateAccessToken returns fixed issuer-validated token evidence for HTTP boundary coverage.
func (generatedPolicyTokenValidator) ValidateAccessToken(_ context.Context, credential []byte) (callerauth.ValidatedAccessToken, error) {
	token := callerauth.ValidatedAccessToken{
		Audiences: []string{definitions.AudiencePolicyAPI},
		Scopes:    []string{definitions.ScopePolicyEvaluate},
		ClientID:  "policy-bearer",
		Issuer:    "https://issuer.example.test",
		Subject:   "policy-subject",
		TokenType: definitions.TokenTypeAccessToken,
	}

	switch string(credential) {
	case "policy-valid":
		return token, nil
	case "policy-wrong-audience":
		token.Audiences = []string{definitions.AudienceBackchannelAPI}
	case "policy-multiple-audience":
		token.Audiences = []string{definitions.AudiencePolicyAPI, definitions.AudienceBackchannelAPI}
	case "policy-missing-scope":
		token.Scopes = []string{definitions.ScopeAdmin}
	case "policy-unregistered":
		token.ClientID = "unregistered-policy-client"
	default:
		return callerauth.ValidatedAccessToken{}, fmt.Errorf("unknown fixture token")
	}

	return token, nil
}

// newGeneratedDecisionService compiles one genuine application generation for the HTTP boundary.
//
//nolint:funlen // The fixture keeps the complete immutable runtime graph visible at its integration boundary.
func newGeneratedDecisionService(t *testing.T) (*decisionservice.DecisionService, func()) {
	t.Helper()

	store := policyruntime.NewGenerationStore()

	bindings, err := policyruntime.NewBindingSet(policyruntime.BindingSetInput{PostActionAcceptance: acceptingPostAction{}})
	if err != nil {
		t.Fatalf("new binding set: %v", err)
	}

	catalog, reference := generatedPolicyCatalog(t)
	callerConfiguration := callerauth.Configuration{
		ExternalProfiles: []callerauth.ExternalProfile{{
			Basic:               &callerauth.BasicCredential{Username: "policy-http", Password: secret.New("policy-http-secret")},
			AuthenticationKinds: []string{policy.CallerAuthenticationKindBasic},
			Principal:           "policy-http",
		}, {
			AuthenticationKinds: []string{policy.CallerAuthenticationKindBearer},
			Principal:           "policy-bearer",
		}},
		TokenValidator:        generatedPolicyTokenValidator{},
		Throttler:             &acceptingPolicyBasicThrottler{},
		TransportCapabilities: callerauth.TransportCapabilities{HTTPProtected: true},
	}
	admissionConfiguration := admission.Configuration{
		GlobalLimits: admission.Limits{MaxRequestBytes: 4096, MaxFacts: 8, MaxConcurrency: 4, RequestsPerSecond: 1000},
		Profiles: []admission.Profile{{
			AuthenticationKinds: []string{policy.CallerAuthenticationKindBasic},
			Limits:              admission.Limits{MaxConcurrency: 1},
			Principal:           "policy-http",
			References:          []registry.ClientAdmissionReference{reference},
		}, {
			AuthenticationKinds: []string{policy.CallerAuthenticationKindBearer},
			Limits:              admission.Limits{MaxConcurrency: 1},
			Principal:           "policy-bearer",
			References:          []registry.ClientAdmissionReference{reference},
		}},
	}

	coordinator, err := policyruntime.NewCoordinator(policyruntime.CoordinatorConfig{
		Store: store,
		Slots: policyruntime.PreparationSlots{
			Policy: policyruntime.PolicyPreparationFunc(func(ctx context.Context, input policyruntime.PreparationInput) (policyruntime.PolicyPreparation, error) {
				prepared, prepareErr := configinput.PreparePolicy(ctx, input.ID(), input.Config().GetPolicy())
				if prepareErr != nil {
					return policyruntime.PolicyPreparation{}, prepareErr
				}

				return policyruntime.PolicyPreparation{Policy: prepared}, nil
			}),
			Extensions: policyruntime.ExtensionPreparationFunc(func(context.Context, policyruntime.PreparationInput) (policyruntime.ExtensionPreparation, error) {
				return policyruntime.ExtensionPreparation{Bindings: bindings}, nil
			}),
			Catalog: policyruntime.CatalogPreparationFunc(func(context.Context, policyruntime.CatalogPreparationInput) (policyruntime.CatalogPreparation, error) {
				return policyruntime.CatalogPreparation{Catalog: catalog}, nil
			}),
			CallerAuthentication: policyruntime.CallerAuthenticationPreparationFunc(func(context.Context, policyruntime.AuthorityPreparationInput) (policyruntime.CallerAuthenticationPreparation, error) {
				return callerauth.Prepare(callerConfiguration)
			}),
			Admission: policyruntime.AdmissionPreparationFunc(func(_ context.Context, input policyruntime.AdmissionPreparationInput) (policyruntime.AdmissionPreparation, error) {
				return admission.Prepare(admissionConfiguration, input.TargetCatalog(), input.CredentialProfiles())
			}),
			Settings: policyruntime.SettingsPreparationFunc(func(context.Context, policyruntime.SettingsPreparationInput) (policyruntime.SettingsPreparation, error) {
				return policyruntime.SettingsPreparation{
					MessageResolver: localization.NewResolver(localization.NewMapCatalog(nil), "en"),
					Settings: policyruntime.GenerationSettings{
						Limits:  policyruntime.DecisionLimits{EvaluationTimeout: time.Second, PostActionBudget: time.Second, MaxDiagnosticsEntries: 8},
						Reports: policyruntime.DecisionReportSettings{MaxEntries: 8},
					},
				}, nil
			}),
			Application: decisionservice.NewRuntimeApplicationPreparationSlot(),
		},
	})
	if err != nil {
		t.Fatalf("new coordinator: %v", err)
	}

	if _, err = coordinator.Apply(context.Background(), policyruntime.PrepareInput{Config: enabledHTTPPolicyConfig(), ID: 1}); err != nil {
		t.Fatalf("apply generated policy runtime: %v", err)
	}

	source, err := decisionservice.NewStoreGenerationSource(store)
	if err != nil {
		t.Fatalf("new store source: %v", err)
	}

	service, err := decisionservice.NewDecisionService(source)
	if err != nil {
		t.Fatalf("new decision service: %v", err)
	}

	return service, func() {
		if shutdownErr := store.Shutdown(context.Background()); shutdownErr != nil {
			t.Errorf("shutdown generated policy runtime: %v", shutdownErr)
		}
	}
}

// enabledHTTPPolicyConfig supplies generation-owned HTTP activation and wire bounds to adapter fixtures.
func enabledHTTPPolicyConfig() config.File {
	return &config.FileSettings{
		Server: &config.ServerSection{},
		Policy: policyconfig.PolicyConfig{API: policyconfig.APIConfig{
			Enabled: true,
			HTTP:    policyconfig.HTTPConfig{Enabled: true},
			Limits:  policyconfig.APILimitsConfig{MaxRequestBytes: decision.MaximumOpaqueCredentialBytes},
		}},
	}
}

// generatedPolicyCatalog creates one admitted non-auth target with deterministic no-match denial.
func generatedPolicyCatalog(t *testing.T) (*policyruntime.TargetCatalog, registry.ClientAdmissionReference) {
	t.Helper()

	target, err := decision.NewTarget("mail", "submit")
	if err != nil {
		t.Fatalf("new target: %v", err)
	}

	identity, err := registry.NewSchemaIdentity("mail", "submit", "v1")
	if err != nil {
		t.Fatalf("new schema identity: %v", err)
	}

	schema, err := registry.NewSchemaDefinition(identity, nil)
	if err != nil {
		t.Fatalf("new schema: %v", err)
	}

	checkpoint, err := registry.NewCheckpointDefinition(decision.CheckpointFinalDecision, nil, nil)
	if err != nil {
		t.Fatalf("new final checkpoint: %v", err)
	}

	plan, err := registry.NewDomainPlanDefinition(target, []registry.CheckpointDefinition{checkpoint})
	if err != nil {
		t.Fatalf("new domain plan: %v", err)
	}

	catalog, err := policyruntime.NewTargetCatalog([]policyruntime.TargetCatalogRecord{{
		Target: target, Schema: schema, SourcePlan: plan,
		Checkpoints: []policyruntime.CheckpointRecord{{Name: decision.CheckpointFinalDecision}},
		NoMatch:     registry.NoMatchDeny, AuthorityMode: registry.AuthorityModeEnforce,
	}}, nil)
	if err != nil {
		t.Fatalf("new target catalog: %v", err)
	}

	reference, err := registry.NewClientAdmissionReference("test.policy-http", "mail", "submit", identity.String())
	if err != nil {
		t.Fatalf("new admission reference: %v", err)
	}

	return catalog, reference
}

var _ decision.Service = (*recordingService)(nil)
var _ decisionservice.PreparedService = (*recordingService)(nil)
