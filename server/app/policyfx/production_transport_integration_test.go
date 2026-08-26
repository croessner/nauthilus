// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyfx

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	policyv1 "github.com/croessner/nauthilus/v3/api/policy/v1"
	"github.com/croessner/nauthilus/v3/server/app/configfx"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/grpcauthority"
	"github.com/croessner/nauthilus/v3/server/handler/policyhttp"
	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/callerauth"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v3/server/policy/decision/service"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/gin-gonic/gin"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

const productionTransportBearerCredential = "production-policy-token"

// TestProductionCoordinatorServesOneNonAuthGenerationOverHTTPAndGRPC proves both public transports use one authority.
func TestProductionCoordinatorServesOneNonAuthGenerationOverHTTPAndGRPC(t *testing.T) {
	configured := productionTransportCandidate(t)
	store := policyruntime.NewGenerationStore()
	shutdownProductionTransportStore(t, store)

	coordinator := newProductionPolicyCoordinator(t, configured, store, productionTransportTokenFactory)

	if err := coordinator.Apply(t.Context(), configfx.Snapshot{File: configured, Version: 1}); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	active := store.Active()
	if active == nil {
		t.Fatal("active generation is nil, want a published generation 1")
	}

	if active.ID() != 1 {
		t.Fatalf("active generation = %p/%d, want a published generation 1", active, active.ID())
	}

	observer := newProductionTransportObserver(productionDecisionService(t, store))
	serveProductionTransportHTTP(t, observer)
	assertProductionTransportSelection(t, observer.next(t), active.ID())
	assertProductionTransportGeneration(t, store, active)

	client := newProductionTransportGRPCClient(t, configured, observer)
	requestContext := metadata.NewOutgoingContext(t.Context(), metadata.Pairs(
		"authorization",
		"Bearer "+productionTransportBearerCredential,
	))

	response, err := client.Evaluate(requestContext, &policyv1.DecisionRequest{
		Version:   decision.ContractVersion,
		RequestId: "production-grpc-wire",
		Target:    &policyv1.Target{Namespace: "mail", Action: "submit"},
	})
	if err != nil {
		t.Fatalf("gRPC Evaluate() error = %v", err)
	}

	if response.GetEffect() != policyv1.Effect_EFFECT_PERMIT {
		t.Fatalf("gRPC effect = %s, want permit", response.GetEffect())
	}

	assertProductionTransportSelection(t, observer.next(t), active.ID())
	assertProductionTransportGeneration(t, store, active)
}

// productionTransportCandidate activates both dedicated Policy credential kinds and the actual gRPC server route.
func productionTransportCandidate(t *testing.T) *config.FileSettings {
	t.Helper()

	configured := productionNonAuthDecisionCandidate(t)
	configured.Policy.API.Clients[0].AuthenticationKinds = []string{
		policy.CallerAuthenticationKindBasic,
		policy.CallerAuthenticationKindBearer,
	}
	configured.Server = &config.ServerSection{BasicAuth: config.BasicAuth{
		Enabled:  true,
		Username: "grpc-backchannel",
		Password: secret.New("grpc-backchannel-secret"),
	}}
	configured.Runtime = &config.RuntimeSection{Servers: config.RuntimeServersSection{
		GRPC: config.RuntimeGRPCServersSection{Authority: config.RuntimeGRPCAuthServerSection{
			Enabled: true,
			Address: "127.0.0.1:9444",
		}},
	}}

	return configured
}

// productionTransportTokenFactory returns one candidate-scoped exact Policy access-token validator.
func productionTransportTokenFactory(context.Context, config.File) (callerauth.AccessTokenValidator, error) {
	return productionTransportTokenValidator{}, nil
}

type productionTransportTokenValidator struct{}

// ValidateAccessToken returns detached issuer-validated evidence only for the exact fixture token.
func (productionTransportTokenValidator) ValidateAccessToken(
	_ context.Context,
	credential []byte,
) (callerauth.ValidatedAccessToken, error) {
	if string(credential) != productionTransportBearerCredential {
		return callerauth.ValidatedAccessToken{}, callerauth.ErrAuthentication
	}

	return callerauth.ValidatedAccessToken{
		Audiences: []string{definitions.AudiencePolicyAPI},
		Scopes:    []string{definitions.ScopePolicyEvaluate},
		ClientID:  "policy-production-client",
		Subject:   "production-policy-subject",
		Issuer:    "https://issuer.example.test",
		TokenType: definitions.TokenTypeAccessToken,
	}, nil
}

type productionTransportObserver struct {
	service   *decisionservice.DecisionService
	responses chan decision.DecisionResponse
}

// newProductionTransportObserver wraps one real Decision Service without adding evaluation authority.
func newProductionTransportObserver(service *decisionservice.DecisionService) *productionTransportObserver {
	return &productionTransportObserver{
		service:   service,
		responses: make(chan decision.DecisionResponse, 2),
	}
}

// Evaluate delegates to the sole Decision Service and records its completed internal selection.
func (o *productionTransportObserver) Evaluate(
	ctx context.Context,
	invocation decision.Invocation,
) (decision.DecisionResponse, error) {
	response, err := o.service.Evaluate(ctx, invocation)
	if err == nil {
		o.responses <- response
	}

	return response, err
}

// EvaluatePrepared delegates capture-first transport preparation to the same Decision Service.
func (o *productionTransportObserver) EvaluatePrepared(
	ctx context.Context,
	transport string,
	prepare func(policyruntime.GenerationConfig) (decision.Invocation, error),
) (decision.DecisionResponse, error) {
	response, err := o.service.EvaluatePrepared(ctx, transport, prepare)
	if err == nil {
		o.responses <- response
	}

	return response, err
}

// next returns the next exact transport evaluation result with a bounded wait.
func (o *productionTransportObserver) next(t *testing.T) decision.DecisionResponse {
	t.Helper()

	select {
	case response := <-o.responses:
		return response
	case <-time.After(time.Second):
		t.Fatal("transport did not complete one production Policy evaluation")

		return decision.DecisionResponse{}
	}
}

// serveProductionTransportHTTP exercises the registered Gin route with direct TLS and dedicated Policy Basic.
func serveProductionTransportHTTP(t *testing.T, service decisionservice.PreparedService) {
	t.Helper()

	gin.SetMode(gin.TestMode)

	engine := gin.New()
	policyhttp.New(service, policyhttp.DirectTLSTransportEvidence{}).Register(engine.Group("/api/v1"))

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/policy/decisions",
		strings.NewReader(`{"version":"1","request_id":"production-http-wire","target":{"namespace":"mail","action":"submit"}}`),
	)
	request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("policy-user:policy-password")))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true}

	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}

	var response struct {
		Effect string `json:"effect"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode HTTP Policy response: %v", err)
	}

	if response.Effect != string(decision.EffectPermit) {
		t.Fatalf("HTTP effect = %q, want permit", response.Effect)
	}
}

// newProductionTransportGRPCClient serves the production gRPC authority stack over a protobuf bufconn wire.
func newProductionTransportGRPCClient(
	t *testing.T,
	configured config.File,
	service decisionservice.PreparedService,
) policyv1.PolicyDecisionServiceClient {
	t.Helper()

	listener := bufconn.Listen(1024 * 1024)

	server, err := grpcauthority.NewServer(grpcauthority.ServerDeps{
		Cfg:           configured,
		AuthService:   productionTransportNoopAuthService{},
		PolicyService: service,
	})
	if err != nil {
		t.Fatalf("grpcauthority.NewServer() error = %v", err)
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(listener)
	}()

	connection, err := grpc.NewClient(
		"passthrough:///production-policy-bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		server.Stop()

		_ = listener.Close()

		t.Fatalf("grpc.NewClient() error = %v", err)
	}

	t.Cleanup(func() {
		_ = connection.Close()

		server.Stop()

		_ = listener.Close()

		select {
		case err := <-serveErr:
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				t.Errorf("bufconn server error = %v", err)
			}
		case <-time.After(time.Second):
			t.Error("bufconn server did not stop")
		}
	})

	return policyv1.NewPolicyDecisionServiceClient(connection)
}

type productionTransportNoopAuthService struct{}

// Authenticate keeps the unrelated AuthService registration fail-closed in this Policy-only test.
func (productionTransportNoopAuthService) Authenticate(context.Context, core.AuthInput) (*core.AuthOutcome, error) {
	return nil, core.ErrAuthApplicationDependencyMissing
}

// LookupIdentity keeps the unrelated identity operation fail-closed in this Policy-only test.
func (productionTransportNoopAuthService) LookupIdentity(context.Context, core.AuthInput) (*core.AuthOutcome, error) {
	return nil, core.ErrAuthApplicationDependencyMissing
}

// ListAccounts keeps the unrelated account operation fail-closed in this Policy-only test.
func (productionTransportNoopAuthService) ListAccounts(context.Context, core.AuthInput) (*core.ListAccountsOutcome, error) {
	return nil, core.ErrAuthApplicationDependencyMissing
}

// assertProductionTransportSelection checks the exact internal metadata omitted from public transport DTOs.
func assertProductionTransportSelection(t *testing.T, response decision.DecisionResponse, generation uint64) {
	t.Helper()

	if response.Effect() != decision.EffectPermit ||
		response.Policy().PolicySet() != "mail/default" ||
		response.Policy().Rule() != "production_permit" ||
		response.Policy().Generation() != generation {
		t.Fatalf(
			"production selection = %q/%q/%q/%d, want permit/mail/default/production_permit/%d",
			response.Effect(),
			response.Policy().PolicySet(),
			response.Policy().Rule(),
			response.Policy().Generation(),
			generation,
		)
	}
}

// assertProductionTransportGeneration proves neither transport published or substituted runtime state.
func assertProductionTransportGeneration(
	t *testing.T,
	store *policyruntime.GenerationStore,
	want *policyruntime.Generation,
) {
	t.Helper()

	got := store.Active()
	if got == nil {
		t.Fatal("active generation disappeared after transport evaluation")
	}

	if got != want || got.ID() != want.ID() {
		t.Fatalf("active generation changed from %p/%d to %p/%d", want, want.ID(), got, got.ID())
	}
}

// shutdownProductionTransportStore registers bounded retirement after transport cleanup.
func shutdownProductionTransportStore(t *testing.T, store *policyruntime.GenerationStore) {
	t.Helper()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		if err := store.Shutdown(ctx); err != nil {
			t.Errorf("shutdown production Policy generation: %v", err)
		}
	})
}

var _ callerauth.AccessTokenValidator = productionTransportTokenValidator{}
var _ decisionservice.PreparedService = (*productionTransportObserver)(nil)
var _ core.AuthApplicationService = productionTransportNoopAuthService{}
