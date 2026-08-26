package grpcauthority

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authv1 "github.com/croessner/nauthilus/v3/api/auth/v1"
	policyv1 "github.com/croessner/nauthilus/v3/api/policy/v1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/policygrpc"
	"github.com/croessner/nauthilus/v3/server/handler/policyhttp"
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

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestBufconnPolicyEvaluateUsesDedicatedInterceptorEvidence(t *testing.T) {
	service := &recordingPolicyDecisionService{invocations: make(chan decision.Invocation, 1)}
	client := newBufconnPolicyClient(t, service)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		authorizationMetadataKey,
		"Basic "+base64.StdEncoding.EncodeToString([]byte("policy-client:policy-secret")),
	))

	_, err := client.Evaluate(ctx, policyDecisionRequest())
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	select {
	case invocation := <-service.invocations:
		if invocation.Authentication.Kind() != "basic" || invocation.Authentication.TransportKind() != "grpc" {
			t.Fatalf("authentication = %q/%q, want basic/grpc", invocation.Authentication.Kind(), invocation.Authentication.TransportKind())
		}

		if invocation.Authentication.GRPCMethod() != policyv1.PolicyDecisionService_Evaluate_FullMethodName {
			t.Fatalf("method = %q, want Policy Evaluate", invocation.Authentication.GRPCMethod())
		}
	case <-time.After(time.Second):
		t.Fatal("Policy DecisionService was not invoked")
	}
}

func TestBufconnPolicyEvaluateRejectsMissingCredentialsBeforeHandler(t *testing.T) {
	service := &recordingPolicyDecisionService{invocations: make(chan decision.Invocation, 1)}
	client := newBufconnPolicyClient(t, service)

	_, err := client.Evaluate(context.Background(), policyDecisionRequest())

	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Evaluate() code = %s, want %s", status.Code(err), codes.Unauthenticated)
	}

	select {
	case <-service.invocations:
		t.Fatal("Policy handler was invoked without credentials")
	default:
	}
}

func TestBufconnPolicyDisabledRoutePrecedesTransportPreparation(t *testing.T) {
	service := &recordingPolicyDecisionService{
		invocations: make(chan decision.Invocation, 1),
		err:         decisionservice.ErrDecisionRouteUnavailable,
	}
	client := newBufconnPolicyClient(t, service)

	oversized := policyDecisionRequest()
	oversized.Attributes = map[string]*policyv1.Value{
		"oversized": {Kind: &policyv1.Value_String_{String_: strings.Repeat("x", decision.MaximumOpaqueCredentialBytes)}},
	}

	for _, testCase := range []struct {
		ctx     context.Context
		request *policyv1.DecisionRequest
		name    string
	}{
		{name: "missing credentials", ctx: context.Background(), request: policyDecisionRequest()},
		{
			name: "oversized credentials",
			ctx: metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
				authorizationMetadataKey,
				"Bearer "+strings.Repeat("t", decision.MaximumOpaqueCredentialBytes+1),
			)),
			request: policyDecisionRequest(),
		},
		{name: "oversized payload", ctx: context.Background(), request: oversized},
		{name: "malformed request", ctx: context.Background(), request: &policyv1.DecisionRequest{}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := client.Evaluate(testCase.ctx, testCase.request)
			if status.Code(err) != codes.Unimplemented {
				t.Fatalf("Evaluate() code = %s, want %s", status.Code(err), codes.Unimplemented)
			}
		})
	}

	if service.transportKind != grpcTransportKind {
		t.Fatalf("transport kind = %q, want %q", service.transportKind, grpcTransportKind)
	}

	select {
	case <-service.invocations:
		t.Fatal("disabled Policy route reached invocation evaluation")
	default:
	}
}

func TestBufconnPolicyEvaluateRejectsOversizedMessageBeforeService(t *testing.T) {
	service := &recordingPolicyDecisionService{invocations: make(chan decision.Invocation, 1)}
	client := newBufconnPolicyClient(t, service)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		authorizationMetadataKey,
		"Bearer policy-token",
	))
	request := policyDecisionRequest()
	request.Attributes = map[string]*policyv1.Value{
		"oversized": {Kind: &policyv1.Value_String_{String_: strings.Repeat("x", decision.MaximumOpaqueCredentialBytes)}},
	}

	_, err := client.Evaluate(ctx, request)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("Evaluate() code = %s, want %s", status.Code(err), codes.ResourceExhausted)
	}

	select {
	case <-service.invocations:
		t.Fatal("Policy service was invoked for an oversized request")
	default:
	}
}

func TestPolicyLimitDoesNotChangeAuthMessageLimit(t *testing.T) {
	service := &recordingService{authOutcome: newBufconnAuthOutcome(core.AuthDecisionOK, "large-auth-request")}
	client := newBufconnAuthServiceClient(t, service)
	ctx := outgoingBasicAuthContext(context.Background())
	username := strings.Repeat("u", decision.MaximumOpaqueCredentialBytes+1024)

	response, err := client.Authenticate(ctx, &authv1.AuthRequest{
		Username: username,
		Password: "secret",
		Protocol: "imap",
	})
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	if !response.GetOk() || service.authInput.Credentials.Username != username {
		t.Fatal("the existing Auth RPC did not reach its normal application path")
	}
}

func TestBufconnPolicyEvaluateRejectsOversizedCredentialBeforeService(t *testing.T) {
	service := &recordingPolicyDecisionService{invocations: make(chan decision.Invocation, 1)}
	client := newBufconnPolicyClient(t, service)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		authorizationMetadataKey,
		"Bearer "+strings.Repeat("t", decision.MaximumOpaqueCredentialBytes+1),
	))

	_, err := client.Evaluate(ctx, policyDecisionRequest())
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("Evaluate() code = %s, want %s", status.Code(err), codes.ResourceExhausted)
	}

	select {
	case <-service.invocations:
		t.Fatal("Policy service was invoked for an oversized credential")
	default:
	}
}

func TestBufconnPolicyEvaluateMapsServiceCancellation(t *testing.T) {
	service := &recordingPolicyDecisionService{invocations: make(chan decision.Invocation, 1), err: context.Canceled}
	client := newBufconnPolicyClient(t, service)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		authorizationMetadataKey,
		"Bearer policy-token",
	))

	_, err := client.Evaluate(ctx, policyDecisionRequest())
	if status.Code(err) != codes.Canceled {
		t.Fatalf("Evaluate() code = %s, want %s", status.Code(err), codes.Canceled)
	}
}

func TestBufconnPolicyEvaluateEnforcesRealDecisionServiceAuthority(t *testing.T) {
	service, closeGeneration := newGRPCPolicyDecisionService(t)
	t.Cleanup(closeGeneration)
	client := newBufconnPolicyClient(t, service)

	for _, testCase := range []struct {
		name          string
		authorization string
		request       *policyv1.DecisionRequest
		want          codes.Code
	}{
		{name: "exact bearer", authorization: "Bearer policy-valid", request: policyDecisionRequest(), want: codes.OK},
		{name: "wrong audience", authorization: "Bearer policy-wrong-audience", request: policyDecisionRequest(), want: codes.Unauthenticated},
		{name: "multiple audiences", authorization: "Bearer policy-multiple-audience", request: policyDecisionRequest(), want: codes.Unauthenticated},
		{name: "missing scope", authorization: "Bearer policy-missing-scope", request: policyDecisionRequest(), want: codes.Unauthenticated},
		{name: "management basic", authorization: "Basic " + base64.StdEncoding.EncodeToString([]byte("management-client:management-secret")), request: policyDecisionRequest(), want: codes.Unauthenticated},
		{name: "plaintext policy basic", authorization: "Basic " + base64.StdEncoding.EncodeToString([]byte("policy-grpc-basic:policy-grpc-basic-secret")), request: policyDecisionRequest(), want: codes.Unauthenticated},
		{name: "target admission", authorization: "Bearer policy-valid", request: &policyv1.DecisionRequest{Version: "1", Target: &policyv1.Target{Namespace: "mail", Action: "other"}}, want: codes.PermissionDenied},
		{name: "diagnostics admission", authorization: "Bearer policy-valid", request: &policyv1.DecisionRequest{Version: "1", Target: &policyv1.Target{Namespace: "mail", Action: "submit"}, Options: &policyv1.EvaluationOptions{IncludeDiagnostics: true}}, want: codes.PermissionDenied},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(authorizationMetadataKey, testCase.authorization))

			response, err := client.Evaluate(ctx, testCase.request)
			if got := status.Code(err); got != testCase.want {
				t.Fatalf("Evaluate() code = %s, want %s (%v)", got, testCase.want, err)
			}

			if testCase.want == codes.OK && response.GetEffect() != policyv1.Effect_EFFECT_DENY {
				t.Fatalf("effect = %s, want deterministic deny", response.GetEffect())
			}
		})
	}
}

func TestBufconnPolicyEvaluateReturnsEveryEffectWithOK(t *testing.T) {
	for _, effect := range []decision.Effect{decision.EffectPermit, decision.EffectDeny, decision.EffectNotApplicable, decision.EffectIndeterminate} {
		t.Run(string(effect), func(t *testing.T) {
			client := newBufconnPolicyClient(t, effectPolicyService{response: grpcPolicyResponse(t, effect)})
			ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(authorizationMetadataKey, "Bearer policy-token"))

			response, err := client.Evaluate(ctx, policyDecisionRequest())
			if status.Code(err) != codes.OK || response.GetEffect() != policyEffect(effect) {
				t.Fatalf("Evaluate() = %s/%s, want OK/%s", status.Code(err), response.GetEffect(), policyEffect(effect))
			}
		})
	}
}

func TestPolicyHTTPGRPCAndInternalNormalizedParity(t *testing.T) {
	service := &parityPolicyService{response: grpcPolicyResponseWithDiagnostics(t, decision.EffectDeny)}
	client := newBufconnPolicyClient(t, service)
	grpcRequest := &policyv1.DecisionRequest{
		Version: "1", Target: &policyv1.Target{Namespace: "mail", Action: "submit"},
		Attributes: map[string]*policyv1.Value{"key": {Kind: &policyv1.Value_String_{String_: "value"}}},
	}
	grpcContext := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(authorizationMetadataKey, "Bearer parity-token"))

	grpcResponse, err := client.Evaluate(grpcContext, grpcRequest)
	if err != nil {
		t.Fatalf("gRPC Evaluate: %v", err)
	}

	gin.SetMode(gin.TestMode)

	engine := gin.New()
	policyhttp.New(service, policyhttp.DirectTLSTransportEvidence{}).Register(engine.Group("/api/v1"))

	httpRequest := httptest.NewRequest(http.MethodPost, "/api/v1/policy/decisions", strings.NewReader(`{"version":"1","target":{"namespace":"mail","action":"submit"},"attributes":{"key":{"string":"value"}}}`))
	httpRequest.Header.Set("Authorization", "Bearer parity-token")
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.TLS = &tls.ConnectionState{HandshakeComplete: true}
	httpResponse := httptest.NewRecorder()
	engine.ServeHTTP(httpResponse, httpRequest)

	if httpResponse.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200", httpResponse.Code)
	}

	if len(service.invocations) != 2 {
		t.Fatalf("invocation count = %d, want 2", len(service.invocations))
	}

	assertNormalizedRequestParity(t, service.invocations[0].Request, service.invocations[1].Request)

	if grpcResponse.GetEffect() != policyv1.Effect_EFFECT_DENY || !strings.Contains(httpResponse.Body.String(), `"effect":"deny"`) {
		t.Fatalf("transport result effects are not equivalent: grpc=%s http=%s", grpcResponse.GetEffect(), httpResponse.Body.String())
	}

	if grpcResponse.GetDiagnostics().GetEntries()["public"].GetString_() != "selected" || grpcResponse.GetDiagnostics().GetEntries()["internal"] != nil {
		t.Fatalf("gRPC diagnostics are not the admitted sanitized projection: %#v", grpcResponse.GetDiagnostics())
	}

	if !strings.Contains(httpResponse.Body.String(), `"diagnostics":{"entries":{"public":{"string":"selected"}}}`) || strings.Contains(httpResponse.Body.String(), "internal") {
		t.Fatalf("HTTP diagnostics are not the admitted sanitized projection: %s", httpResponse.Body.String())
	}
}

func TestBufconnPolicyEvaluateOmitsDiagnosticsWhenApplicationResponseOmitsThem(t *testing.T) {
	client := newBufconnPolicyClient(t, effectPolicyService{response: grpcPolicyResponse(t, decision.EffectDeny)})
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(authorizationMetadataKey, "Bearer policy-token"))

	response, err := client.Evaluate(ctx, policyDecisionRequest())
	if err != nil {
		t.Fatalf("Evaluate(): %v", err)
	}

	if response.GetDiagnostics() != nil {
		t.Fatalf("diagnostics = %#v, want omitted", response.GetDiagnostics())
	}
}

// assertNormalizedRequestParity compares the contract fields both adapters submit to the application authority.
func assertNormalizedRequestParity(t *testing.T, grpcRequest, httpRequest decision.DecisionRequestInput) {
	t.Helper()

	if grpcRequest.Version != httpRequest.Version || grpcRequest.Target != httpRequest.Target {
		t.Fatalf("normalized request identity differs: grpc=%#v http=%#v", grpcRequest, httpRequest)
	}

	grpcValue, grpcOK := grpcRequest.Attributes["key"].StringValue()

	httpValue, httpOK := httpRequest.Attributes["key"].StringValue()
	if !grpcOK || !httpOK || grpcValue != httpValue {
		t.Fatalf("normalized attributes differ: grpc=%q/%t http=%q/%t", grpcValue, grpcOK, httpValue, httpOK)
	}
}

func TestPolicyBasicRequiresVerifiedGRPCMTLSBeforeRealDecisionService(t *testing.T) {
	service, closeGeneration := newGRPCPolicyDecisionService(t)
	t.Cleanup(closeGeneration)

	handler := policygrpc.New(service, policyAuthenticationEvidence)
	credential := "Basic " + base64.StdEncoding.EncodeToString([]byte("policy-grpc-basic:policy-grpc-basic-secret"))

	for _, testCase := range []struct {
		name     string
		verified bool
		want     codes.Code
	}{
		{name: "verified client identity", verified: true, want: codes.OK},
		{name: "unverified client identity", verified: false, want: codes.Unauthenticated},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := policyTLSContext(credential, testCase.verified)
			ctx, gate := core.ContextWithPostActionExecutionGate(ctx)
			defer gate.Complete()

			_, err := handler.Evaluate(ctx, policyDecisionRequest())
			if got := status.Code(err); got != testCase.want {
				t.Fatalf("Evaluate() code = %s, want %s (%v)", got, testCase.want, err)
			}
		})
	}
}

// policyTLSContext supplies listener-originated TLS evidence for the Policy-Basic boundary fixture.
func policyTLSContext(authorization string, verified bool) context.Context {
	certificate := &x509.Certificate{Subject: pkix.Name{CommonName: "policy-grpc-basic"}}

	state := tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{certificate}}
	if verified {
		state.VerifiedChains = [][]*x509.Certificate{{certificate}}
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(authorizationMetadataKey, authorization))

	return peer.NewContext(ctx, &peer.Peer{AuthInfo: credentials.TLSInfo{
		State: state, CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
	}})
}

func TestPolicyAuthorityUnknownMethodDoesNotInheritAuthenticateScope(t *testing.T) {
	interceptor := backchannelAuthInterceptor(ServerDeps{Cfg: grpcAuthTestConfig(config.BasicAuth{}, config.OIDCAuth{})})
	handlerCalled := false

	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/nauthilus.policy.v1.PolicyDecisionService/Unknown"}, func(context.Context, any) (any, error) {
		handlerCalled = true

		return nil, nil
	})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("unknown method code = %s, want %s", status.Code(err), codes.Unimplemented)
	}

	if handlerCalled {
		t.Fatal("unknown method reached the handler")
	}
}

func newBufconnPolicyClient(t *testing.T, service decisionservice.PreparedService) policyv1.PolicyDecisionServiceClient {
	t.Helper()

	listener := bufconn.Listen(1024 * 1024)

	server, err := NewServer(ServerDeps{
		Cfg: grpcAuthTestConfig(config.BasicAuth{
			Enabled:  true,
			Username: "management-client",
			Password: secret.New("management-secret"),
		}, config.OIDCAuth{}),
		AuthService:   &recordingService{},
		PolicyService: service,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	serveErr := make(chan error, 1)

	go func() { serveErr <- server.Serve(listener) }()

	t.Cleanup(func() {
		server.Stop()

		_ = listener.Close()

		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("bufconn server error = %v", err)
			}
		case <-time.After(time.Second):
			t.Error("bufconn server did not stop")
		}
	})

	connection, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("bufconn dial error = %v", err)
	}

	t.Cleanup(func() { _ = connection.Close() })

	return policyv1.NewPolicyDecisionServiceClient(connection)
}

func policyDecisionRequest() *policyv1.DecisionRequest {
	return &policyv1.DecisionRequest{
		Version: "1",
		Target:  &policyv1.Target{Namespace: "mail", Action: "submit"},
	}
}

type recordingPolicyDecisionService struct {
	invocations   chan decision.Invocation
	err           error
	transportKind string
}

func (s *recordingPolicyDecisionService) Evaluate(_ context.Context, invocation decision.Invocation) (decision.DecisionResponse, error) {
	s.invocations <- invocation

	return decision.DecisionResponse{}, s.err
}

// EvaluatePrepared records one invocation prepared under a captured test configuration.
func (s *recordingPolicyDecisionService) EvaluatePrepared(
	ctx context.Context,
	transportKind string,
	prepare func(config.File) (decision.Invocation, error),
) (decision.DecisionResponse, error) {
	s.transportKind = transportKind
	if errors.Is(s.err, decisionservice.ErrDecisionRouteUnavailable) {
		return decision.DecisionResponse{}, s.err
	}

	invocation, err := prepare(enabledGRPCPolicyAuthorityConfig())
	if err != nil {
		return decision.DecisionResponse{}, err
	}

	return s.Evaluate(ctx, invocation)
}

type effectPolicyService struct {
	response decision.DecisionResponse
}

type parityPolicyService struct {
	invocations []decision.Invocation
	response    decision.DecisionResponse
}

// Evaluate records both transport-normalized invocations before returning one shared application result.
func (s *parityPolicyService) Evaluate(_ context.Context, invocation decision.Invocation) (decision.DecisionResponse, error) {
	s.invocations = append(s.invocations, invocation)

	return s.response, nil
}

// EvaluatePrepared records transport parity under one captured test configuration.
func (s *parityPolicyService) EvaluatePrepared(
	ctx context.Context,
	_ string,
	prepare func(config.File) (decision.Invocation, error),
) (decision.DecisionResponse, error) {
	invocation, err := prepare(enabledGRPCPolicyAuthorityConfig())
	if err != nil {
		return decision.DecisionResponse{}, err
	}

	return s.Evaluate(ctx, invocation)
}

// Evaluate returns one constructor-validated fixture result through the complete gRPC adapter.
func (s effectPolicyService) Evaluate(context.Context, decision.Invocation) (decision.DecisionResponse, error) {
	return s.response, nil
}

// EvaluatePrepared returns one fixture result after capture-first transport preparation.
func (s effectPolicyService) EvaluatePrepared(
	ctx context.Context,
	_ string,
	prepare func(config.File) (decision.Invocation, error),
) (decision.DecisionResponse, error) {
	invocation, err := prepare(enabledGRPCPolicyAuthorityConfig())
	if err != nil {
		return decision.DecisionResponse{}, err
	}

	return s.Evaluate(ctx, invocation)
}

// grpcPolicyResponse builds a complete response for one closed effect fixture.
func grpcPolicyResponse(t *testing.T, effect decision.Effect) decision.DecisionResponse {
	return grpcPolicyResponseInput(t, effect, nil)
}

// grpcPolicyResponseWithDiagnostics builds one response with a sanitized admitted diagnostic projection.
func grpcPolicyResponseWithDiagnostics(t *testing.T, effect decision.Effect) decision.DecisionResponse {
	value := "selected"

	diagnosticValue, err := decision.NewValue(decision.ValueInput{String: &value})
	if err != nil {
		t.Fatalf("new diagnostic value: %v", err)
	}

	diagnostics, err := decision.NewDiagnostics(map[string]decision.Value{"public": diagnosticValue})
	if err != nil {
		t.Fatalf("new diagnostics: %v", err)
	}

	return grpcPolicyResponseInput(t, effect, &diagnostics)
}

// grpcPolicyResponseInput constructs a complete response while keeping diagnostics optional at the test boundary.
func grpcPolicyResponseInput(t *testing.T, effect decision.Effect, diagnostics *decision.Diagnostics) decision.DecisionResponse {
	t.Helper()

	statusValue, err := decision.NewStatus(decision.StatusCodePermit, "fixture", nil)
	if err != nil {
		t.Fatalf("new status: %v", err)
	}

	metadataValue, err := decision.NewPolicyMetadata("test/policy", "v1", "fixture", 1)
	if err != nil {
		t.Fatalf("new policy metadata: %v", err)
	}

	response, err := decision.NewDecisionResponse(decision.DecisionResponseInput{
		RequestID: "request", DecisionID: "decision", Effect: effect, Status: statusValue, Policy: metadataValue, Diagnostics: diagnostics,
	})
	if err != nil {
		t.Fatalf("new response: %v", err)
	}

	return response
}

// policyEffect projects the closed internal effect for the response assertion.
func policyEffect(effect decision.Effect) policyv1.Effect {
	switch effect {
	case decision.EffectPermit:
		return policyv1.Effect_EFFECT_PERMIT
	case decision.EffectDeny:
		return policyv1.Effect_EFFECT_DENY
	case decision.EffectNotApplicable:
		return policyv1.Effect_EFFECT_NOT_APPLICABLE
	default:
		return policyv1.Effect_EFFECT_INDETERMINATE
	}
}

type grpcAcceptingPostAction struct{}

// Accept confirms fixture ownership without scheduling post-action work.
func (grpcAcceptingPostAction) Accept(context.Context, effectsupervisor.Plan) (effectsupervisor.Receipt, error) {
	return effectsupervisor.Receipt{}, nil
}

type grpcPolicyTokenValidator struct{}

// ValidateAccessToken returns fixed issuer-validated evidence for gRPC boundary coverage.
func (grpcPolicyTokenValidator) ValidateAccessToken(_ context.Context, credential []byte) (callerauth.ValidatedAccessToken, error) {
	token := callerauth.ValidatedAccessToken{
		Audiences: []string{definitions.AudiencePolicyAPI}, Scopes: []string{definitions.ScopePolicyEvaluate},
		ClientID: "policy-grpc", Issuer: "https://issuer.example.test", Subject: "policy-subject", TokenType: definitions.TokenTypeAccessToken,
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
	default:
		return callerauth.ValidatedAccessToken{}, fmt.Errorf("unknown fixture token")
	}

	return token, nil
}

// grpcPolicyCatalog builds the single admitted non-auth target used by the real gRPC authority fixture.
func grpcPolicyCatalog(t *testing.T) (*policyruntime.TargetCatalog, registry.ClientAdmissionReference) {
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
		t.Fatalf("new checkpoint: %v", err)
	}

	plan, err := registry.NewDomainPlanDefinition(target, []registry.CheckpointDefinition{checkpoint})
	if err != nil {
		t.Fatalf("new plan: %v", err)
	}

	catalog, err := policyruntime.NewTargetCatalog([]policyruntime.TargetCatalogRecord{{
		Target: target, Schema: schema, SourcePlan: plan, Checkpoints: []policyruntime.CheckpointRecord{{Name: decision.CheckpointFinalDecision}},
		NoMatch: registry.NoMatchDeny, AuthorityMode: registry.AuthorityModeEnforce,
	}}, nil)
	if err != nil {
		t.Fatalf("new target catalog: %v", err)
	}

	reference, err := registry.NewClientAdmissionReference("test.policy-grpc", "mail", "submit", identity.String())
	if err != nil {
		t.Fatalf("new admission reference: %v", err)
	}

	return catalog, reference
}

// newGRPCPolicyDecisionService compiles a genuine application generation for the gRPC boundary.
func newGRPCPolicyDecisionService(t *testing.T) (*decisionservice.DecisionService, func()) {
	t.Helper()

	store := policyruntime.NewGenerationStore()

	bindings, err := policyruntime.NewBindingSet(policyruntime.BindingSetInput{PostActionAcceptance: grpcAcceptingPostAction{}})
	if err != nil {
		t.Fatalf("new binding set: %v", err)
	}

	catalog, reference := grpcPolicyCatalog(t)

	callerConfiguration, admissionConfiguration := grpcPolicyAuthorityConfiguration(reference)

	coordinator, err := policyruntime.NewCoordinator(policyruntime.CoordinatorConfig{Store: store, Slots: policyruntime.PreparationSlots{
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
					Limits: policyruntime.DecisionLimits{
						EvaluationTimeout: time.Second, PostActionBudget: time.Second, MaxDiagnosticsEntries: 8,
					},
					Reports: policyruntime.DecisionReportSettings{MaxEntries: 8},
				},
			}, nil
		}),
		Application: decisionservice.NewRuntimeApplicationPreparationSlot(),
	}})
	if err != nil {
		t.Fatalf("new coordinator: %v", err)
	}

	if _, err = coordinator.Apply(context.Background(), policyruntime.PrepareInput{Config: enabledGRPCPolicyAuthorityConfig(), ID: 1}); err != nil {
		t.Fatalf("apply policy runtime: %v", err)
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
			t.Errorf("shutdown policy runtime: %v", shutdownErr)
		}
	}
}

// grpcPolicyAuthorityConfiguration keeps the fixture's caller and admission principals exactly aligned.
func grpcPolicyAuthorityConfiguration(reference registry.ClientAdmissionReference) (callerauth.Configuration, admission.Configuration) {
	caller := callerauth.Configuration{
		ExternalProfiles: []callerauth.ExternalProfile{
			{AuthenticationKinds: []string{policy.CallerAuthenticationKindBearer}, Principal: "policy-grpc"},
			{Basic: &callerauth.BasicCredential{Username: "policy-grpc-basic", Password: secret.New("policy-grpc-basic-secret")}, AuthenticationKinds: []string{policy.CallerAuthenticationKindBasic}, Principal: "policy-grpc-basic", RequireMTLS: true},
		},
		TokenValidator: grpcPolicyTokenValidator{}, Throttler: &grpcAcceptingPolicyBasicThrottler{}, TransportCapabilities: callerauth.TransportCapabilities{
			GRPCProtected:                 true,
			GRPCVerifiedClientCertificate: true,
		},
	}
	admission := admission.Configuration{
		GlobalLimits: admission.Limits{MaxRequestBytes: 4096, MaxFacts: 8, MaxConcurrency: 4, RequestsPerSecond: 1000},
		Profiles: []admission.Profile{
			{AuthenticationKinds: []string{policy.CallerAuthenticationKindBearer}, Limits: admission.Limits{MaxConcurrency: 1}, Principal: "policy-grpc", References: []registry.ClientAdmissionReference{reference}},
			{AuthenticationKinds: []string{policy.CallerAuthenticationKindBasic}, Limits: admission.Limits{MaxConcurrency: 1}, Principal: "policy-grpc-basic", References: []registry.ClientAdmissionReference{reference}},
		},
	}

	return caller, admission
}

type grpcAcceptingPolicyBasicThrottler struct{}

// BeforeAttempt accepts one focused gRPC adapter-fixture verification attempt.
func (*grpcAcceptingPolicyBasicThrottler) BeforeAttempt(context.Context, callerauth.BasicThrottleKey) error {
	return nil
}

// RecordFailure accepts one focused gRPC adapter-fixture verification failure.
func (*grpcAcceptingPolicyBasicThrottler) RecordFailure(context.Context, callerauth.BasicThrottleKey) error {
	return nil
}

// RecordSuccess accepts one focused gRPC adapter-fixture verification success.
func (*grpcAcceptingPolicyBasicThrottler) RecordSuccess(context.Context, callerauth.BasicThrottleKey) error {
	return nil
}

// enabledGRPCPolicyAuthorityConfig supplies generation-owned gRPC activation and wire bounds to fixtures.
func enabledGRPCPolicyAuthorityConfig() config.File {
	return &config.FileSettings{
		Server: &config.ServerSection{},
		Policy: policyconfig.PolicyConfig{API: policyconfig.APIConfig{
			Enabled: true,
			GRPC:    policyconfig.GRPCConfig{Enabled: true},
			Limits:  policyconfig.APILimitsConfig{MaxRequestBytes: decision.MaximumOpaqueCredentialBytes},
		}},
	}
}
