package policygrpc

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	policyv1 "github.com/croessner/nauthilus/v4/api/policy/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestPolicyGRPCRejectsRawValueWireAmbiguityAndUnknownFields(t *testing.T) {
	t.Run("absent oneof", func(t *testing.T) {
		request := policyRequestWithValue(&policyv1.Value{})
		if _, err := requestInput(request); err == nil {
			t.Fatal("requestInput() succeeded for absent oneof")
		}
	})

	t.Run("last oneof tag wins", func(t *testing.T) {
		encoded, err := proto.Marshal(&policyv1.Value{Kind: &policyv1.Value_String_{String_: "first"}})
		if err != nil {
			t.Fatalf("marshal value: %v", err)
		}

		encoded = append(encoded, 0x18, 0x02)

		decoded := &policyv1.Value{}

		if err = proto.Unmarshal(encoded, decoded); err != nil {
			t.Fatalf("unmarshal conflicting value: %v", err)
		}

		input, err := requestInput(policyRequestWithValue(decoded))
		if err != nil {
			t.Fatalf("requestInput() error = %v", err)
		}

		value, found := input.Attributes["value"]
		if !found {
			t.Fatal("normalized attribute missing")
		}

		integer, ok := value.Integer()
		if !ok || integer != 1 {
			t.Fatalf("last oneof value = %#v, want integer 1", value)
		}
	})

	t.Run("unknown field", func(t *testing.T) {
		request := policyRequestWithValue(&policyv1.Value{Kind: &policyv1.Value_String_{String_: "value"}})

		encoded, err := proto.Marshal(request)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}

		encoded = append(encoded, 0x98, 0x06, 0x01)

		decoded := &policyv1.DecisionRequest{}
		if err = proto.Unmarshal(encoded, decoded); err != nil {
			t.Fatalf("unmarshal unknown-field request: %v", err)
		}

		if _, err = requestInput(decoded); err == nil {
			t.Fatal("requestInput() accepted protobuf unknown fields")
		}
	})
}

func TestPolicyGRPCRejectsNestedUnknownValueField(t *testing.T) {
	encoded, err := proto.Marshal(&policyv1.Value{Kind: &policyv1.Value_String_{String_: "value"}})
	if err != nil {
		t.Fatalf("marshal value: %v", err)
	}

	encoded = append(encoded, 0x98, 0x06, 0x01)

	decoded := &policyv1.Value{}
	if err = proto.Unmarshal(encoded, decoded); err != nil {
		t.Fatalf("unmarshal nested value: %v", err)
	}

	if _, err = requestInput(policyRequestWithValue(decoded)); err == nil {
		t.Fatal("requestInput() accepted a nested protobuf unknown field")
	}
}

func TestPolicyGRPCMapsClosedApplicationErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code codes.Code
	}{
		{name: "invalid", err: decision.ErrInvalidRequest, code: codes.InvalidArgument},
		{name: "route disabled", err: decisionservice.ErrDecisionRouteUnavailable, code: codes.Unimplemented},
		{name: "authentication", err: decisionservice.ErrDecisionAuthentication, code: codes.Unauthenticated},
		{name: "admission", err: decisionservice.ErrDecisionAdmission, code: codes.PermissionDenied},
		{name: "unavailable", err: decisionservice.ErrDecisionGenerationUnavailable, code: codes.Unavailable},
		{name: "cancelled", err: context.Canceled, code: codes.Canceled},
		{name: "deadline", err: context.DeadlineExceeded, code: codes.DeadlineExceeded},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := status.Code(grpcServiceError(testCase.err)); got != testCase.code {
				t.Fatalf("grpc code = %s, want %s", got, testCase.code)
			}
		})
	}
}

func TestPolicyGRPCHandlerRequiresInterceptorEvidence(t *testing.T) {
	handler := New(&policyRecordingService{err: errors.New("unexpected invocation")}, contextAuthenticationEvidence)

	_, err := handler.Evaluate(context.Background(), validPolicyRequest())
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Evaluate() code = %s, want %s", status.Code(err), codes.Unauthenticated)
	}
}

func TestPolicyGRPCDisabledRoutePrecedesRequestPreparation(t *testing.T) {
	oversized := validPolicyRequest()
	oversized.Attributes["oversized"] = &policyv1.Value{
		Kind: &policyv1.Value_String_{String_: strings.Repeat("x", decision.MaximumOpaqueCredentialBytes)},
	}

	for _, testCase := range []struct {
		request *policyv1.DecisionRequest
		name    string
	}{
		{name: "missing credentials", request: validPolicyRequest()},
		{name: "malformed request", request: &policyv1.DecisionRequest{}},
		{name: "oversized request", request: oversized},
		{name: "missing finalization gate", request: validPolicyRequest()},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			service := &policyRecordingService{err: decisionservice.ErrDecisionRouteUnavailable}
			handler := New(service, contextAuthenticationEvidence)

			_, err := handler.Evaluate(context.Background(), testCase.request)
			if status.Code(err) != codes.Unimplemented {
				t.Fatalf("Evaluate() code = %s, want %s", status.Code(err), codes.Unimplemented)
			}

			if service.transportKind != policyGRPCTransportKind {
				t.Fatalf("transport kind = %q, want %q", service.transportKind, policyGRPCTransportKind)
			}
		})
	}
}

func TestPolicyGRPCAdapterCannotImportEvaluatorOrCaptureAGeneration(t *testing.T) {
	source, err := os.ReadFile("handler.go")
	if err != nil {
		t.Fatalf("read adapter source: %v", err)
	}

	for _, forbidden := range []string{"server/policy/evaluation", "NewStoreGenerationSource", "NewDecisionService"} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("adapter source contains forbidden boundary dependency %q", forbidden)
		}
	}
}

func TestPolicyGRPCHandlerKeepsFinalizationClosedUntilOuterUnaryBoundary(t *testing.T) {
	service := &policyFinalizationService{}
	handler := New(service, contextAuthenticationEvidence)
	ctx, gate := core.ContextWithPostActionExecutionGate(context.Background())

	authentication, err := decision.NewAuthenticationInput(decision.AuthenticationEvidence{
		Kind: "basic", Credential: []byte("policy:secret"), TransportKind: "grpc", Protected: true,
	})
	if err != nil {
		t.Fatalf("new authentication input: %v", err)
	}

	_, err = handler.Evaluate(ContextWithAuthentication(ctx, authentication), validPolicyRequest())
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if !service.finalization.Valid() || service.finalization.Boundary() != "grpc_unary_return" {
		t.Fatalf("finalization = %#v, want gRPC unary boundary", service.finalization)
	}

	select {
	case <-service.finalization.Done():
		t.Fatal("handler opened the finalization gate before the outer unary boundary")
	default:
	}

	gate.Complete()

	select {
	case <-service.finalization.Done():
	default:
		t.Fatal("outer unary gate did not complete finalization")
	}
}

func policyRequestWithValue(value *policyv1.Value) *policyv1.DecisionRequest {
	return &policyv1.DecisionRequest{
		Version: "1",
		Target:  &policyv1.Target{Namespace: "mail", Action: "submit"},
		Attributes: map[string]*policyv1.Value{
			"value": value,
		},
	}
}

func validPolicyRequest() *policyv1.DecisionRequest {
	return policyRequestWithValue(&policyv1.Value{Kind: &policyv1.Value_String_{String_: "value"}})
}

type policyRecordingService struct {
	err           error
	transportKind string
}

func (s *policyRecordingService) Evaluate(context.Context, decision.Invocation) (decision.DecisionResponse, error) {
	return decision.DecisionResponse{}, s.err
}

// EvaluatePrepared runs the recording service through capture-first preparation.
func (s *policyRecordingService) EvaluatePrepared(
	ctx context.Context,
	transportKind string,
	prepare func(config.File) (decision.Invocation, error),
) (decision.DecisionResponse, error) {
	s.transportKind = transportKind
	if errors.Is(s.err, decisionservice.ErrDecisionRouteUnavailable) {
		return decision.DecisionResponse{}, s.err
	}

	invocation, err := prepare(enabledGRPCPolicyConfig())
	if err != nil {
		return decision.DecisionResponse{}, err
	}

	return s.Evaluate(ctx, invocation)
}

type policyFinalizationService struct {
	finalization decision.EvaluationFinalization
}

func (s *policyFinalizationService) Evaluate(_ context.Context, invocation decision.Invocation) (decision.DecisionResponse, error) {
	s.finalization = invocation.Finalization

	return decision.DecisionResponse{}, nil
}

// EvaluatePrepared captures finalization only after transport preparation has completed.
func (s *policyFinalizationService) EvaluatePrepared(
	ctx context.Context,
	_ string,
	prepare func(config.File) (decision.Invocation, error),
) (decision.DecisionResponse, error) {
	invocation, err := prepare(enabledGRPCPolicyConfig())
	if err != nil {
		return decision.DecisionResponse{}, err
	}

	return s.Evaluate(ctx, invocation)
}

// enabledGRPCPolicyConfig supplies generation-owned gRPC activation and wire bounds to adapter fixtures.
func enabledGRPCPolicyConfig() config.File {
	return &config.FileSettings{Policy: policyconfig.PolicyConfig{API: policyconfig.APIConfig{
		Enabled: true,
		GRPC:    policyconfig.GRPCConfig{Enabled: true},
		Limits:  policyconfig.APILimitsConfig{MaxRequestBytes: decision.MaximumOpaqueCredentialBytes},
	}}}
}
