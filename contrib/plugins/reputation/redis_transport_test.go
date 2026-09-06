//go:build reputation_integration

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	policyv1 "github.com/croessner/nauthilus/v4/api/policy/v1"
	"github.com/croessner/nauthilus/v4/server/handler/policygrpc"
	"github.com/croessner/nauthilus/v4/server/handler/policyhttp"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
	"github.com/gin-gonic/gin"
	"google.golang.org/protobuf/encoding/protojson"
)

// transportObservation builds both wire representations from one canonical independent observation.
func transportObservation(now time.Time, extra string, protobuf bool) map[string]any {
	fields := []any{}
	for _, field := range []struct{ name, value string }{{"role", "smtp_peer"}, {"kind", "ip"}, {"value", "192.0.2.8"}} {
		fields = append(fields, map[string]any{"name": field.name, "value": map[string]any{"string": field.value}})
	}

	var records any = []any{map[string]any{"fields": fields}}
	if protobuf {
		records = map[string]any{"records": records}
	}

	attributes := map[string]any{
		"reputation.event_id":    map[string]any{"string": "transport-event"},
		"reputation.observed_at": map[string]any{"timestamp": now.Format(time.RFC3339Nano)},
		"reputation.signal":      map[string]any{"string": "scan.clean"},
		"reputation.subjects":    map[string]any{"records": records},
	}
	if extra != "" {
		attributes["reputation."+extra] = map[string]any{"string": "forged"}
	}

	return map[string]any{"version": "1", "target": map[string]any{"namespace": "reputation", "action": "observe"}, "resource": map[string]any{"attributes": attributes}}
}

// TestReputationObserveHTTPAndGRPCShareAdmissionAndIdempotency drives the real unary adapters and synchronous Redis effect.
func TestReputationObserveHTTPAndGRPCShareAdmissionAndIdempotency(t *testing.T) {
	service, plugin := newReputationTransportService(t)
	counter := &learningTestCounter{}
	plugin.learningCounter = counter
	engine, grpcHandler := reputationTransportHandlers(service)

	now := time.Now().UTC()
	for _, extra := range []string{"", "causality", "independent", "policy_influenced", "evidence_origin"} {
		assertObservationHTTP(t, engine, now, extra)
		assertObservationGRPC(t, grpcHandler, now, extra)
	}

	assertLearningResults(t, counter, "applied", "duplicate")
}

// assertObservationHTTP checks the actual JSON adapter with verified transport evidence and real caller authentication.
func assertObservationHTTP(t *testing.T, engine *gin.Engine, now time.Time, extra string) {
	t.Helper()

	body, err := json.Marshal(transportObservation(now, extra, false))
	requireNoError(t, err)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/policy/decisions", strings.NewReader(string(body)))
	request.TLS = &tls.ConnectionState{}
	request.SetBasicAuth("ScanWriter", transportTestPassword)
	request.Header.Set("Content-Type", "application/json")

	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)

	permitted := response.Code == http.StatusOK && strings.Contains(response.Body.String(), `"effect":"permit"`)
	if permitted != (extra == "") {
		t.Fatalf("HTTP observation: %d %s", response.Code, response.Body.String())
	}
}

// assertObservationGRPC checks the same observation through the actual protobuf adapter and shared admission authority.
func assertObservationGRPC(t *testing.T, handler *policygrpc.Handler, now time.Time, extra string) {
	t.Helper()

	body, err := json.Marshal(transportObservation(now, extra, true))
	requireNoError(t, err)

	request := &policyv1.DecisionRequest{}
	requireNoError(t, protojson.Unmarshal(body, request))
	reply, err := handler.Evaluate(t.Context(), request)

	permitted := err == nil && reply.GetEffect() == policyv1.Effect_EFFECT_PERMIT
	if permitted != (extra == "") {
		t.Fatalf("gRPC observation: %s %v", reply.GetEffect(), err)
	}
}

// reputationTransportHandlers constructs both actual unary adapters with isolated authenticated transport evidence.
func reputationTransportHandlers(service *decisionservice.DecisionService) (*gin.Engine, *policygrpc.Handler) {
	engine := gin.New()
	policyhttp.New(service, policyhttp.DirectTLSTransportEvidence{}).Register(engine.Group("/api/v1"))
	grpcHandler := policygrpc.New(service, func(context.Context) (decision.AuthenticationInput, error) {
		return decision.NewAuthenticationInput(decision.AuthenticationEvidence{Kind: "basic", Credential: []byte("ScanWriter:" + transportTestPassword), TransportKind: "grpc", Protected: true})
	})

	return engine, grpcHandler
}
