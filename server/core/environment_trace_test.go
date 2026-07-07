package core

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/policy"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
	"github.com/croessner/nauthilus/v3/server/testing/tracetest"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

func TestHandleEnvironment_EnvironmentControlsShareEvaluationParentSpan(t *testing.T) {
	auth, ctx, collector := newTraceParentedEnvironmentAuth(t)
	requestSpan := attachRequestParentSpan(t, ctx, auth)

	result := auth.HandleEnvironment(ctx)

	requestSpan.End()

	if result != definitions.AuthResultOK {
		t.Fatalf("HandleEnvironment() = %v, want %v", result, definitions.AuthResultOK)
	}

	spans := collector.Spans()
	environmentSpan := requireTraceSpan(t, spans, "environment.evaluate")
	tlsSpan := requireTraceSpan(t, spans, "auth.environment.tls")
	relaySpan := requireTraceSpan(t, spans, "auth.environment.relay_domains")
	rblSpan := requireTraceSpan(t, spans, "auth.environment.rbl")

	requireParentSpanID(t, environmentSpan, requestSpan.SpanContext().SpanID())
	requireParentSpanID(t, tlsSpan, environmentSpan.SpanContext().SpanID())
	requireParentSpanID(t, relaySpan, environmentSpan.SpanContext().SpanID())
	requireParentSpanID(t, rblSpan, environmentSpan.SpanContext().SpanID())
	requireNoEnvironmentControlParent(t, relaySpan, tlsSpan, rblSpan)
	requireNoEnvironmentControlParent(t, rblSpan, tlsSpan, relaySpan)
}

func TestHandleEnvironment_PolicyCheckRemainsChildOfEnvironmentControl(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlTLSEncryption)
	cfg.ClearTextList = nil

	activateTracePolicySnapshotForTest(t)

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	collector := tracetest.Setup(t)
	requestSpan := attachRequestParentSpan(t, ctx, auth)

	result := auth.HandleEnvironment(ctx)

	requestSpan.End()

	if result != definitions.AuthResultPreAuthTLS {
		t.Fatalf("HandleEnvironment() = %v, want %v", result, definitions.AuthResultPreAuthTLS)
	}

	spans := collector.Spans()
	tlsSpan := requireTraceSpan(t, spans, "auth.environment.tls")
	policySpan := requireTraceSpanWithAttributes(
		t,
		spans,
		"policy.check",
		attribute.String("policy.check", definitions.ControlTLSEncryption),
	)

	requireParentSpanID(t, policySpan, tlsSpan.SpanContext().SpanID())
}

func TestHandleEnvironment_RBLLookupRemainsChildOfRBLEnvironment(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlRBL)
	cfg.RBLs = &config.RBLSection{Threshold: 5}

	activateTracePolicySnapshotForTest(t)

	previous := GetRBLService()

	RegisterRBLService(currentBehaviorRBLService{score: 0, threshold: 5})
	t.Cleanup(func() {
		RegisterRBLService(previous)
	})

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	collector := tracetest.Setup(t)
	requestSpan := attachRequestParentSpan(t, ctx, auth)

	result := auth.HandleEnvironment(ctx)

	requestSpan.End()

	if result != definitions.AuthResultOK {
		t.Fatalf("HandleEnvironment() = %v, want %v", result, definitions.AuthResultOK)
	}

	spans := collector.Spans()
	rblSpan := requireTraceSpan(t, spans, "auth.environment.rbl")
	lookupSpan := requireTraceSpan(t, spans, "rbl.lookup")

	requireParentSpanID(t, lookupSpan, rblSpan.SpanContext().SpanID())
	requireRequestContextsSpanID(t, ctx, auth, requestSpan.SpanContext().SpanID())
}

func TestHandleEnvironment_RestoresRequestContextAfterEnvironmentEvaluation(t *testing.T) {
	auth, ctx, _ := newTraceParentedEnvironmentAuth(t)

	requestSpan := attachRequestParentSpan(t, ctx, auth)
	defer requestSpan.End()

	result := auth.HandleEnvironment(ctx)
	if result != definitions.AuthResultOK {
		t.Fatalf("HandleEnvironment() = %v, want %v", result, definitions.AuthResultOK)
	}

	requireRequestContextsSpanID(t, ctx, auth, requestSpan.SpanContext().SpanID())
}

func TestHandleEnvironment_RestoresRequestContextAfterEarlyEnvironmentReturn(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlTLSEncryption)
	cfg.ClearTextList = nil

	activateTracePolicySnapshotForTest(t)

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	_ = tracetest.Setup(t)

	requestSpan := attachRequestParentSpan(t, ctx, auth)
	defer requestSpan.End()

	result := auth.HandleEnvironment(ctx)
	if result != definitions.AuthResultPreAuthTLS {
		t.Fatalf("HandleEnvironment() = %v, want %v", result, definitions.AuthResultPreAuthTLS)
	}

	requireRequestContextsSpanID(t, ctx, auth, requestSpan.SpanContext().SpanID())
}

func TestAuthenticate_DoesNotInheritLastEnvironmentControlSpan(t *testing.T) {
	auth, ctx, collector := newTraceParentedEnvironmentAuth(t)
	requestSpan := attachRequestParentSpan(t, ctx, auth)

	environmentResult := auth.HandleEnvironment(ctx)
	if environmentResult != definitions.AuthResultOK {
		t.Fatalf("HandleEnvironment() = %v, want %v", environmentResult, definitions.AuthResultOK)
	}

	restore := replaceBackendPlanTestServices(
		t,
		backendPlanPasswordVerifier{},
		nil,
		nil,
		backendPlanSubject{result: definitions.AuthResultOK},
		currentBehaviorPostAction{},
	)
	defer restore()

	auth.authenticateUser(ctx, backendExecutionPlan{
		positions: map[definitions.Backend]int{definitions.BackendLDAP: 0},
		passDBs:   []*PassDBMap{{backend: definitions.BackendLDAP}},
	})
	requireRequestContextsSpanID(t, ctx, auth, requestSpan.SpanContext().SpanID())
	requestSpan.End()

	spans := collector.Spans()
	rblSpan := requireTraceSpan(t, spans, "auth.environment.rbl")
	authSpan := requireTraceSpan(t, spans, "auth.authenticate")
	verifySpan := requireTraceSpan(t, spans, "auth.verify")

	if got, stale := authSpan.Parent().SpanID(), rblSpan.SpanContext().SpanID(); got == stale {
		t.Fatalf("%s parent = %s, must not inherit stale %s span %s", authSpan.Name(), got, rblSpan.Name(), stale)
	}

	requireParentSpanID(t, authSpan, requestSpan.SpanContext().SpanID())
	requireParentSpanID(t, verifySpan, authSpan.SpanContext().SpanID())
}

// newTraceParentedEnvironmentAuth creates a deterministic auth state whose environment controls do not reject.
func newTraceParentedEnvironmentAuth(t *testing.T) (*AuthState, *gin.Context, *tracetest.Collector) {
	t.Helper()

	cfg := newCurrentBehaviorConfig(
		t,
		definitions.ControlTLSEncryption,
		definitions.ControlRelayDomains,
		definitions.ControlRBL,
	)
	cfg.RelayDomains = &config.RelayDomainsSection{
		StaticDomains: []string{"example.test"},
	}

	activateTracePolicySnapshotForTest(t)

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.XSSL = "TLSv1.3"
	auth.AccountCache().Set(cfg, auth.Request.Username, auth.Request.Protocol.Get(), "", auth.Request.Username)

	return auth, ctx, tracetest.Setup(t)
}

// activateTracePolicySnapshotForTest installs a minimal snapshot so policy.check spans are recorded.
func activateTracePolicySnapshotForTest(t *testing.T) {
	t.Helper()

	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation:    1,
		Mode:          "enforce",
		DefaultPolicy: policy.BuiltinDefaultSet,
	})
}

// attachRequestParentSpan installs an explicit request parent span on both request holders.
func attachRequestParentSpan(t *testing.T, ctx *gin.Context, auth *AuthState) trace.Span {
	t.Helper()

	parentCtx, requestSpan := otel.Tracer("nauthilus/core/environment_trace_test").Start(context.Background(), "request.parent")

	ctx.Request = ctx.Request.WithContext(parentCtx)
	if auth.Request.HTTPClientRequest != nil {
		auth.Request.HTTPClientRequest = auth.Request.HTTPClientRequest.WithContext(parentCtx)
	}

	return requestSpan
}

// requireTraceSpan returns the first exported span with the requested name.
func requireTraceSpan(t *testing.T, spans []sdktrace.ReadOnlySpan, name string) sdktrace.ReadOnlySpan {
	t.Helper()

	for _, span := range spans {
		if span.Name() == name {
			return span
		}
	}

	t.Fatalf("missing span %q; exported spans: %v", name, traceSpanNames(spans))

	return nil
}

// requireTraceSpanWithAttributes returns the first exported span matching a name and attributes.
func requireTraceSpanWithAttributes(
	t *testing.T,
	spans []sdktrace.ReadOnlySpan,
	name string,
	attrs ...attribute.KeyValue,
) sdktrace.ReadOnlySpan {
	t.Helper()

	span, ok := tracetest.FindByNameAndAttributes(spans, name, attrs...)
	if !ok {
		t.Fatalf("missing span %q with attributes %v; exported spans: %v", name, attrs, traceSpanNames(spans))
	}

	return span
}

// requireParentSpanID compares a child span parent directly with the expected parent span ID.
func requireParentSpanID(t *testing.T, child sdktrace.ReadOnlySpan, parentID trace.SpanID) {
	t.Helper()

	if got := child.Parent().SpanID(); got != parentID {
		t.Fatalf("%s parent = %s, want %s", child.Name(), got, parentID)
	}
}

// requireRequestContextsSpanID verifies both request holders restored the expected active span context.
func requireRequestContextsSpanID(t *testing.T, ctx *gin.Context, auth *AuthState, parentID trace.SpanID) {
	t.Helper()

	if got := trace.SpanContextFromContext(ctx.Request.Context()).SpanID(); got != parentID {
		t.Fatalf("gin request context span = %s, want %s", got, parentID)
	}

	if auth.Request.HTTPClientRequest != nil {
		if got := trace.SpanContextFromContext(auth.Request.HTTPClientRequest.Context()).SpanID(); got != parentID {
			t.Fatalf("http client request context span = %s, want %s", got, parentID)
		}
	}
}

// requireNoEnvironmentControlParent rejects accidental parentage between sequential environment controls.
func requireNoEnvironmentControlParent(t *testing.T, child sdktrace.ReadOnlySpan, controls ...sdktrace.ReadOnlySpan) {
	t.Helper()

	childParent := child.Parent().SpanID()
	for _, control := range controls {
		if childParent == control.SpanContext().SpanID() {
			t.Fatalf("%s parent = %s, must not be environment control %s", child.Name(), childParent, control.Name())
		}
	}
}

// traceSpanNames formats exported span names for failure diagnostics.
func traceSpanNames(spans []sdktrace.ReadOnlySpan) []string {
	names := make([]string, 0, len(spans))
	for _, span := range spans {
		names = append(names, span.Name())
	}

	return names
}
