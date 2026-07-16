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
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/testing/tracetest"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

const (
	requestOwnedTraceAttribute = "request_owned"
	requestOwnedTraceStatus    = "request-owned"
)

func TestNewAuthStateWithSetup_RestoresRequestParentContext(t *testing.T) {
	setupMinimalTestConfig(t)
	gin.SetMode(gin.TestMode)

	collector := tracetest.Setup(t)

	parentCtx, requestSpan := otel.Tracer("nauthilus/core/request_trace_scope_test").Start(context.Background(), "request.parent")
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/json",
		bytes.NewBufferString(`{"username":"user1","password":"secret"}`),
	).WithContext(parentCtx)
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set(definitions.CtxServiceKey, definitions.ServJSON)
	ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())

	state := NewAuthStateWithSetupWithDeps(ctx, setupAuthDeps())
	if state == nil {
		t.Fatal("NewAuthStateWithSetupWithDeps() returned nil")
	}

	auth := state.(*AuthState)
	requireRequestContextsSpanID(t, ctx, auth, requestSpan.SpanContext().SpanID())
	requestSpan.End()

	setupSpan := requireTraceSpan(t, collector.Spans(), "auth.setup")
	requireParentSpanID(t, setupSpan, requestSpan.SpanContext().SpanID())
}

func TestAuthApplicationServiceSetup_RestoresRequestParentContext(t *testing.T) {
	deps, _ := setupPhase4AuthApplicationServiceTest(t, "test(trace_setup)")
	collector := tracetest.Setup(t)
	service := NewAuthApplicationService(deps).(*authApplicationService)

	parentCtx, requestSpan := otel.Tracer("nauthilus/core/request_trace_scope_test").Start(context.Background(), "request.parent")

	auth, ginCtx, _, err := service.newAuthState(parentCtx, AuthInput{
		Service: definitions.ServGRPC,
		Mode:    AuthModeAuthenticate,
		Credentials: Credentials{
			Username: "user@example.test",
		},
		Context: AuthContext{
			Protocol: "imap",
		},
	})
	if err != nil {
		t.Fatalf("newAuthState() error = %v", err)
	}

	requireRequestContextsSpanID(t, ginCtx, auth, requestSpan.SpanContext().SpanID())
	requestSpan.End()

	setupSpan := requireTraceSpan(t, collector.Spans(), "auth.setup")
	requireParentSpanID(t, setupSpan, requestSpan.SpanContext().SpanID())
}

func TestScopeRequestContext_RestoresBothRequestObjectsInLIFOOrder(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/auth", http.NoBody)
	auth := NewAuthStateFromContextWithDeps(ctx, AuthDeps{}).(*AuthState)

	outerContext, outerSpan := otel.Tracer("nauthilus/core/request_trace_scope_test").Start(context.Background(), "outer")
	innerContext, innerSpan := otel.Tracer("nauthilus/core/request_trace_scope_test").Start(outerContext, "inner")

	outerScope := auth.scopeRequestContext(outerContext, ctx)
	innerScope := auth.scopeRequestContext(innerContext, ctx)
	requireRequestContextsSpanID(t, ctx, auth, innerSpan.SpanContext().SpanID())

	innerScope.Restore()
	requireRequestContextsSpanID(t, ctx, auth, outerSpan.SpanContext().SpanID())

	outerScope.Restore()

	if got := trace.SpanContextFromContext(ctx.Request.Context()); got.IsValid() {
		t.Fatalf("gin request context still carries span %s", got.SpanID())
	}

	if got := trace.SpanContextFromContext(auth.Request.HTTPClientRequest.Context()); got.IsValid() {
		t.Fatalf("auth request context still carries span %s", got.SpanID())
	}

	newerScope := auth.scopeRequestContext(innerContext, ctx)

	outerScope.Restore()
	requireRequestContextsSpanID(t, ctx, auth, innerSpan.SpanContext().SpanID())
	newerScope.Restore()

	innerSpan.End()
	outerSpan.End()
}

type requestOwnedTraceObservation struct {
	auth         *AuthState
	requestCtx   context.Context
	authStateCtx context.Context
}

type requestOwnedTracePasswordVerifier struct {
	observations chan requestOwnedTraceObservation
}

// Verify records the direct request carrier and waits for that request's cancellation.
func (v requestOwnedTracePasswordVerifier) Verify(ctx *gin.Context, auth *AuthState, _ []*PassDBMap) (*PassDBResult, error) {
	auth.Runtime.StatusMessage = requestOwnedTraceStatus
	auth.ReplaceAllAttributes(map[string][]any{requestOwnedTraceAttribute: {"value"}})

	v.observations <- requestOwnedTraceObservation{
		auth:         auth,
		requestCtx:   ctx.Request.Context(),
		authStateCtx: auth.Ctx(),
	}

	<-ctx.Request.Context().Done()

	return nil, ctx.Request.Context().Err()
}

// installRequestOwnedTracePasswordVerifier installs a verifier controlled by the context-restoration test.
func installRequestOwnedTracePasswordVerifier(t *testing.T) requestOwnedTracePasswordVerifier {
	t.Helper()

	verifier := requestOwnedTracePasswordVerifier{
		observations: make(chan requestOwnedTraceObservation, 1),
	}
	previousVerifier := getPasswordVerifier()

	RegisterPasswordVerifier(verifier)
	t.Cleanup(func() {
		RegisterPasswordVerifier(previousVerifier)
	})

	return verifier
}

// awaitRequestOwnedTraceObservation waits for the verifier to capture its scoped request contexts.
func awaitRequestOwnedTraceObservation(deadline context.Context, t *testing.T, observations <-chan requestOwnedTraceObservation) requestOwnedTraceObservation {
	t.Helper()

	select {
	case observation := <-observations:
		return observation
	case <-deadline.Done():
		t.Fatalf("timed out waiting for verifier observation: %v", deadline.Err())

		return requestOwnedTraceObservation{}
	}
}

// requireRequestOwnedTrace verifies state identity and matching request child contexts.
func requireRequestOwnedTrace(t *testing.T, auth *AuthState, requestSpan trace.Span, observation requestOwnedTraceObservation) {
	t.Helper()

	if observation.auth != auth {
		t.Fatal("verifier did not receive the request-owned AuthState")
	}

	requestVerifySpan := trace.SpanContextFromContext(observation.requestCtx)
	authStateVerifySpan := trace.SpanContextFromContext(observation.authStateCtx)

	if !requestVerifySpan.IsValid() || requestVerifySpan.TraceID() != requestSpan.SpanContext().TraceID() {
		t.Fatalf("verifier request trace = %s, want trace %s", requestVerifySpan.TraceID(), requestSpan.SpanContext().TraceID())
	}

	if authStateVerifySpan.TraceID() != requestVerifySpan.TraceID() || authStateVerifySpan.SpanID() != requestVerifySpan.SpanID() {
		t.Fatalf("AuthState verify span = %s, want request verify span %s", authStateVerifySpan.SpanID(), requestVerifySpan.SpanID())
	}

	if observation.requestCtx.Done() != observation.authStateCtx.Done() {
		t.Fatal("verifier request and AuthState contexts do not share cancellation ownership")
	}
}

// requireRequestOwnedTraceMutation verifies direct verifier changes remain on the owning AuthState.
func requireRequestOwnedTraceMutation(t *testing.T, auth *AuthState) {
	t.Helper()

	if auth.Runtime.StatusMessage != requestOwnedTraceStatus {
		t.Fatalf("request-owned runtime mutation = %q, want %q", auth.Runtime.StatusMessage, requestOwnedTraceStatus)
	}

	if _, exists := auth.GetAttribute(requestOwnedTraceAttribute); !exists {
		t.Fatal("request-owned attribute mutation was not applied")
	}
}

// awaitRequestOwnedCancellation waits for direct verification to observe request cancellation.
func awaitRequestOwnedCancellation(deadline context.Context, t *testing.T, result <-chan error) {
	t.Helper()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("processVerifyPassword() error = %v, want context canceled", err)
		}
	case <-deadline.Done():
		t.Fatalf("timed out waiting for cancellation result: %v", deadline.Err())
	}
}

// requireRestoredCanceledRequestContexts verifies both request holders were restored after verification.
func requireRestoredCanceledRequestContexts(t *testing.T, ctx *gin.Context, auth *AuthState, requestSpan trace.Span) {
	t.Helper()

	requireRequestContextsSpanID(t, ctx, auth, requestSpan.SpanContext().SpanID())

	if !errors.Is(ctx.Request.Context().Err(), context.Canceled) {
		t.Fatalf("restored Gin request error = %v, want context canceled", ctx.Request.Context().Err())
	}

	if !errors.Is(auth.Request.HTTPClientRequest.Context().Err(), context.Canceled) {
		t.Fatalf("restored auth request error = %v, want context canceled", auth.Request.HTTPClientRequest.Context().Err())
	}
}

func TestProcessVerifyPassword_UsesRequestOwnedStateAndRestoresContext(t *testing.T) {
	auth, ctx, _ := newTraceParentedEnvironmentAuth(t)
	requestSpan := attachRequestParentSpan(t, ctx, auth)
	requestCtx, cancelRequest := context.WithCancel(ctx.Request.Context())
	t.Cleanup(cancelRequest)

	ctx.Request = ctx.Request.WithContext(requestCtx)
	auth.Request.HTTPClientRequest = auth.Request.HTTPClientRequest.WithContext(requestCtx)

	verifier := installRequestOwnedTracePasswordVerifier(t)
	waitContext, cancelWait := context.WithTimeout(context.Background(), time.Second)

	defer cancelWait()

	result := make(chan error, 1)

	go func() {
		_, err := auth.processVerifyPassword(ctx, []*PassDBMap{{backend: definitions.BackendLDAP}})
		result <- err
	}()

	observation := awaitRequestOwnedTraceObservation(waitContext, t, verifier.observations)
	requireRequestOwnedTrace(t, auth, requestSpan, observation)
	requireRequestOwnedTraceMutation(t, auth)

	cancelRequest()
	awaitRequestOwnedCancellation(waitContext, t, result)
	requireRestoredCanceledRequestContexts(t, ctx, auth, requestSpan)

	requestSpan.End()
}
