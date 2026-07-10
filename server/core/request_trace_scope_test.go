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

type blockingTracePasswordVerifier struct {
	started chan struct{}
	release chan struct{}
	worker  chan *AuthState
	done    chan struct{}
}

// Verify blocks until the test releases the shared singleflight callback.
func (v blockingTracePasswordVerifier) Verify(_ *gin.Context, auth *AuthState, _ []*PassDBMap) (*PassDBResult, error) {
	v.worker <- auth

	close(v.started)
	<-v.release

	auth.Runtime.StatusMessage = "worker-only"
	auth.ReplaceAllAttributes(map[string][]any{"worker": {"value"}})
	close(v.done)

	return nil, context.Canceled
}

// installBlockingTracePasswordVerifier installs a verifier controlled by the cancellation test.
func installBlockingTracePasswordVerifier(t *testing.T) blockingTracePasswordVerifier {
	t.Helper()

	verifier := blockingTracePasswordVerifier{
		started: make(chan struct{}),
		release: make(chan struct{}),
		worker:  make(chan *AuthState, 1),
		done:    make(chan struct{}),
	}
	previousVerifier := getPasswordVerifier()

	RegisterPasswordVerifier(verifier)
	t.Cleanup(func() {
		RegisterPasswordVerifier(previousVerifier)
	})

	return verifier
}

func TestProcessVerifyPassword_CancellationReturnsWithoutSharedRequestPointerMutation(t *testing.T) {
	auth, ctx, _ := newTraceParentedEnvironmentAuth(t)
	requestSpan := attachRequestParentSpan(t, ctx, auth)
	requestCtx, cancelRequest := context.WithCancel(ctx.Request.Context())
	ctx.Request = ctx.Request.WithContext(requestCtx)
	auth.Request.HTTPClientRequest = auth.Request.HTTPClientRequest.WithContext(requestCtx)

	verifier := installBlockingTracePasswordVerifier(t)

	result := make(chan error, 1)

	go func() {
		_, err := auth.processVerifyPassword(ctx, []*PassDBMap{{backend: definitions.BackendLDAP}})
		result <- err
	}()

	<-verifier.started

	workerAuth := <-verifier.worker
	if workerAuth == auth {
		close(verifier.release)
		t.Fatal("singleflight verifier received request-owned AuthState")
	}

	cancelRequest()

	workerSpanContext := trace.SpanContextFromContext(workerAuth.Ctx())
	if !workerSpanContext.IsValid() || workerSpanContext.TraceID() != requestSpan.SpanContext().TraceID() {
		close(verifier.release)
		t.Fatalf("worker trace context = %s, want trace %s", workerSpanContext.TraceID(), requestSpan.SpanContext().TraceID())
	}

	if !errors.Is(workerAuth.Ctx().Err(), context.Canceled) {
		close(verifier.release)
		t.Fatalf("worker context error = %v, want context canceled", workerAuth.Ctx().Err())
	}

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			close(verifier.release)
			t.Fatalf("processVerifyPassword() error = %v, want context canceled", err)
		}
	case <-time.After(250 * time.Millisecond):
		close(verifier.release)
		t.Fatal("processVerifyPassword() did not return promptly after cancellation")
	}

	requireRequestContextsSpanID(t, ctx, auth, requestSpan.SpanContext().SpanID())
	close(verifier.release)
	<-verifier.done

	if auth.Runtime.StatusMessage == "worker-only" {
		t.Fatal("detached verifier mutated request-owned runtime")
	}

	if _, exists := auth.GetAttribute("worker"); exists {
		t.Fatal("detached verifier mutated request-owned attributes")
	}

	requestSpan.End()
}
