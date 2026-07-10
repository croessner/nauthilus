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
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/testing/oteltest"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestPostActionResponseCompletionMiddlewareReleasesAfterInnerReturn(t *testing.T) {
	gin.SetMode(gin.TestMode)

	engine := gin.New()
	innerReturned := atomic.Bool{}
	releasedAfterInnerReturn := make(chan bool, 1)

	engine.Use(postActionResponseCompletionMiddleware())
	engine.Use(func(ctx *gin.Context) {
		defer innerReturned.Store(true)

		ctx.Next()
	})
	engine.GET("/auth", func(ctx *gin.Context) {
		executionDone := PostActionExecutionDone(ctx)
		go func() {
			<-executionDone

			releasedAfterInnerReturn <- innerReturned.Load()
		}()

		ctx.Status(http.StatusNoContent)
	})

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/auth", http.NoBody)
	engine.ServeHTTP(response, request)

	select {
	case releasedAfterInner := <-releasedAfterInnerReturn:
		if !releasedAfterInner {
			t.Fatal("post-action gate released before inner middleware returned")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("post-action gate was not released")
	}

	if response.Code != http.StatusNoContent {
		t.Fatalf("response status = %d, want %d", response.Code, http.StatusNoContent)
	}
}

func TestPostActionExecutionGateCompleteIsIdempotent(t *testing.T) {
	gate := NewPostActionExecutionGate()

	gate.Complete()
	gate.Complete()

	select {
	case <-gate.Done():
	default:
		t.Fatal("completed gate remained open")
	}
}

func TestPostActionResponseCompletionMiddlewareDoesNotCommitOnPanic(t *testing.T) {
	gin.SetMode(gin.TestMode)

	engine := gin.New()
	engine.Use(postActionResponseCompletionMiddleware())
	engine.GET("/panic", func(*gin.Context) {
		panic("boom")
	})

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/panic", http.NoBody)

	defer func() {
		if recover() == nil {
			t.Fatal("ServeHTTP() did not propagate panic")
		}

		if response.Code != http.StatusOK || response.Flushed {
			t.Fatalf("panic response was committed: code=%d flushed=%t", response.Code, response.Flushed)
		}
	}()

	engine.ServeHTTP(response, request)
}

func TestPostActionGateReleasesAfterOTelGinServerSpanEnds(t *testing.T) {
	gin.SetMode(gin.TestMode)

	collector := oteltest.Setup(t)
	engine := gin.New()
	asyncDone := make(chan struct{}, 1)

	engine.Use(postActionResponseCompletionMiddleware())
	engine.Use(otelgin.Middleware("nauthilus-test"))
	engine.GET("/auth", func(ctx *gin.Context) {
		executionDone := PostActionExecutionDone(ctx)
		parent := context.WithoutCancel(ctx.Request.Context())

		go func() {
			<-executionDone

			_, span := otel.Tracer("nauthilus/core/post_action_gate_test").Start(parent, "async.post_action")
			span.End()

			asyncDone <- struct{}{}
		}()

		ctx.Status(http.StatusNoContent)
	})

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/auth", http.NoBody)
	engine.ServeHTTP(response, request)

	select {
	case <-asyncDone:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("asynchronous post-action span was not recorded")
	}

	serverSpan := findReadOnlySpan(t, collector.Spans(), "GET /auth")
	asyncSpan := findReadOnlySpan(t, collector.Spans(), "async.post_action")

	if asyncSpan.StartTime().Before(serverSpan.EndTime()) {
		t.Fatalf("async span started at %s before server span ended at %s", asyncSpan.StartTime(), serverSpan.EndTime())
	}

	if asyncSpan.Parent().SpanID() != serverSpan.SpanContext().SpanID() {
		t.Fatalf("async parent = %s, want server span %s", asyncSpan.Parent().SpanID(), serverSpan.SpanContext().SpanID())
	}

	if response.Code != http.StatusNoContent {
		t.Fatalf("response status = %d, want %d", response.Code, http.StatusNoContent)
	}
}

// findReadOnlySpan returns the completed span with name.
func findReadOnlySpan(t *testing.T, spans []sdktrace.ReadOnlySpan, name string) sdktrace.ReadOnlySpan {
	t.Helper()

	for _, span := range spans {
		if span.Name() == name {
			return span
		}
	}

	t.Fatalf("missing span %q", name)

	return nil
}
