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
	"sync"

	"github.com/croessner/nauthilus/v3/server/svcctx"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/trace"
)

const postActionExecutionGateKey = "nauthilus.post_action.execution_gate"

type postActionExecutionGateContextKey struct{}

// PostActionExecutionGate releases detached post-actions after the response boundary completes.
type PostActionExecutionGate struct {
	done chan struct{}
	once sync.Once
}

// NewPostActionExecutionGate creates a closed-once execution gate.
func NewPostActionExecutionGate() *PostActionExecutionGate {
	return &PostActionExecutionGate{done: make(chan struct{})}
}

// Done returns the channel closed when detached post-actions may begin.
func (g *PostActionExecutionGate) Done() <-chan struct{} {
	if g == nil {
		return nil
	}

	return g.done
}

// Complete releases every post-action waiting on the response boundary.
func (g *PostActionExecutionGate) Complete() {
	if g == nil {
		return
	}

	g.once.Do(func() {
		close(g.done)
	})
}

// InstallPostActionExecutionGate attaches a fresh execution gate to a Gin request.
func InstallPostActionExecutionGate(ctx *gin.Context) *PostActionExecutionGate {
	gate := NewPostActionExecutionGate()
	if ctx != nil {
		ctx.Set(postActionExecutionGateKey, gate)
	}

	return gate
}

// ContextWithPostActionExecutionGate installs a gate on a standard request context.
func ContextWithPostActionExecutionGate(ctx context.Context) (context.Context, *PostActionExecutionGate) {
	if ctx == nil {
		ctx = context.Background()
	}

	gate := NewPostActionExecutionGate()

	return context.WithValue(ctx, postActionExecutionGateContextKey{}, gate), gate
}

// PostActionExecutionDoneFromContext returns a standard-context response gate.
func PostActionExecutionDoneFromContext(ctx context.Context) <-chan struct{} {
	if ctx == nil {
		return nil
	}

	gate, _ := ctx.Value(postActionExecutionGateContextKey{}).(*PostActionExecutionGate)
	if gate == nil {
		return nil
	}

	return gate.Done()
}

// AttachPostActionExecutionGate copies a standard-context gate into a Gin request.
func AttachPostActionExecutionGate(parent context.Context, ctx *gin.Context) {
	if ctx == nil || parent == nil {
		return
	}

	gate, _ := parent.Value(postActionExecutionGateContextKey{}).(*PostActionExecutionGate)
	if gate != nil {
		ctx.Set(postActionExecutionGateKey, gate)
	}
}

// PostActionExecutionDone returns the response-completion channel attached to ctx.
func PostActionExecutionDone(ctx *gin.Context) <-chan struct{} {
	if ctx == nil {
		return nil
	}

	value, exists := ctx.Get(postActionExecutionGateKey)
	if !exists {
		return nil
	}

	gate, ok := value.(*PostActionExecutionGate)
	if !ok || gate == nil {
		return nil
	}

	return gate.Done()
}

// CompletePostActionResponse releases the gate attached to ctx when one exists.
func CompletePostActionResponse(ctx *gin.Context) {
	if ctx == nil {
		return
	}

	value, exists := ctx.Get(postActionExecutionGateKey)
	if !exists {
		return
	}

	if gate, ok := value.(*PostActionExecutionGate); ok {
		gate.Complete()
	}
}

// WaitForPostActionExecution waits for response completion or worker cancellation.
func WaitForPostActionExecution(ctx context.Context, executionDone <-chan struct{}) error {
	if executionDone == nil {
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	select {
	case <-executionDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// DetachedPostActionContext keeps trace identity while using service-lifetime cancellation.
func DetachedPostActionContext(requestContext context.Context) context.Context {
	base := svcctx.Get()

	spanContext := trace.SpanContextFromContext(requestContext)
	if !spanContext.IsValid() {
		return base
	}

	return trace.ContextWithSpanContext(base, spanContext)
}

// postActionResponseCompletionMiddleware releases post-actions after inner middleware has returned.
func postActionResponseCompletionMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		gate := InstallPostActionExecutionGate(ctx)

		defer func() {
			recovered := recover()
			if recovered == nil {
				ctx.Writer.WriteHeaderNow()
			}

			gate.Complete()

			if recovered != nil {
				panic(recovered)
			}
		}()

		ctx.Next()
	}
}
