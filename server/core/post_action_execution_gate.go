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

	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/svcctx"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/trace"
)

const postActionExecutionGateKey = "nauthilus.post_action.execution_gate"

type postActionExecutionGateContextKey struct{}

// PostActionExecutionGate is the typed internal application-response finalization gate.
type PostActionExecutionGate = effectsupervisor.Gate

// NewPostActionExecutionGate creates an HTTP commit execution gate.
func NewPostActionExecutionGate() *PostActionExecutionGate {
	gate, err := effectsupervisor.NewGate(effectsupervisor.BoundaryHTTPCommit)
	if err != nil {
		panic(err)
	}

	return gate
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
	return contextWithPostActionExecutionBoundary(ctx, effectsupervisor.BoundaryGRPCUnaryReturn)
}

// ContextWithHTTPPostActionExecutionGate installs a transport-owned HTTP commit gate.
func ContextWithHTTPPostActionExecutionGate(ctx context.Context) (context.Context, *PostActionExecutionGate) {
	return contextWithPostActionExecutionBoundary(ctx, effectsupervisor.BoundaryHTTPCommit)
}

// contextWithPostActionExecutionBoundary installs one transport-selected standard-context gate.
func contextWithPostActionExecutionBoundary(
	ctx context.Context,
	boundary effectsupervisor.Boundary,
) (context.Context, *PostActionExecutionGate) {
	if ctx == nil {
		ctx = context.Background()
	}

	gate, err := effectsupervisor.NewGate(boundary)
	if err != nil {
		panic(err)
	}

	return contextWithPostActionExecutionGate(ctx, gate), gate
}

// contextWithPostActionExecutionGate attaches one already transport-owned gate.
func contextWithPostActionExecutionGate(
	ctx context.Context,
	gate *PostActionExecutionGate,
) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}

	if gate == nil {
		return ctx
	}

	return context.WithValue(ctx, postActionExecutionGateContextKey{}, gate)
}

// PostActionFinalizationGateFromContext returns a typed standard-context response gate.
func PostActionFinalizationGateFromContext(ctx context.Context) effectsupervisor.FinalizationGate {
	if ctx == nil {
		return nil
	}

	gate, _ := ctx.Value(postActionExecutionGateContextKey{}).(*PostActionExecutionGate)

	return gate
}

// PostActionExecutionDoneFromContext returns a standard-context response gate.
func PostActionExecutionDoneFromContext(ctx context.Context) <-chan struct{} {
	if ctx == nil {
		return nil
	}

	gate := PostActionFinalizationGateFromContext(ctx)
	if gate == nil {
		return nil
	}

	return gate.Done()
}

// PostActionFinalizationGate returns the typed response gate attached to ctx.
func PostActionFinalizationGate(ctx *gin.Context) effectsupervisor.FinalizationGate {
	if ctx == nil {
		return nil
	}

	value, exists := ctx.Get(postActionExecutionGateKey)
	if !exists {
		return nil
	}

	gate, _ := value.(*PostActionExecutionGate)

	return gate
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

// PostActionExecutionDone returns the response-finalization channel attached to ctx.
func PostActionExecutionDone(ctx *gin.Context) <-chan struct{} {
	if ctx == nil {
		return nil
	}

	gate := PostActionFinalizationGate(ctx)
	if gate == nil {
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
		ctx.Request = ctx.Request.WithContext(contextWithPostActionExecutionGate(ctx.Request.Context(), gate))

		defer func() {
			recovered := recover()
			if recovered == nil {
				ctx.Writer.WriteHeaderNow()
				gate.Complete()
			}

			if recovered != nil {
				panic(recovered)
			}
		}()

		ctx.Next()
	}
}
