package trace

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Tracer is a narrow facade over OpenTelemetry's trace.Tracer to keep
// instrumentation usage simple and testable across the codebase.
//
// Usage:
//
//	tr := trace.New("nauthilus/ldap")
//	ctx, sp := tr.Start(ctx, "ldap.search", attribute.String("bucket", bucket))
//	defer sp.End()
//
// In tests, this interface can be replaced with a lightweight fake if needed.
type Tracer interface {
	Start(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span)
}

type tracer struct {
	t trace.Tracer
}

// New creates a new Tracer tied to the given instrumentation scope.
func New(scope string) Tracer {
	return &tracer{t: otel.Tracer(scope)}
}

// Start begins a span with the provided name and attaches optional attributes.
// The span must be ended by the caller.
func (tr *tracer) Start(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	ctx, sp := tr.t.Start(ctx, name)
	if len(attrs) > 0 {
		sp.SetAttributes(attrs...)
	}

	return ctx, sp
}

// SpanFromContext is a convenience passthrough to extract the active span.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}
