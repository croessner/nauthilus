// Copyright (C) 2024 Christian Rößner
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

// Package trace provides trace functionality.
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
	// StartServer begins a span explicitly marked as SpanKindServer to represent
	// an incoming server operation.
	// Optional attributes can be supplied and will be set on the span.
	StartServer(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span)
	// StartClient begins a span explicitly marked as SpanKindClient to represent
	// an outgoing client operation (e.g., LDAP, HTTP client, Redis, etc.).
	// Optional attributes can be supplied and will be set on the span.
	StartClient(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span)
}

// ScopedTracer is the Tracer of one instrumentation scope.
//
// New returns the concrete type so that calls on a freshly created tracer are direct calls: the compiler can then
// keep the attributes of a span that nobody records off the heap.
type ScopedTracer struct {
	t trace.Tracer
}

// inertProvider is the tracer provider that OpenTelemetry installs by default; it is nil if a recording provider
// was already installed when this package was initialized.
//
// As long as it is the global provider, no SDK is present: a span is not recorded, drops its attributes and only
// carries the span context it found in its parent context.
var inertProvider = defaultInertProvider()

// inertSpan is the shared span without span context that stands in for spans nobody records.
var inertSpan = trace.SpanFromContext(context.Background())

// defaultInertProvider returns the current global provider if spans started from it are not recorded.
func defaultInertProvider() trace.TracerProvider {
	provider := otel.GetTracerProvider()

	_, probe := provider.Tracer("nauthilus/trace/probe").Start(context.Background(), "probe")
	defer probe.End()

	if probe.IsRecording() || probe.SpanContext().IsValid() {
		return nil
	}

	return provider
}

// spansAreInert reports whether a span started from ctx would neither be recorded nor carry a span context.
//
// That holds while no tracer provider was installed and ctx holds no span context to pass on. Such a span is
// indistinguishable from the shared inert span, so starting it would only allocate.
func spansAreInert(ctx context.Context) bool {
	return inertProvider != nil &&
		otel.GetTracerProvider() == inertProvider &&
		!trace.SpanContextFromContext(ctx).IsValid()
}

// New creates a new Tracer tied to the given instrumentation scope.
func New(scope string) *ScopedTracer {
	return &ScopedTracer{t: otel.Tracer(scope)}
}

// Start begins a span with the provided name and attaches optional attributes.
// The span must be ended by the caller.
func (tr *ScopedTracer) Start(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return tr.start(ctx, name, trace.SpanKindUnspecified, attrs)
}

// StartServer begins a server span and attaches optional attributes.
// The span must be ended by the caller.
func (tr *ScopedTracer) StartServer(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return tr.start(ctx, name, trace.SpanKindServer, attrs)
}

// StartClient begins a client span (SpanKindClient) and attaches optional attributes.
// The span must be ended by the caller.
func (tr *ScopedTracer) StartClient(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return tr.start(ctx, name, trace.SpanKindClient, attrs)
}

// start begins a span of the given kind, or hands out the inert span if nobody would see the span.
func (tr *ScopedTracer) start(
	ctx context.Context,
	name string,
	kind trace.SpanKind,
	attrs []attribute.KeyValue,
) (context.Context, trace.Span) {
	if spansAreInert(ctx) {
		return ctx, inertSpan
	}

	var sp trace.Span

	if kind == trace.SpanKindUnspecified {
		ctx, sp = tr.t.Start(ctx, name)
	} else {
		ctx, sp = tr.t.Start(ctx, name, trace.WithSpanKind(kind))
	}

	if len(attrs) > 0 {
		// The span keeps a copy, so the attributes of the caller do not have to outlive the call.
		sp.SetAttributes(append([]attribute.KeyValue(nil), attrs...)...)
	}

	return ctx, sp
}

// SetAttributes attaches attributes to a span that records them.
//
// Unlike a direct call on the span it leaves the attributes of a span that nobody records off the heap.
func SetAttributes(span trace.Span, attrs ...attribute.KeyValue) {
	if span.IsRecording() {
		span.SetAttributes(append([]attribute.KeyValue(nil), attrs...)...)
	}
}

// SpanFromContext is a convenience passthrough to extract the active span.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}
