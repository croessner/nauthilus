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
	// StartClient begins a span explicitly marked as SpanKindClient to represent
	// an outgoing client operation (e.g., LDAP, HTTP client, Redis, etc.).
	// Optional attributes can be supplied and will be set on the span.
	StartClient(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span)
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

// StartClient begins a client span (SpanKindClient) and attaches optional attributes.
// The span must be ended by the caller.
func (tr *tracer) StartClient(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	ctx, sp := tr.t.Start(ctx, name, trace.WithSpanKind(trace.SpanKindClient))
	if len(attrs) > 0 {
		sp.SetAttributes(attrs...)
	}

	return ctx, sp
}

// SpanFromContext is a convenience passthrough to extract the active span.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}
