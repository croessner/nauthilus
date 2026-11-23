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

package trace

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/v4/server/testing/oteltest"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const traceTestScope = "nauthilus/trace/test"

// traceTestSpanContext returns a valid sampled span context as a remote parent would provide it.
func traceTestSpanContext() trace.SpanContext {
	return trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SpanID:     trace.SpanID{1, 2, 3, 4, 5, 6, 7, 8},
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
}

// TestTracerStart runs its phases in order: installing a tracer provider cannot be undone within a process.
func TestTracerStart(t *testing.T) {
	t.Run("spans are inert without a tracer provider", testInertSpans)
	t.Run("a span context is passed on without a tracer provider", testSpanContextPassedOn)
	t.Run("spans are recorded with a tracer provider", testRecordedSpans)
}

// testInertSpans checks that spans nobody can observe are not built.
func testInertSpans(t *testing.T) {
	if inertProvider == nil || otel.GetTracerProvider() != inertProvider {
		t.Fatal("expected the default tracer provider to be the inert one")
	}

	tr := New(traceTestScope)
	ctx := context.WithValue(context.Background(), traceTestKey{}, "value")

	starts := map[string]func(context.Context, string, ...attribute.KeyValue) (context.Context, trace.Span){
		"internal": tr.Start,
		"server":   tr.StartServer,
		"client":   tr.StartClient,
	}

	for kind, start := range starts {
		spanCtx, span := start(ctx, "operation", attribute.String("key", "value"))

		if spanCtx != ctx {
			t.Fatalf("%s: expected the context to be passed through", kind)
		}

		if span.IsRecording() || span.SpanContext().IsValid() {
			t.Fatalf("%s: expected a span that is neither recorded nor identified", kind)
		}

		// The whole span API must stay usable.
		span.SetAttributes(attribute.Int("count", 1))
		span.RecordError(context.Canceled)
		span.End()
	}

	allocations := testing.AllocsPerRun(100, func() {
		_, span := tr.Start(ctx, "operation")
		span.End()
	})

	if allocations != 0 {
		t.Fatalf("expected an inert span to cost no allocation, got %v", allocations)
	}
}

// testSpanContextPassedOn checks that a parent span context still reaches the spans below it.
func testSpanContextPassedOn(t *testing.T) {
	parent := traceTestSpanContext()
	ctx := trace.ContextWithSpanContext(context.Background(), parent)

	spanCtx, span := New(traceTestScope).Start(ctx, "operation")
	defer span.End()

	if !span.SpanContext().Equal(parent) {
		t.Fatalf("expected the span to carry the parent span context, got %v", span.SpanContext())
	}

	if !trace.SpanContextFromContext(spanCtx).Equal(parent) {
		t.Fatal("expected the returned context to carry the parent span context")
	}
}

// testRecordedSpans checks kinds and attributes once a recording provider is installed, also for a tracer that
// was created before.
func testRecordedSpans(t *testing.T) {
	early := New(traceTestScope)
	collector := oteltest.Setup(t)

	if spansAreInert(context.Background()) {
		t.Fatal("expected spans to count as observable with a tracer provider")
	}

	late := New(traceTestScope)

	_, internal := early.Start(context.Background(), "internal", attribute.String("key", "value"))
	internal.End()

	_, server := late.StartServer(context.Background(), "server")
	server.End()

	_, client := late.StartClient(context.Background(), "client", attribute.Int("count", 2))
	client.End()

	spans := collector.Spans()
	if len(spans) != 3 {
		t.Fatalf("expected 3 recorded spans, got %d", len(spans))
	}

	wantKinds := []trace.SpanKind{trace.SpanKindInternal, trace.SpanKindServer, trace.SpanKindClient}
	wantAttributes := []int{1, 0, 1}

	for index, span := range spans {
		if span.SpanKind() != wantKinds[index] {
			t.Fatalf("span %q: expected kind %v, got %v", span.Name(), wantKinds[index], span.SpanKind())
		}

		if len(span.Attributes()) != wantAttributes[index] {
			t.Fatalf("span %q: expected %d attributes, got %v", span.Name(), wantAttributes[index], span.Attributes())
		}
	}
}

// traceTestKey is a context key for the pass-through check.
type traceTestKey struct{}
