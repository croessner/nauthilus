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

// Package tracetest provides small OpenTelemetry helpers for focused tracing tests.
package tracetest

import (
	"context"
	"reflect"
	"sync"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Collector stores exported spans in memory.
type Collector struct {
	mu    sync.Mutex
	spans []sdktrace.ReadOnlySpan
}

// ExportSpans implements sdktrace.SpanExporter.
func (c *Collector) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.spans = append(c.spans, spans...)

	return nil
}

// Shutdown implements sdktrace.SpanExporter.
func (c *Collector) Shutdown(_ context.Context) error {
	return nil
}

// Spans returns a stable snapshot of collected spans.
func (c *Collector) Spans() []sdktrace.ReadOnlySpan {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([]sdktrace.ReadOnlySpan(nil), c.spans...)
}

// Setup installs an always-sampled tracer provider and enables tracing in the test config.
func Setup(t *testing.T) *Collector {
	t.Helper()

	collector := &Collector{}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(collector)),
	)

	cfg := &config.FileSettings{
		Server: &config.ServerSection{},
	}
	cfg.Server.Insights.Tracing.Enabled = true
	config.SetTestFile(cfg)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())

		config.SetTestFile(nil)

		otel.SetTracerProvider(sdktrace.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	})

	return collector
}

// FindByNameAndAttributes returns the first span matching name and all attributes.
func FindByNameAndAttributes(spans []sdktrace.ReadOnlySpan, name string, attrs ...attribute.KeyValue) (sdktrace.ReadOnlySpan, bool) {
	for _, span := range spans {
		if span.Name() != name {
			continue
		}

		if hasAttributes(span, attrs...) {
			return span, true
		}
	}

	return nil, false
}

func hasAttributes(span sdktrace.ReadOnlySpan, attrs ...attribute.KeyValue) bool {
	if len(attrs) == 0 {
		return true
	}

	spanAttrs := span.Attributes()

	for _, want := range attrs {
		found := false

		for _, got := range spanAttrs {
			if got.Key == want.Key && reflect.DeepEqual(got.Value.AsInterface(), want.Value.AsInterface()) {
				found = true

				break
			}
		}

		if !found {
			return false
		}
	}

	return true
}
