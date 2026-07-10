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

// Package oteltest provides config-independent OpenTelemetry test collection.
package oteltest

import (
	"context"
	"sync"
	"testing"

	"go.opentelemetry.io/otel"
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
func (c *Collector) Shutdown(context.Context) error {
	return nil
}

// Spans returns a stable snapshot of collected spans.
func (c *Collector) Spans() []sdktrace.ReadOnlySpan {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([]sdktrace.ReadOnlySpan(nil), c.spans...)
}

// Setup installs an always-sampled provider without changing application configuration.
func Setup(t *testing.T) *Collector {
	t.Helper()

	collector := &Collector{}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(collector)),
	)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	t.Cleanup(func() {
		_ = provider.Shutdown(context.Background())

		otel.SetTracerProvider(sdktrace.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		))
	})

	return collector
}
