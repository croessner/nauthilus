// Copyright (C) 2026 Christian Roessner
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

package pluginruntime

import (
	"context"
	"fmt"
	"strings"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"

	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
)

var _ pluginapi.Tracer = (*TracerFacade)(nil)
var _ pluginapi.Span = (*spanFacade)(nil)

// TracerFacade starts plugin spans through the host tracing package.
type TracerFacade struct {
	tracer monittrace.Tracer
	scope  string
}

// NewTracerFacade returns a scoped plugin tracer facade.
func NewTracerFacade(scope string) *TracerFacade {
	if strings.TrimSpace(scope) == "" {
		scope = "plugin"
	}

	return &TracerFacade{
		tracer: monittrace.New("nauthilus/plugin/" + scope),
		scope:  scope,
	}
}

// Start begins a child span using host-owned OpenTelemetry plumbing.
func (t *TracerFacade) Start(ctx context.Context, name string, attrs ...pluginapi.TraceAttribute) (context.Context, pluginapi.Span) {
	if ctx == nil {
		ctx = context.Background()
	}

	if t == nil || t.tracer == nil {
		return ctx, noopSpan{}
	}

	spanName := strings.TrimSpace(name)
	if spanName == "" {
		spanName = "plugin.operation"
	}

	nextCtx, span := t.tracer.Start(ctx, spanName, traceAttributes(attrs)...)

	return nextCtx, spanFacade{span: span}
}

type spanFacade struct {
	span oteltrace.Span
}

// AddEvent records a span event through OpenTelemetry.
func (s spanFacade) AddEvent(name string, attrs ...pluginapi.TraceAttribute) {
	if s.span == nil {
		return
	}

	s.span.AddEvent(name, oteltrace.WithAttributes(traceAttributes(attrs)...))
}

// SetAttributes records span attributes through OpenTelemetry.
func (s spanFacade) SetAttributes(attrs ...pluginapi.TraceAttribute) {
	if s.span == nil {
		return
	}

	s.span.SetAttributes(traceAttributes(attrs)...)
}

// RecordError records an error on the span.
func (s spanFacade) RecordError(err error) {
	if s.span == nil || err == nil {
		return
	}

	s.span.RecordError(err)
}

// End finishes the span.
func (s spanFacade) End() {
	if s.span == nil {
		return
	}

	s.span.End()
}

// traceAttributes converts API trace attributes to OpenTelemetry attributes.
func traceAttributes(attrs []pluginapi.TraceAttribute) []attribute.KeyValue {
	if len(attrs) == 0 {
		return nil
	}

	converted := make([]attribute.KeyValue, 0, len(attrs))
	for _, attr := range attrs {
		key := strings.TrimSpace(attr.Key)
		if key == "" {
			continue
		}

		converted = append(converted, traceAttribute(key, attr.Value))
	}

	return converted
}

// traceAttribute converts one low-cardinality API attribute.
func traceAttribute(key string, value any) attribute.KeyValue {
	switch typed := value.(type) {
	case bool:
		return attribute.Bool(key, typed)
	case int:
		return attribute.Int(key, typed)
	case int64:
		return attribute.Int64(key, typed)
	case float64:
		return attribute.Float64(key, typed)
	case string:
		return attribute.String(key, typed)
	default:
		return attribute.String(key, fmt.Sprint(typed))
	}
}
