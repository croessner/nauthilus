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

package log

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log/level"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type recordingLogHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

// Enabled accepts every test log record.
func (h *recordingLogHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

// Handle stores a detached copy of the test log record.
func (h *recordingLogHandler) Handle(_ context.Context, record slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.records = append(h.records, record.Clone())

	return nil
}

// WithAttrs keeps the recording handler used by the dynamic wrapper test.
func (h *recordingLogHandler) WithAttrs([]slog.Attr) slog.Handler {
	return h
}

// WithGroup keeps the recording handler used by the dynamic wrapper test.
func (h *recordingLogHandler) WithGroup(string) slog.Handler {
	return h
}

// firstRecord returns the single record captured by the test handler.
func (h *recordingLogHandler) firstRecord(t *testing.T) slog.Record {
	t.Helper()

	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.records) != 1 {
		t.Fatalf("records = %d, want 1", len(h.records))
	}

	return h.records[0]
}

func TestSetupLogging(t *testing.T) {
	tests := []struct {
		name           string
		configLogLevel int
		formatJSON     bool
		useColor       bool
		instance       string
	}{
		{
			name:           "LogLevelNone, JSON format, Color",
			configLogLevel: definitions.LogLevelNone,
			formatJSON:     true,
			useColor:       true,
			instance:       "none_json_color",
		},
		{
			name:           "LogLevelError, Logfmt format, No Color",
			configLogLevel: definitions.LogLevelError,
			formatJSON:     false,
			useColor:       false,
			instance:       "error_logfmt_nocolor",
		},
		{
			name:           "LogLevelWarn, JSON format, Color",
			configLogLevel: definitions.LogLevelWarn,
			formatJSON:     true,
			useColor:       true,
			instance:       "warn_json_color",
		},
		{
			name:           "LogLevelInfo, Logfmt format, No Color",
			configLogLevel: definitions.LogLevelInfo,
			formatJSON:     false,
			useColor:       false,
			instance:       "info_logfmt_nocolor",
		},
		{
			name:           "LogLevelDebug, JSON format, No color",
			configLogLevel: definitions.LogLevelDebug,
			formatJSON:     true,
			useColor:       false,
			instance:       "debug_json_nocolor",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize logging
			SetupLogging(tt.configLogLevel, tt.formatJSON, tt.useColor, true, tt.instance)

			// Ensure global Logger is initialized
			if Logger == nil {
				t.Fatalf("Logger was not initialized")
			}

			// exercise wrapper functions; should not panic
			_ = level.Debug(Logger).Log("msg", "debug")
			_ = level.Info(Logger).Log("msg", "info")
			_ = level.Warn(Logger).Log("msg", "warn")
			_ = level.Error(Logger).Log("msg", "error")
		})
	}
}

func TestDynamicHandlerAddsActiveTraceCorrelation(t *testing.T) {
	provider := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()))
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		_ = provider.Shutdown(context.Background())

		otel.SetTracerProvider(sdktrace.NewTracerProvider())
	})

	capture := &recordingLogHandler{}
	root := &dynamicHandlerRoot{}
	root.inner.Store(&handlerHolder{h: capture})
	handler := &dynamicHandler{root: root}

	ctx, span := otel.Tracer("nauthilus/log/logger_test").Start(context.Background(), "request.parent")
	record := slog.NewRecord(time.Now(), slog.LevelInfo, "message", 0)

	if err := handler.Handle(ctx, record); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	attrs := recordAttributes(capture.firstRecord(t))
	spanContext := span.SpanContext()
	span.End()

	if got := attrs["trace_id"]; got != spanContext.TraceID().String() {
		t.Fatalf("trace_id = %q, want %q", got, spanContext.TraceID())
	}

	if got := attrs["span_id"]; got != spanContext.SpanID().String() {
		t.Fatalf("span_id = %q, want %q", got, spanContext.SpanID())
	}

	if got := attrs["trace_flags"]; got != spanContext.TraceFlags().String() {
		t.Fatalf("trace_flags = %q, want %q", got, spanContext.TraceFlags())
	}
}

func TestDynamicHandlerPreservesExplicitTraceCorrelation(t *testing.T) {
	provider := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()))
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		_ = provider.Shutdown(context.Background())

		otel.SetTracerProvider(sdktrace.NewTracerProvider())
	})

	capture := &recordingLogHandler{}
	root := &dynamicHandlerRoot{}
	root.inner.Store(&handlerHolder{h: capture})
	handler := &dynamicHandler{root: root}
	ctx, span := otel.Tracer("nauthilus/log/logger_test").Start(context.Background(), "request.parent")

	defer span.End()

	record := slog.NewRecord(time.Now(), slog.LevelInfo, "message", 0)
	record.AddAttrs(
		slog.String(logTraceIDKey, "explicit-trace"),
		slog.String(logSpanIDKey, "explicit-span"),
		slog.String(logTraceFlagsKey, "explicit-flags"),
	)

	if err := handler.Handle(ctx, record); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	attrs := recordAttributes(capture.firstRecord(t))
	if attrs[logTraceIDKey] != "explicit-trace" || attrs[logSpanIDKey] != "explicit-span" || attrs[logTraceFlagsKey] != "explicit-flags" {
		t.Fatalf("explicit trace correlation was replaced: %#v", attrs)
	}
}

func TestDynamicHandlerOmitsTraceCorrelationWithoutSpan(t *testing.T) {
	capture := &recordingLogHandler{}
	root := &dynamicHandlerRoot{}
	root.inner.Store(&handlerHolder{h: capture})
	handler := &dynamicHandler{root: root}

	record := slog.NewRecord(time.Now(), slog.LevelInfo, "message", 0)
	if err := handler.Handle(context.Background(), record); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	attrs := recordAttributes(capture.firstRecord(t))
	if _, exists := attrs[logTraceIDKey]; exists {
		t.Fatalf("trace correlation added without active span: %#v", attrs)
	}
}

// recordAttributes flattens top-level record attributes for focused assertions.
func recordAttributes(record slog.Record) map[string]string {
	attrs := make(map[string]string, record.NumAttrs())
	record.Attrs(func(attr slog.Attr) bool {
		attrs[attr.Key] = attr.Value.String()

		return true
	})

	return attrs
}
