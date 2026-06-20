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

package lualib

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log"

	lua "github.com/yuin/gopher-lua"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// --- test helpers ---

type spanCollector struct{ spans []sdktrace.ReadOnlySpan }

func (c *spanCollector) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	c.spans = append(c.spans, spans...)

	return nil
}

func (c *spanCollector) Shutdown(_ context.Context) error { return nil }

func setupTracingEnabled(tp *sdktrace.TracerProvider) func() {
	// Minimal config: enable tracing via test file provider
	cfg := &config.FileSettings{}
	cfg.Server = &config.ServerSection{}
	cfg.Server.Insights.Tracing.Enabled = true
	config.SetTestFile(cfg)

	if tp != nil {
		otel.SetTracerProvider(tp)
	}

	// Ensure propagators support tracecontext + baggage used by tests
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return func() {
		// Reset globals for cleanliness across tests
		otel.SetTracerProvider(sdktrace.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
		// Leave config test file in place; other tests may rely on it.
	}
}

func setupTracingDisabled() {
	cfg := &config.FileSettings{}
	cfg.Server = &config.ServerSection{}
	cfg.Server.Insights.Tracing.Enabled = false
	config.SetTestFile(cfg)
}

// newOTELTestState creates a Lua state with the OpenTelemetry module preloaded.
func newOTELTestState(t *testing.T) *lua.LState {
	t.Helper()

	L := lua.NewState()
	L.PreloadModule(definitions.LuaModOpenTelemetry, LoaderModOTEL(context.Background(), config.GetFile(), log.GetLogger()))

	return L
}

// runOTELScript executes a Lua OpenTelemetry test script.
func runOTELScript(t *testing.T, L *lua.LState, script string) {
	t.Helper()

	if err := L.DoString(script); err != nil {
		t.Fatalf("lua error: %v", err)
	}
}

// requireCollectedSpan returns a recorded span by name.
func requireCollectedSpan(t *testing.T, coll *spanCollector, name string) sdktrace.ReadOnlySpan {
	t.Helper()

	if len(coll.spans) == 0 {
		t.Fatalf("expected spans to be recorded, got 0")
	}

	for _, sp := range coll.spans {
		if sp.Name() == name {
			return sp
		}
	}

	t.Fatalf("expected to find span %q", name)

	return nil
}

// assertSpanStringAttr verifies a string span attribute.
func assertSpanStringAttr(t *testing.T, sp sdktrace.ReadOnlySpan, key string, value string) {
	t.Helper()

	for _, attr := range sp.Attributes() {
		if string(attr.Key) == key && attr.Value.AsString() == value {
			return
		}
	}

	t.Fatalf("missing expected string attribute %s=%s", key, value)
}

// assertSpanFloatAttr verifies a numeric span attribute.
func assertSpanFloatAttr(t *testing.T, sp sdktrace.ReadOnlySpan, key string, value float64) {
	t.Helper()

	for _, attr := range sp.Attributes() {
		if string(attr.Key) == key && attr.Value.AsFloat64() == value {
			return
		}
	}

	t.Fatalf("missing expected numeric attribute %s=%v", key, value)
}

// assertSpanBoolAttr verifies a boolean span attribute.
func assertSpanBoolAttr(t *testing.T, sp sdktrace.ReadOnlySpan, key string, value bool) {
	t.Helper()

	for _, attr := range sp.Attributes() {
		if string(attr.Key) == key && attr.Value.AsBool() == value {
			return
		}
	}

	t.Fatalf("missing expected boolean attribute %s=%v", key, value)
}

// --- tests ---

func TestOTEL_WithSpan_Basic(t *testing.T) {
	coll := &spanCollector{}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(coll)),
	)
	cleanup := setupTracingEnabled(tp)

	defer cleanup()

	L := newOTELTestState(t)
	defer L.Close()

	script := `
      local otel = require("nauthilus_opentelemetry")
      local tr = otel.tracer("test/scope")
      tr:with_span("client.op", function(span)
        span:set_attributes({ ["peer.service"] = "http", tries = 1, ok = true })
        span:add_event("evt", { ["k"] = "v" })
        span:set_status("ok")
      end, { kind = "client" })
    `

	runOTELScript(t, L, script)

	sp := requireCollectedSpan(t, coll, "client.op")
	if want := trace.SpanKindClient; sp.SpanKind() != want {
		t.Fatalf("span kind mismatch: want %v got %v", want, sp.SpanKind())
	}

	assertSpanStringAttr(t, sp, "peer.service", "http")
	assertSpanFloatAttr(t, sp, "tries", 1)
	assertSpanBoolAttr(t, sp, "ok", true)
}

func TestOTEL_Span_Finish(t *testing.T) {
	coll := &spanCollector{}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(coll)),
	)
	cleanup := setupTracingEnabled(tp)

	defer cleanup()

	L := newOTELTestState(t)
	defer L.Close()

	script := `
      local otel = require("nauthilus_opentelemetry")
      local tr = otel.tracer("test/scope")
      local span = tr:start_span("manual.op", { kind = "internal" })
      span:set_attribute("manual", true)
      span:finish()
    `

	runOTELScript(t, L, script)
	assertSpanBoolAttr(t, requireCollectedSpan(t, coll, "manual.op"), "manual", true)
}

func TestOTEL_BaggageAndPropagation(t *testing.T) {
	coll := &spanCollector{}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(coll)),
	)
	cleanup := setupTracingEnabled(tp)

	defer cleanup()

	L := newOTELTestState(t)
	defer L.Close()

	script := `
      local otel = require("nauthilus_opentelemetry")
      if not otel.is_enabled() then error("otel disabled in test") end
      local tr = otel.default_tracer()
      headers = {}
      -- create a span so that a valid trace context exists for injection
      tr:with_span("propagation.test", function(span)
        otel.baggage_set("user.id", "42")
        otel.inject_headers(headers)
        span:add_event("ok")
      end)
    `

	runOTELScript(t, L, script)
	assertLuaHeaderPresent(t, L, "traceparent")
	assertLuaHeaderPresent(t, L, "baggage")
}

func TestOTEL_SemconvHelpers_And_NoOp(t *testing.T) {
	// 1) Semconv helpers under enabled
	coll := &spanCollector{}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(coll)),
	)
	cleanup := setupTracingEnabled(tp)

	L := newOTELTestState(t)
	defer L.Close()

	script := `
      local otel = require("nauthilus_opentelemetry")
      local sem = otel.semconv
      out_http = sem.http_client_attrs({ method = "GET", url = "https://x", status_code = 200 })
      out_db = sem.db_attrs({ system = "sqlite", name = "m", operation = "query" })
      out_net = sem.net_attrs({ peer_name = "host", peer_port = 443 })
      local tr = otel.tracer("semconv/test")
      tr:with_span("test.semconv", function(span)
        span:set_attributes(out_http)
        span:set_attributes(out_db)
        span:set_attributes(out_net)
      end, { kind = "client" })
    `

	runOTELScript(t, L, script)
	assertSemconvAttributes(t, requireCollectedSpan(t, coll, "test.semconv"))

	cleanup()

	assertOTELNoOpRecordsNoSpans(t)
}

// assertLuaHeaderPresent verifies that the global headers table contains one key.
func assertLuaHeaderPresent(t *testing.T, L *lua.LState, key string) {
	t.Helper()

	headers, ok := L.GetGlobal("headers").(*lua.LTable)
	if !ok {
		t.Fatalf("headers table not found")
	}

	if value := headers.RawGetString(key); value == lua.LNil {
		t.Fatalf("%s not injected into headers", key)
	}
}

// assertSemconvAttributes verifies representative semantic convention attributes.
func assertSemconvAttributes(t *testing.T, sp sdktrace.ReadOnlySpan) {
	t.Helper()

	assertSpanKeyPresent(t, sp, "http.method")
	assertSpanKeyPresent(t, sp, "db.system")
	assertSpanKeyPresent(t, sp, "server.address")
}

// assertSpanKeyPresent verifies that a span contains an attribute key.
func assertSpanKeyPresent(t *testing.T, sp sdktrace.ReadOnlySpan, key string) {
	t.Helper()

	for _, attr := range sp.Attributes() {
		if string(attr.Key) == key {
			return
		}
	}

	t.Fatalf("missing semconv attribute %s", key)
}

// assertOTELNoOpRecordsNoSpans verifies disabled tracing does not export spans.
func assertOTELNoOpRecordsNoSpans(t *testing.T) {
	t.Helper()

	setupTracingDisabled()

	coll2 := &spanCollector{}
	tp2 := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(coll2)))
	otel.SetTracerProvider(tp2)

	L2 := newOTELTestState(t)
	defer L2.Close()

	noOpScript := `
      local otel = require("nauthilus_opentelemetry")
      if otel.is_enabled() then error("otel should be disabled in this section") end
      local tr = otel.tracer("noop")
      local sp = tr:start_span("noop.op", { kind = "client" })
      -- method name 'end' is a Lua keyword; call via index form
      sp["end"](sp)
    `

	runOTELScript(t, L2, noOpScript)

	if len(coll2.spans) != 0 {
		t.Fatalf("expected 0 spans recorded in no-op mode, got %d", len(coll2.spans))
	}
}
