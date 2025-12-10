package lualib

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"

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

// --- tests ---

func TestOTEL_WithSpan_Basic(t *testing.T) {
	coll := &spanCollector{}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(coll)),
	)
	cleanup := setupTracingEnabled(tp)

	defer cleanup()

	L := lua.NewState()
	defer L.Close()

	// Preload module with a background context
	L.PreloadModule(definitions.LuaModOpenTelemetry, LoaderModOTEL(context.Background()))

	script := `
      local otel = require("nauthilus_opentelemetry")
      local tr = otel.tracer("test/scope")
      tr:with_span("client.op", function(span)
        span:set_attributes({ ["peer.service"] = "http", tries = 1, ok = true })
        span:add_event("evt", { ["k"] = "v" })
        span:set_status("ok")
      end, { kind = "client" })
    `

	if err := L.DoString(script); err != nil {
		t.Fatalf("lua error: %v", err)
	}

	// One span expected with name client.op and kind client
	if len(coll.spans) == 0 {
		t.Fatalf("expected spans to be recorded, got 0")
	}

	var found bool
	for _, sp := range coll.spans {
		if sp.Name() == "client.op" {
			found = true
			if want := trace.SpanKindClient; sp.SpanKind() != want {
				t.Fatalf("span kind mismatch: want %v got %v", want, sp.SpanKind())
			}

			attrs := sp.Attributes()
			hasPeer := false
			hasTries := false
			hasOk := false
			for _, a := range attrs {
				if string(a.Key) == "peer.service" && a.Value.AsString() == "http" {
					hasPeer = true
				}
				if string(a.Key) == "tries" && a.Value.AsFloat64() == 1 {
					hasTries = true
				}
				if string(a.Key) == "ok" && a.Value.AsBool() {
					hasOk = true
				}
			}

			if !hasPeer || !hasTries || !hasOk {
				t.Fatalf("missing expected attributes: peer=%v tries=%v ok=%v", hasPeer, hasTries, hasOk)
			}
		}
	}

	if !found {
		t.Fatalf("expected to find span 'client.op'")
	}
}

func TestOTEL_BaggageAndPropagation(t *testing.T) {
	coll := &spanCollector{}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(coll)),
	)
	cleanup := setupTracingEnabled(tp)

	defer cleanup()

	L := lua.NewState()
	defer L.Close()

	L.PreloadModule(definitions.LuaModOpenTelemetry, LoaderModOTEL(context.Background()))

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

	if err := L.DoString(script); err != nil {
		t.Fatalf("lua error: %v", err)
	}

	// Verify headers were populated with trace context and baggage
	tbl := L.GetGlobal("headers")
	ht, ok := tbl.(*lua.LTable)
	if !ok {
		t.Fatalf("headers table not found")
	}

	// Look for typical keys
	var haveTraceparent, haveBaggage bool
	ht.ForEach(func(k, v lua.LValue) {
		if ks, ok := k.(lua.LString); ok {
			switch string(ks) {
			case "traceparent":
				if v != lua.LNil {
					haveTraceparent = true
				}
			case "baggage":
				if v != lua.LNil {
					haveBaggage = true
				}
			}
		}
	})

	if !haveTraceparent {
		t.Fatalf("traceparent not injected into headers")
	}
	if !haveBaggage {
		t.Fatalf("baggage not injected into headers")
	}
}

func TestOTEL_SemconvHelpers_And_NoOp(t *testing.T) {
	// 1) Semconv helpers under enabled
	coll := &spanCollector{}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(coll)),
	)
	cleanup := setupTracingEnabled(tp)

	L := lua.NewState()
	defer L.Close()

	L.PreloadModule(definitions.LuaModOpenTelemetry, LoaderModOTEL(context.Background()))

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

	if err := L.DoString(script); err != nil {
		t.Fatalf("lua error: %v", err)
	}

	// Verify mapping keys exist in at least one span
	if len(coll.spans) == 0 {
		t.Fatalf("expected spans, got 0")
	}

	var okHTTP, okDB, okNet bool
	for _, sp := range coll.spans {
		if sp.Name() != "test.semconv" {
			continue
		}
		for _, a := range sp.Attributes() {
			switch string(a.Key) {
			case "http.method":
				okHTTP = true
			case "db.system":
				okDB = true
			case "server.address":
				okNet = true
			}
		}
	}

	if !okHTTP || !okDB || !okNet {
		t.Fatalf("missing semconv attributes http=%v db=%v net=%v", okHTTP, okDB, okNet)
	}

	cleanup()

	// 2) No-op path: disabled tracing should not record spans
	setupTracingDisabled()

	coll2 := &spanCollector{}
	tp2 := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(coll2)))
	otel.SetTracerProvider(tp2)

	L2 := lua.NewState()
	defer L2.Close()

	L2.PreloadModule(definitions.LuaModOpenTelemetry, LoaderModOTEL(context.Background()))

	noOpScript := `
      local otel = require("nauthilus_opentelemetry")
      if otel.is_enabled() then error("otel should be disabled in this section") end
      local tr = otel.tracer("noop")
      local sp = tr:start_span("noop.op", { kind = "client" })
      -- method name 'end' is a Lua keyword; call via index form
      sp["end"](sp)
    `

	if err := L2.DoString(noOpScript); err != nil {
		t.Fatalf("lua error: %v", err)
	}

	if len(coll2.spans) != 0 {
		t.Fatalf("expected 0 spans recorded in no-op mode, got %d", len(coll2.spans))
	}
}
