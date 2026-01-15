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
	"log/slog"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/luastack"

	lua "github.com/yuin/gopher-lua"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// --- Public module loaders ---

type OTELManager struct {
	*BaseManager
	enabled bool
}

// NewOTELManager creates a new OTELManager.
func NewOTELManager(ctx context.Context, cfg config.File, logger *slog.Logger) *OTELManager {
	enabled := cfg.GetServer().GetInsights().GetTracing().IsEnabled()

	return &OTELManager{
		BaseManager: NewBaseManager(ctx, cfg, logger),
		enabled:     enabled,
	}
}

// --- Public module loaders ---

// LoaderModOTEL provides a context-aware OpenTelemetry Lua module.
// It binds helper functions and userdata to create and manage spans from Lua.
func LoaderModOTEL(ctx context.Context, cfg config.File, logger *slog.Logger) lua.LGFunction {
	return func(L *lua.LState) int {
		stack := luastack.NewManager(L)
		manager := NewOTELManager(ctx, cfg, logger)
		mod := L.NewTable()

		// Ensure metatables are registered once per state
		ensureTracerMT(L)
		ensureSpanMT(L)

		// Register functions
		L.SetFuncs(mod, map[string]lua.LGFunction{
			"tracer":         manager.luaTracer,
			"default_tracer": manager.luaDefaultTracer,
			"is_enabled":     manager.luaIsEnabled,
			// baggage
			"baggage_set":   manager.luaBaggageSet,
			"baggage_get":   manager.luaBaggageGet,
			"baggage_all":   manager.luaBaggageAll,
			"baggage_clear": manager.luaBaggageClear,
			// propagation
			"inject_headers":  manager.luaInjectHeaders,
			"extract_headers": manager.luaExtractHeaders,
		})

		// semconv helpers (strings only, to avoid importing specific versions)
		sem := L.NewTable()
		L.SetFuncs(sem, map[string]lua.LGFunction{
			"peer_service":      luaSemconvPeerService,
			"http_client_attrs": luaSemconvHTTPClientAttrs,
			"db_attrs":          luaSemconvDBAttrs,
			"net_attrs":         luaSemconvNetAttrs,
		})
		mod.RawSetString("semconv", sem)

		return stack.PushResult(mod)
	}
}

// LoaderOTELStateless returns an empty module so require("nauthilus_opentelemetry") never fails.
func LoaderOTELStateless() lua.LGFunction {
	return func(L *lua.LState) int {
		stack := luastack.NewManager(L)

		return stack.PushResult(L.NewTable())
	}
}

// --- Internal state and helpers ---

func (s *OTELManager) tracerFor(scope string) trace.Tracer {
	if scope == "" {
		scope = "nauthilus/lua"
	}

	return otel.Tracer(scope)
}

// textMapCarrier adapts a Lua table [string]string to propagation carrier.
type textMapCarrier struct{ tbl *lua.LTable }

func (c textMapCarrier) Get(key string) string {
	v := c.tbl.RawGetString(key)
	if s, ok := v.(lua.LString); ok {
		return string(s)
	}

	return ""
}
func (c textMapCarrier) Set(key string, value string) {
	c.tbl.RawSetString(key, lua.LString(value))
}
func (c textMapCarrier) Keys() []string {
	keys := make([]string, 0, c.tbl.Len())
	c.tbl.ForEach(func(k, _ lua.LValue) {
		if ks, ok := k.(lua.LString); ok {
			keys = append(keys, string(ks))
		}
	})

	return keys
}

// --- Lua bindings (globals) ---

func (s *OTELManager) luaIsEnabled(L *lua.LState) int {
	stack := luastack.NewManager(L)

	return stack.PushResults(lua.LBool(s.enabled), lua.LNil)
}

func (s *OTELManager) luaTracer(L *lua.LState) int {
	stack := luastack.NewManager(L)
	scope := stack.CheckString(1)

	return s.pushTracer(L, scope)
}

func (s *OTELManager) luaDefaultTracer(L *lua.LState) int {
	return s.pushTracer(L, "nauthilus/lua")
}

func (s *OTELManager) pushTracer(L *lua.LState, scope string) int {
	stack := luastack.NewManager(L)
	ud := L.NewUserData()
	ud.Value = &luaTracerUD{state: s, scope: scope}
	L.SetMetatable(ud, L.GetTypeMetatable(definitions.LuaUDTracer))

	return stack.PushResults(ud, lua.LNil)
}

func (s *OTELManager) luaBaggageSet(L *lua.LState) int {
	stack := luastack.NewManager(L)

	if !s.enabled { // no-op
		return 0
	}

	key := stack.CheckString(1)
	val := stack.CheckString(2)
	m := baggage.FromContext(s.Ctx)
	mem, err := baggage.NewMember(key, val)
	if err == nil {
		nb, err2 := baggage.New(append(m.Members(), mem)...)
		if err2 == nil {
			s.Ctx = baggage.ContextWithBaggage(s.Ctx, nb)
		}
	}

	return 0
}

func (s *OTELManager) luaBaggageGet(L *lua.LState) int {
	stack := luastack.NewManager(L)
	key := stack.CheckString(1)
	m := baggage.FromContext(s.Ctx)
	v := m.Member(key).Value()

	if v == "" {
		return stack.PushResults(lua.LNil, lua.LNil)
	}

	return stack.PushResults(lua.LString(v), lua.LNil)
}

func (s *OTELManager) luaBaggageAll(L *lua.LState) int {
	stack := luastack.NewManager(L)
	tbl := L.NewTable()
	m := baggage.FromContext(s.Ctx)

	for _, mem := range m.Members() {
		tbl.RawSetString(mem.Key(), lua.LString(mem.Value()))
	}

	return stack.PushResults(tbl, lua.LNil)
}

func (s *OTELManager) luaBaggageClear(_ *lua.LState) int {
	if !s.enabled {
		return 0
	}

	if nb, err := baggage.New(); err == nil {
		s.Ctx = baggage.ContextWithBaggage(s.Ctx, nb)
	}

	return 0
}

func (s *OTELManager) luaInjectHeaders(L *lua.LState) int {
	stack := luastack.NewManager(L)

	if !s.enabled {
		return 0
	}

	tbl := stack.CheckTable(1)
	carrier := textMapCarrier{tbl}

	otel.GetTextMapPropagator().Inject(s.Ctx, carrier)

	return 0
}

func (s *OTELManager) luaExtractHeaders(L *lua.LState) int {
	stack := luastack.NewManager(L)

	if !s.enabled {
		return 0
	}

	tbl := stack.CheckTable(1)
	carrier := textMapCarrier{tbl}
	ctx := otel.GetTextMapPropagator().Extract(s.Ctx, carrier)
	s.Ctx = ctx

	return 0
}

// --- Tracer userdata ---

type luaTracerUD struct {
	state *OTELManager
	scope string
}

// register tracer metatable on first use
func ensureTracerMT(L *lua.LState) {
	if L.GetTypeMetatable(definitions.LuaUDTracer) != lua.LNil {
		return
	}

	mt := L.NewTypeMetatable(definitions.LuaUDTracer)
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"start_span": tracerStartSpan,
		"with_span":  tracerWithSpan,
	}))
}

// register span metatable on first use
func ensureSpanMT(L *lua.LState) {
	if L.GetTypeMetatable(definitions.LuaUDSpan) != lua.LNil {
		return
	}

	mt := L.NewTypeMetatable(definitions.LuaUDSpan)
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"set_attribute":  spanSetAttribute,
		"set_attributes": spanSetAttributes,
		"add_event":      spanAddEvent,
		"set_status":     spanSetStatus,
		"record_error":   spanRecordError,
		"end":            spanEnd, // Reserved ke
		"finish":         spanEnd,
	}))
}

func tracerStartSpan(L *lua.LState) int {
	ensureSpanMT(L)

	stack := luastack.NewManager(L)

	ud := stack.CheckUserData(1)
	if ud == nil {
		L.ArgError(1, "tracer expected")

		return 0
	}

	tr, ok := ud.Value.(*luaTracerUD)
	if !ok || tr == nil {
		L.ArgError(1, "tracer expected")

		return 0
	}

	name := stack.CheckString(2)

	var opts *lua.LTable

	if stack.GetTop() >= 3 {
		opts = L.OptTable(3, nil)
	}

	// Build options
	kind := spanKindFromOpts(opts)
	attrs := attrsFromTable(L, tblField(opts, "attributes"))

	// Links (optional)
	links := linksFromTable(L, tblField(opts, "links"))

	ctx := tr.state.Ctx

	if !tr.state.enabled {
		// Return a dummy span userdata to keep API stable
		return stack.PushResults(newDummySpanUD(L), lua.LNil)
	}

	tracer := tr.state.tracerFor(tr.scope)
	sctx, sp := tracer.Start(ctx, name, append([]trace.SpanStartOption{trace.WithSpanKind(kind)}, trace.WithLinks(links...))...)

	if len(attrs) > 0 {
		sp.SetAttributes(attrs...)
	}

	// Update context for caller if they want it
	spanUD := L.NewUserData()
	spanUD.Value = &luaSpanUD{span: sp}

	L.SetMetatable(spanUD, L.GetTypeMetatable(definitions.LuaUDSpan))

	// return a tiny context token (opaque); we don’t expose it as Lua value – keep API simple
	// Instead, we store latest context back to state for nesting convenience
	tr.state.Ctx = sctx

	return stack.PushResults(spanUD, lua.LNil)
}

func tracerWithSpan(L *lua.LState) int {
	ensureSpanMT(L)

	stack := luastack.NewManager(L)

	ud := stack.CheckUserData(1)
	if ud == nil {
		L.ArgError(1, "tracer expected")

		return 0
	}

	tr, ok := ud.Value.(*luaTracerUD)
	if !ok || tr == nil {
		L.ArgError(1, "tracer expected")

		return 0
	}

	name := stack.CheckString(2)
	fn := L.CheckFunction(3)

	var opts *lua.LTable

	if stack.GetTop() >= 4 {
		opts = L.OptTable(4, nil)
	}

	if !tr.state.enabled {
		// no-op: call fn without span
		base := stack.GetTop()
		L.Push(fn)

		if err := L.PCall(0, lua.MultRet, nil); err != nil {
			L.RaiseError("%s", err.Error())
		}

		return stack.GetTop() - base
	}

	kind := spanKindFromOpts(opts)
	attrs := attrsFromTable(L, tblField(opts, "attributes"))
	links := linksFromTable(L, tblField(opts, "links"))

	tracer := tr.state.tracerFor(tr.scope)
	parent := tr.state.Ctx
	sctx, sp := tracer.Start(parent, name, append([]trace.SpanStartOption{trace.WithSpanKind(kind)}, trace.WithLinks(links...))...)

	if len(attrs) > 0 {
		sp.SetAttributes(attrs...)
	}

	// Set new context during call
	prev := tr.state.Ctx
	tr.state.Ctx = sctx

	// Make span available to function as first argument
	spanUD := L.NewUserData()
	spanUD.Value = &luaSpanUD{span: sp}
	L.SetMetatable(spanUD, L.GetTypeMetatable(definitions.LuaUDSpan))

	base := stack.GetTop()
	L.Push(fn)
	L.Push(spanUD)
	err := L.PCall(1, lua.MultRet, nil)

	// Restore context and end span
	tr.state.Ctx = prev
	sp.End()

	if err != nil {
		// propagate error
		L.RaiseError("%s", err.Error())
	}

	return stack.GetTop() - base
}

// --- Span userdata ---

type luaSpanUD struct {
	span trace.Span
}

func spanSetAttribute(L *lua.LState) int {
	stack := luastack.NewManager(L)

	ud := stack.CheckUserData(1)
	if ud == nil {
		L.ArgError(1, "span expected")

		return 0
	}

	lsp, ok := ud.Value.(*luaSpanUD)
	if !ok || lsp == nil || lsp.span == nil {
		L.ArgError(1, "span expected")

		return 0
	}

	k := stack.CheckString(2)
	v := stack.CheckAny(3)

	if kv, ok := kvFromLValue(k, v); ok {
		lsp.span.SetAttributes(kv)
	}

	return 0
}

func spanSetAttributes(L *lua.LState) int {
	stack := luastack.NewManager(L)

	ud := stack.CheckUserData(1)
	if ud == nil {
		L.ArgError(1, "span expected")

		return 0
	}

	lsp, ok := ud.Value.(*luaSpanUD)
	if !ok || lsp == nil || lsp.span == nil {
		L.ArgError(1, "span expected")

		return 0
	}

	tbl := stack.CheckTable(2)
	attrs := attrsFromTable(L, tbl)

	if len(attrs) > 0 {
		lsp.span.SetAttributes(attrs...)
	}

	return 0
}

func spanAddEvent(L *lua.LState) int {
	stack := luastack.NewManager(L)

	ud := stack.CheckUserData(1)
	if ud == nil {
		L.ArgError(1, "span expected")

		return 0
	}

	lsp, ok := ud.Value.(*luaSpanUD)
	if !ok || lsp == nil || lsp.span == nil {
		L.ArgError(1, "span expected")

		return 0
	}

	name := stack.CheckString(2)

	var attrs []attribute.KeyValue

	if stack.GetTop() >= 3 {
		attrs = attrsFromTable(L, stack.CheckTable(3))
	}

	lsp.span.AddEvent(name, trace.WithAttributes(attrs...))

	return 0
}

func spanSetStatus(L *lua.LState) int {
	stack := luastack.NewManager(L)

	ud := stack.CheckUserData(1)
	if ud == nil {
		L.ArgError(1, "span expected")

		return 0
	}

	lsp, ok := ud.Value.(*luaSpanUD)
	if !ok || lsp == nil || lsp.span == nil {
		L.ArgError(1, "span expected")

		return 0
	}

	codeStr := strings.ToLower(stack.CheckString(2))

	var desc string

	if stack.GetTop() >= 3 {
		desc = stack.CheckString(3)
	}

	var c codes.Code

	switch codeStr {
	case "ok":
		c = codes.Ok
	case "error":
		c = codes.Error
	default:
		c = codes.Unset
	}

	lsp.span.SetStatus(c, desc)

	return 0
}

func spanRecordError(L *lua.LState) int {
	stack := luastack.NewManager(L)

	ud := stack.CheckUserData(1)
	if ud == nil {
		L.ArgError(1, "span expected")

		return 0
	}

	lsp, ok := ud.Value.(*luaSpanUD)
	if !ok || lsp == nil || lsp.span == nil {
		L.ArgError(1, "span expected")

		return 0
	}

	v := stack.CheckAny(2)
	if v == lua.LNil {
		return 0
	}

	errStr := strings.TrimSpace(v.String())
	if errStr == "" || errStr == "redis: nil" || errStr == "nil" {
		return 0
	}

	lsp.span.RecordError(&luaErr{msg: errStr})
	lsp.span.SetStatus(codes.Error, errStr)

	return 0
}

func spanEnd(L *lua.LState) int {
	stack := luastack.NewManager(L)

	ud := stack.CheckUserData(1)
	if ud == nil {
		L.ArgError(1, "span expected")

		return 0
	}

	lsp, ok := ud.Value.(*luaSpanUD)
	if !ok || lsp == nil || lsp.span == nil {
		L.ArgError(1, "span expected")

		return 0
	}

	lsp.span.End()

	return 0
}

// --- Utilities ---

type luaErr struct{ msg string }

func (e *luaErr) Error() string { return e.msg }

func spanKindFromOpts(opts *lua.LTable) trace.SpanKind {
	if opts == nil {
		return trace.SpanKindInternal
	}

	if k := opts.RawGetString("kind"); k != lua.LNil {
		switch strings.ToLower(k.String()) {
		case "client":
			return trace.SpanKindClient
		case "server":
			return trace.SpanKindServer
		case "producer":
			return trace.SpanKindProducer
		case "consumer":
			return trace.SpanKindConsumer
		}
	}

	return trace.SpanKindInternal
}

func kvFromLValue(k string, v lua.LValue) (attribute.KeyValue, bool) {
	switch tv := v.(type) {
	case lua.LString:
		return attribute.String(k, string(tv)), true
	case lua.LNumber:
		return attribute.Float64(k, float64(tv)), true
	case lua.LBool:
		return attribute.Bool(k, bool(tv)), true
	default:
		return attribute.KeyValue{}, false
	}
}

func attrsFromTable(_ *lua.LState, tbl *lua.LTable) []attribute.KeyValue {
	if tbl == nil {
		return nil
	}

	out := make([]attribute.KeyValue, 0, tbl.Len())
	tbl.ForEach(func(k, v lua.LValue) {
		ks, ok := k.(lua.LString)
		if !ok {
			return
		}
		if kv, good := kvFromLValue(string(ks), v); good {
			out = append(out, kv)
		}
	})

	return out
}

func tblField(tbl *lua.LTable, key string) *lua.LTable {
	if tbl == nil {
		return nil
	}

	v := tbl.RawGetString(key)
	if t, ok := v.(*lua.LTable); ok {
		return t
	}

	return nil
}

func linksFromTable(L *lua.LState, arr *lua.LTable) []trace.Link {
	if arr == nil {
		return nil
	}

	links := make([]trace.Link, 0, arr.Len())
	arr.ForEach(func(_ lua.LValue, v lua.LValue) {
		t, ok := v.(*lua.LTable)
		if !ok {
			return
		}

		tid := strings.TrimSpace(t.RawGetString("trace_id").String())
		sid := strings.TrimSpace(t.RawGetString("span_id").String())

		var sc trace.SpanContext

		if id, err := trace.TraceIDFromHex(tid); err == nil {
			if spid, err := trace.SpanIDFromHex(sid); err == nil {
				sc = trace.NewSpanContext(trace.SpanContextConfig{TraceID: id, SpanID: spid})
			}
		}

		attrs := attrsFromTable(L, tblField(t, "attributes"))
		if sc.IsValid() {
			links = append(links, trace.Link{SpanContext: sc, Attributes: attrs})
		}
	})

	return links
}

// Dummy span for no-op mode to keep API stable
func newDummySpanUD(L *lua.LState) *lua.LUserData {
	ud := L.NewUserData()
	// Non-recording span keeps methods safe in no-op mode
	ud.Value = &luaSpanUD{span: trace.SpanFromContext(context.Background())}
	L.SetMetatable(ud, L.GetTypeMetatable(definitions.LuaUDSpan))

	return ud
}

// --- SemConv helpers (string-only) ---

func luaSemconvPeerService(L *lua.LState) int {
	stack := luastack.NewManager(L)
	val := stack.CheckString(1)
	tbl := L.NewTable()

	tbl.RawSetString("peer.service", lua.LString(val))

	return stack.PushResults(tbl, lua.LNil)
}

func luaSemconvHTTPClientAttrs(L *lua.LState) int {
	stack := luastack.NewManager(L)
	in := stack.CheckTable(1)
	out := L.NewTable()

	copyIfStr(in, out, "method", "http.method")
	copyIfStr(in, out, "url", "url.full")

	if v := in.RawGetString("status_code"); v != lua.LNil {
		out.RawSetString("http.status_code", v)
	}

	return stack.PushResults(out, lua.LNil)
}

func luaSemconvDBAttrs(L *lua.LState) int {
	stack := luastack.NewManager(L)
	in := stack.CheckTable(1)
	out := L.NewTable()

	copyIfStr(in, out, "system", "db.system")
	copyIfStr(in, out, "name", "db.name")
	copyIfStr(in, out, "operation", "db.operation")

	if v := in.RawGetString("statement"); v != lua.LNil {
		out.RawSetString("db.statement", v)
	}

	return stack.PushResults(out, lua.LNil)
}

func luaSemconvNetAttrs(L *lua.LState) int {
	stack := luastack.NewManager(L)
	in := stack.CheckTable(1)
	out := L.NewTable()

	copyIfStr(in, out, "peer_name", "server.address")
	copyIfStr(in, out, "peer_port", "server.port")

	return stack.PushResults(out, lua.LNil)
}

func copyIfStr(in *lua.LTable, out *lua.LTable, inKey, outKey string) {
	if v := in.RawGetString(inKey); v != lua.LNil {
		out.RawSetString(outKey, v)
	}
}

// Ensure metatables are registered when module is loaded
func init() { //nolint:gochecknoinits // module registration
	// We cannot create metatables without a state; ensure via LoaderModOTEL.
	// However, we rely on known type names declared in definitions.
	_ = time.Now() // silence unused imports if build tags strip otel
}
