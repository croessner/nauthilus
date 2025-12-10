package lualib

import (
	"context"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"

	lua "github.com/yuin/gopher-lua"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// --- Public module loaders ---

// LoaderModOTEL provides a context-aware OpenTelemetry Lua module.
// It binds helper functions and userdata to create and manage spans from Lua.
func LoaderModOTEL(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()

		// State holder (per-request)
		enabled := isTracingEnabled()
		lstate := &luaOTEL{ctx: ctx, enabled: enabled}

		// Ensure metatables are registered once per state
		ensureTracerMT(L)
		ensureSpanMT(L)

		// Register functions
		L.SetFuncs(mod, map[string]lua.LGFunction{
			"tracer":         lstate.luaTracer,
			"default_tracer": lstate.luaDefaultTracer,
			"is_enabled":     lstate.luaIsEnabled,
			// baggage
			"baggage_set":   lstate.luaBaggageSet,
			"baggage_get":   lstate.luaBaggageGet,
			"baggage_all":   lstate.luaBaggageAll,
			"baggage_clear": lstate.luaBaggageClear,
			// propagation
			"inject_headers":  lstate.luaInjectHeaders,
			"extract_headers": lstate.luaExtractHeaders,
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

		L.Push(mod)

		return 1
	}
}

// LoaderOTELStateless returns an empty module so require("nauthilus_opentelemetry") never fails.
func LoaderOTELStateless() lua.LGFunction {
	return func(L *lua.LState) int {
		L.Push(L.NewTable())

		return 1
	}
}

func isTracingEnabled() bool {
	if !config.IsFileLoaded() {
		return false
	}

	return config.GetFile().GetServer().GetInsights().GetTracing().IsEnabled()
}

// --- Internal state and helpers ---

type luaOTEL struct {
	ctx     context.Context
	enabled bool
}

func (s *luaOTEL) tracerFor(scope string) trace.Tracer {
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

func (s *luaOTEL) luaIsEnabled(L *lua.LState) int {
	L.Push(lua.LBool(s.enabled))

	return 1
}

func (s *luaOTEL) luaTracer(L *lua.LState) int {
	scope := L.CheckString(1)
	return s.pushTracer(L, scope)
}

func (s *luaOTEL) luaDefaultTracer(L *lua.LState) int {
	return s.pushTracer(L, "nauthilus/lua")
}

func (s *luaOTEL) pushTracer(L *lua.LState, scope string) int {
	ud := L.NewUserData()
	ud.Value = &luaTracerUD{state: s, scope: scope}
	L.SetMetatable(ud, L.GetTypeMetatable(definitions.LuaUDTracer))
	L.Push(ud)

	return 1
}

func (s *luaOTEL) luaBaggageSet(L *lua.LState) int {
	if !s.enabled { // no-op
		return 0
	}

	key := L.CheckString(1)
	val := L.CheckString(2)
	m := baggage.FromContext(s.ctx)
	mem, err := baggage.NewMember(key, val)
	if err == nil {
		nb, err2 := baggage.New(append(m.Members(), mem)...)
		if err2 == nil {
			s.ctx = baggage.ContextWithBaggage(s.ctx, nb)
		}
	}

	return 0
}

func (s *luaOTEL) luaBaggageGet(L *lua.LState) int {
	key := L.CheckString(1)
	m := baggage.FromContext(s.ctx)
	v := m.Member(key).Value()
	if v == "" {
		L.Push(lua.LNil)
	} else {
		L.Push(lua.LString(v))
	}

	return 1
}

func (s *luaOTEL) luaBaggageAll(L *lua.LState) int {
	tbl := L.NewTable()
	m := baggage.FromContext(s.ctx)
	for _, mem := range m.Members() {
		tbl.RawSetString(mem.Key(), lua.LString(mem.Value()))
	}
	L.Push(tbl)

	return 1
}

func (s *luaOTEL) luaBaggageClear(L *lua.LState) int {
	if !s.enabled {
		return 0
	}

	if nb, err := baggage.New(); err == nil {
		s.ctx = baggage.ContextWithBaggage(s.ctx, nb)
	}

	return 0
}

func (s *luaOTEL) luaInjectHeaders(L *lua.LState) int {
	if !s.enabled {
		return 0
	}

	tbl := L.CheckTable(1)
	carrier := textMapCarrier{tbl}
	otel.GetTextMapPropagator().Inject(s.ctx, carrier)

	return 0
}

func (s *luaOTEL) luaExtractHeaders(L *lua.LState) int {
	if !s.enabled {
		return 0
	}

	tbl := L.CheckTable(1)
	carrier := textMapCarrier{tbl}
	ctx := otel.GetTextMapPropagator().Extract(s.ctx, carrier)
	s.ctx = ctx

	return 0
}

// --- Tracer userdata ---

type luaTracerUD struct {
	state *luaOTEL
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
		"end":            spanEnd,
	}))
}

func tracerStartSpan(L *lua.LState) int {
	ensureSpanMT(L)
	ud := L.CheckUserData(1)
	tr, ok := ud.Value.(*luaTracerUD)
	if !ok {
		return 0
	}

	name := L.CheckString(2)
	var opts *lua.LTable
	if L.GetTop() >= 3 {
		opts = L.OptTable(3, nil)
	}

	// Build options
	kind := spanKindFromOpts(opts)
	attrs := attrsFromTable(L, tblField(opts, "attributes"))

	// Links (optional)
	links := linksFromTable(L, tblField(opts, "links"))

	ctx := tr.state.ctx
	if !tr.state.enabled {
		// Return a dummy span userdata to keep API stable
		L.Push(newDummySpanUD(L))
		L.Push(lua.LNil)

		return 2
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
	L.Push(spanUD)

	// return a tiny context token (opaque); we don’t expose it as Lua value – keep API simple
	// Instead, we store latest context back to state for nesting convenience
	tr.state.ctx = sctx
	L.Push(lua.LNil)

	return 2
}

func tracerWithSpan(L *lua.LState) int {
	ensureSpanMT(L)
	ud := L.CheckUserData(1)
	tr, ok := ud.Value.(*luaTracerUD)
	if !ok {
		return 0
	}

	name := L.CheckString(2)
	fn := L.CheckFunction(3)
	var opts *lua.LTable
	if L.GetTop() >= 4 {
		opts = L.OptTable(4, nil)
	}

	if !tr.state.enabled {
		// no-op: call fn without span
		base := L.GetTop()
		L.Push(fn)
		if err := L.PCall(0, lua.MultRet, nil); err != nil {
			L.RaiseError("%s", err.Error())
		}
		return L.GetTop() - base
	}

	kind := spanKindFromOpts(opts)
	attrs := attrsFromTable(L, tblField(opts, "attributes"))
	links := linksFromTable(L, tblField(opts, "links"))

	tracer := tr.state.tracerFor(tr.scope)
	parent := tr.state.ctx
	sctx, sp := tracer.Start(parent, name, append([]trace.SpanStartOption{trace.WithSpanKind(kind)}, trace.WithLinks(links...))...)
	if len(attrs) > 0 {
		sp.SetAttributes(attrs...)
	}

	// Set new context during call
	prev := tr.state.ctx
	tr.state.ctx = sctx

	// Make span available to function as first argument
	spanUD := L.NewUserData()
	spanUD.Value = &luaSpanUD{span: sp}
	L.SetMetatable(spanUD, L.GetTypeMetatable(definitions.LuaUDSpan))

	base := L.GetTop()
	L.Push(fn)
	L.Push(spanUD)
	err := L.PCall(1, lua.MultRet, nil)

	// Restore context and end span
	tr.state.ctx = prev
	sp.End()

	if err != nil {
		// propagate error
		L.RaiseError("%s", err.Error())
	}

	return L.GetTop() - base
}

// --- Span userdata ---

type luaSpanUD struct {
	span trace.Span
}

func spanSetAttribute(L *lua.LState) int {
	ud := L.CheckUserData(1)
	lsp, ok := ud.Value.(*luaSpanUD)
	if !ok || lsp.span == nil {
		return 0
	}

	k := L.CheckString(2)
	v := L.CheckAny(3)
	if kv, ok := kvFromLValue(k, v); ok {
		lsp.span.SetAttributes(kv)
	}

	return 0
}

func spanSetAttributes(L *lua.LState) int {
	ud := L.CheckUserData(1)
	lsp, ok := ud.Value.(*luaSpanUD)
	if !ok || lsp.span == nil {
		return 0
	}

	tbl := L.CheckTable(2)
	attrs := attrsFromTable(L, tbl)
	if len(attrs) > 0 {
		lsp.span.SetAttributes(attrs...)
	}

	return 0
}

func spanAddEvent(L *lua.LState) int {
	ud := L.CheckUserData(1)
	lsp, ok := ud.Value.(*luaSpanUD)
	if !ok || lsp.span == nil {
		return 0
	}

	name := L.CheckString(2)
	var attrs []attribute.KeyValue
	if L.GetTop() >= 3 {
		attrs = attrsFromTable(L, L.CheckTable(3))
	}
	lsp.span.AddEvent(name, trace.WithAttributes(attrs...))

	return 0
}

func spanSetStatus(L *lua.LState) int {
	ud := L.CheckUserData(1)
	lsp, ok := ud.Value.(*luaSpanUD)
	if !ok || lsp.span == nil {
		return 0
	}

	codeStr := strings.ToLower(L.CheckString(2))
	var desc string
	if L.GetTop() >= 3 {
		desc = L.CheckString(3)
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
	ud := L.CheckUserData(1)
	lsp, ok := ud.Value.(*luaSpanUD)
	if !ok || lsp.span == nil {
		return 0
	}

	v := L.CheckAny(2)
	switch vv := v.(type) {
	case lua.LString:
		lsp.span.RecordError(&luaErr{msg: string(vv)})
		lsp.span.SetStatus(codes.Error, string(vv))
	default:
		lsp.span.RecordError(&luaErr{msg: vv.String()})
		lsp.span.SetStatus(codes.Error, vv.String())
	}

	return 0
}

func spanEnd(L *lua.LState) int {
	ud := L.CheckUserData(1)
	lsp, ok := ud.Value.(*luaSpanUD)
	if !ok || lsp.span == nil {
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

func attrsFromTable(L *lua.LState, tbl *lua.LTable) []attribute.KeyValue {
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
	val := L.CheckString(1)
	tbl := L.NewTable()
	tbl.RawSetString("peer.service", lua.LString(val))
	L.Push(tbl)

	return 1
}

func luaSemconvHTTPClientAttrs(L *lua.LState) int {
	in := L.CheckTable(1)
	out := L.NewTable()
	copyIfStr(in, out, "method", "http.method")
	copyIfStr(in, out, "url", "url.full")
	if v := in.RawGetString("status_code"); v != lua.LNil {
		out.RawSetString("http.status_code", v)
	}
	L.Push(out)

	return 1
}

func luaSemconvDBAttrs(L *lua.LState) int {
	in := L.CheckTable(1)
	out := L.NewTable()
	copyIfStr(in, out, "system", "db.system")
	copyIfStr(in, out, "name", "db.name")
	copyIfStr(in, out, "operation", "db.operation")
	if v := in.RawGetString("statement"); v != lua.LNil {
		out.RawSetString("db.statement", v)
	}
	L.Push(out)

	return 1
}

func luaSemconvNetAttrs(L *lua.LState) int {
	in := L.CheckTable(1)
	out := L.NewTable()
	copyIfStr(in, out, "peer_name", "server.address")
	copyIfStr(in, out, "peer_port", "server.port")
	L.Push(out)

	return 1
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
