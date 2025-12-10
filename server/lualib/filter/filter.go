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

package filter

import (
	"context"
	stderrs "errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib"
	bflib "github.com/croessner/nauthilus/server/lualib/bruteforce"
	"github.com/croessner/nauthilus/server/lualib/connmgr"
	"github.com/croessner/nauthilus/server/lualib/luapool"
	"github.com/croessner/nauthilus/server/lualib/redislib"
	"github.com/croessner/nauthilus/server/lualib/vmpool"
	"github.com/croessner/nauthilus/server/monitoring"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	lua "github.com/yuin/gopher-lua"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/sync/errgroup"
)

// LuaFilters holds pre-compiled Lua scripts for use across the application.
// It allows faster access and execution of frequently used scripts.
var LuaFilters *PreCompiledLuaFilters

// LoaderModBackend initializes and returns a Lua module containing backend-related functionalities for LuaState.
func LoaderModBackend(request *Request, backendResult **lualib.LuaBackendResult, removeAttributes *[]string) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnGetBackendServers:       GetBackendServersWithReq(request),
			definitions.LuaFnSelectBackendServer:     SelectBackendServerWithReq(request),
			definitions.LuaFnCheckBackendConnection:  CheckBackendConnectionWithMonitor(monitoring.NewMonitor()),
			definitions.LuaFnApplyBackendResult:      ApplyBackendResultWithPtr(backendResult),
			definitions.LuaFnRemoveFromBackendResult: RemoveFromBackendResultWithList(removeAttributes),
		})

		L.Push(mod)

		return 1
	}
}

// PreCompileLuaFilters prepares and pre-compiles Lua filters based on the configuration, ensuring optimized filter execution.
// Returns an error if pre-compilation fails or configuration is missing.
// Initializes or resets the global LuaFilters container, adding compiled Lua filters sequentially.
func PreCompileLuaFilters() (err error) {
	tr := monittrace.New("nauthilus/filters")
	ctx, sp := tr.Start(context.Background(), "filters.precompile_all",
		attribute.Int("configured", func() int {
			if config.GetFile().HaveLuaFilters() {
				return len(config.GetFile().GetLua().GetFilters())
			}
			return 0
		}()),
	)

	_ = ctx

	defer sp.End()

	if config.GetFile().HaveLuaFilters() {
		if LuaFilters == nil {
			LuaFilters = &PreCompiledLuaFilters{}
		} else {
			LuaFilters.Reset()
		}

		for index := range config.GetFile().GetLua().GetFilters() {
			var luaFilter *LuaFilter

			cfg := config.GetFile().GetLua().GetFilters()[index]

			luaFilter, err = NewLuaFilter(cfg.Name, cfg.ScriptPath)
			if err != nil {
				sp.RecordError(err)

				return err
			}

			// Apply execution flags with sane defaults for backward compatibility
			wa := cfg.WhenAuthenticated
			wu := cfg.WhenUnauthenticated
			wn := cfg.WhenNoAuth

			if !wa && !wu && !wn {
				// No flags specified in config → run in authenticated and unauthenticated by default
				wa = true
				wu = true
				wn = false
			}

			luaFilter.WhenAuthenticated = wa
			luaFilter.WhenUnauthenticated = wu
			luaFilter.WhenNoAuth = wn

			// Add compiled Lua Filters.
			LuaFilters.Add(luaFilter)
		}
	}

	return nil
}

// PreCompiledLuaFilters represents a collection of precompiled Lua scripts
// along with a mutex for handling concurrent access to the script data.
type PreCompiledLuaFilters struct {
	// LuaScripts is a slice of pointers to LuaFilter,
	// each of which represents a precompiled Lua script.
	LuaScripts []*LuaFilter

	// Mu is a read/write mutex used to allow safe concurrent access to the LuaScripts.
	Mu sync.RWMutex
}

// Add appends a LuaFilter to the LuaScripts slice while ensuring thread-safe access using a mutex.
func (a *PreCompiledLuaFilters) Add(luaFilter *LuaFilter) {
	a.Mu.Lock()

	defer a.Mu.Unlock()

	a.LuaScripts = append(a.LuaScripts, luaFilter)
}

// Reset clears the LuaScripts slice of a PreCompiledLuaFilters object.The method also prevents race conditions
// by Locking the Mutex before executing, and Unlocking once it has finished. Existing entries in the slice are discarded.
func (a *PreCompiledLuaFilters) Reset() {
	a.Mu.Lock()

	defer a.Mu.Unlock()

	a.LuaScripts = make([]*LuaFilter, 0)
}

// LuaFilter represents a struct for managing Lua filters.
// It contains fields for filter name and a compiled Lua script.
type LuaFilter struct {
	// Name is a string that represents the name of the Lua filter.
	Name string

	// CompiledScript is a pointer to a FunctionProto struct from the go-lua package.
	// It represents a compiled Lua function that can be executed by a Lua VM.
	CompiledScript *lua.FunctionProto

	// Execution flags: control in which authentication states this filter should run
	WhenAuthenticated   bool
	WhenUnauthenticated bool
	WhenNoAuth          bool
}

// NewLuaFilter creates a new LuaFilter with the provided name and scriptPath by compiling the Lua script.
// Returns an error if the name or scriptPath is empty, or if there is a failure during script compilation.
func NewLuaFilter(name string, scriptPath string) (*LuaFilter, error) {
	if name == "" {
		return nil, errors.ErrFilterLuaNameMissing
	}

	if scriptPath == "" {
		return nil, errors.ErrFilterLuaScriptPathEmpty
	}

	compiledScript, err := lualib.CompileLua(scriptPath)
	if err != nil {
		return nil, err
	}

	return &LuaFilter{
		Name:           name,
		CompiledScript: compiledScript,
	}, nil
}

// Request represents a structure used for handling and processing requests within the system.
type Request struct {
	// BackendServers holds a list of backend server configurations that are used for handling requests.
	BackendServers []*config.BackendServer

	// UsedBackendAddress indicates the specific backend server address selected for processing the current request.
	UsedBackendAddress *string

	// UsedBackendPort represents the port of the backend server that was used for the current request execution.
	UsedBackendPort *int

	// Log is used to capture logging information.
	Logs *lualib.CustomLogKeyValue

	// Context includes context data from the caller.
	*lualib.Context

	// CommonRequest represents a common request object with various properties used in different functionalities.
	*lualib.CommonRequest
}

// handleError logs Lua execution errors for filters with stacktrace when available,
// stops the running timer and cancels the Lua context to abort pending operations.
func (r *Request) handleError(luaCancel context.CancelFunc, err error, scriptName string, stopTimer func()) {
	// Try to include Lua stacktrace for easier diagnostics
	var ae *lua.ApiError
	if stderrs.As(err, &ae) && ae != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, func() string {
				if r != nil && r.CommonRequest != nil {
					return r.CommonRequest.Session
				}

				return ""
			}(),
			"name", scriptName,
			definitions.LogKeyMsg, "Lua filter failed",
			definitions.LogKeyError, ae.Error(),
			"stacktrace", ae.StackTrace,
		)
	}

	if stopTimer != nil {
		stopTimer()
	}

	if luaCancel != nil {
		luaCancel()
	}
}

// The userData constellation method:
func newLuaBackendServer(userData *lua.LUserData) *config.BackendServer {
	if v, ok := userData.Value.(*config.BackendServer); ok {
		return v
	}

	return nil
}

// The metamethod for the __index field of the metatable
func indexMethod(L *lua.LState) int {
	userData := L.CheckUserData(1)
	field := L.CheckString(2)

	server := newLuaBackendServer(userData)
	if server == nil {
		return 0
	}

	switch field {
	case "protocol":
		L.Push(lua.LString(server.Protocol))
	case "host":
		L.Push(lua.LString(server.Host))
	case "port":
		L.Push(lua.LNumber(server.Port))
	case "request_uri":
		L.Push(lua.LString(server.RequestURI))
	case "test_username":
		L.Push(lua.LString(server.TestUsername))
	case "test_password":
		L.Push(lua.LString(server.TestPassword))
	case "haproxy_v2":
		L.Push(lua.LBool(server.HAProxyV2))
	case "tls":
		L.Push(lua.LBool(server.TLS))
	case "tls_skip_verify":
		L.Push(lua.LBool(server.TLSSkipVerify))
	case "deep_check":
		L.Push(lua.LBool(server.DeepCheck))
	default:
		return 0 // The field does not exist
	}

	return 1 // Number of return values
}

// getBackendServers creates a Lua function that returns a table of backend server configurations as userdata.
func getBackendServers(backendServers []*config.BackendServer) lua.LGFunction {
	return func(L *lua.LState) int {
		servers := L.NewTable()

		// Create the metatable
		mt := L.NewTypeMetatable(definitions.LuaBackendServerTypeName)

		L.SetField(mt, "__index", L.NewFunction(indexMethod))

		for _, backendServer := range backendServers {
			if backendServer == nil {
				continue
			}

			// Create an userdata and set its metatable
			serverUserData := L.NewUserData()
			serverUserData.Value = backendServer

			L.SetMetatable(serverUserData, L.GetTypeMetatable(definitions.LuaBackendServerTypeName))

			// Add userdata into the servers table
			servers.Append(serverUserData)
		}

		L.Push(servers)

		return 1
	}
}

// selectBackendServer returns a Lua function that assigns a server address and port from Lua state arguments.
func selectBackendServer(server **string, port **int) lua.LGFunction {
	return func(L *lua.LState) int {
		if L.GetTop() != 2 {
			L.ArgError(2, "expected server (string) and port (number)")

			return 0
		}

		serverValue := L.CheckString(1)
		portValue := L.CheckInt(2)

		*server = &serverValue
		*port = &portValue

		return 0
	}
}

// applyBackendResult merges attributes from the provided Lua userdata into the existing backendResult
// instead of reassigning the pointer. This ensures the per-filter accumulator referenced elsewhere
// (e.g., in filtResult) sees the applied changes.
func applyBackendResult(backendResult **lualib.LuaBackendResult) lua.LGFunction {
	return func(L *lua.LState) int {
		userData := L.CheckUserData(1)

		luaBackendResult, ok := userData.Value.(*lualib.LuaBackendResult)
		if !ok {
			L.ArgError(1, "expected lua backend_result")

			return 0
		}

		// Ensure destination exists
		if *backendResult == nil {
			*backendResult = &lualib.LuaBackendResult{Attributes: make(map[any]any)}
		}

		if (*backendResult).Attributes == nil {
			(*backendResult).Attributes = make(map[any]any)
		}

		// Merge attributes (overwrite on conflict)
		if luaBackendResult != nil {
			for k, v := range luaBackendResult.Attributes {
				(*backendResult).Attributes[k] = v
			}
		}

		return 0
	}
}

// removeFromBackendResult is a Lua function generator that populates a given slice with strings
// from a Lua table passed as an argument. If the attributes slice is nil, the function does nothing.
func removeFromBackendResult(attributes *[]string) lua.LGFunction {
	return func(L *lua.LState) int {
		if attributes == nil {
			return 0
		}

		attributeTable := L.ToTable(1)

		attributeTable.ForEach(func(_, value lua.LValue) {
			*attributes = append(*attributes, value.String())
		})

		return 0
	}
}

// mergeMaps merges 2 maps into one. If same key exists in both maps, value from m2 is used.
func mergeMaps(m1, m2 map[any]any) map[any]any {
	result := make(map[any]any)

	for k, v := range m1 {
		result[k] = v
	}

	for k, v := range m2 {
		result[k] = v
	}

	return result
}

// CallFilterLua executes Lua filter scripts in parallel. It merges backend results and remove-attributes
// from all filters, returns action=true if any filter requested action, and returns the first error if any.
func (r *Request) CallFilterLua(ctx *gin.Context) (action bool, backendResult *lualib.LuaBackendResult, removeAttributes []string, err error) {
	tr := monittrace.New("nauthilus/filters")
	fctx, fsp := tr.Start(ctx.Request.Context(), "filters.call",
		attribute.String("service", func() string {
			if r != nil && r.CommonRequest != nil {
				return r.CommonRequest.Service
			}

			return ""
		}()),
		attribute.String("username", func() string {
			if r != nil && r.CommonRequest != nil {
				return r.CommonRequest.Username
			}

			return ""
		}()),
		attribute.Int("filters", func() int {
			if LuaFilters != nil {
				return len(LuaFilters.LuaScripts)
			}

			return 0
		}()),
	)

	// propagate context for downstream
	ctx.Request = ctx.Request.WithContext(fctx)

	defer func() {
		fsp.SetAttributes(
			attribute.Bool("result", action),
			attribute.Int("removed_attrs", len(removeAttributes)),
		)

		if err != nil {
			fsp.RecordError(err)
		}

		fsp.End()
	}()

	startTime := time.Now()

	defer func() {
		latency := time.Since(startTime)
		if r.Logs == nil {
			r.Logs = new(lualib.CustomLogKeyValue)
		}

		r.Logs.Set(definitions.LogKeyFilterLatency, util.FormatDurationMs(latency))
	}()

	if LuaFilters == nil || len(LuaFilters.LuaScripts) == 0 {
		return false, nil, nil, errors.ErrNoFiltersDefined
	}

	LuaFilters.Mu.RLock()
	defer LuaFilters.Mu.RUnlock()

	// Determine which filters should run based on request state
	mode := "unauthenticated"
	scripts := make([]*LuaFilter, 0)

	// Trace selection of applicable filters for the current mode
	sctx, selSpan := tr.Start(fctx, "filters.select_applicable")
	_ = sctx

	if r.CommonRequest != nil && r.CommonRequest.NoAuth {
		mode = "no_auth"

		for _, s := range LuaFilters.LuaScripts {
			if s.WhenNoAuth {
				scripts = append(scripts, s)
			}
		}
	} else if r.CommonRequest != nil && r.CommonRequest.Authenticated {
		mode = "authenticated"

		for _, s := range LuaFilters.LuaScripts {
			if s.WhenAuthenticated {
				scripts = append(scripts, s)
			}
		}

		selSpan.SetAttributes(
			attribute.String("mode", mode),
			attribute.Int("configured_total", len(LuaFilters.LuaScripts)),
			attribute.Int("runnable", len(scripts)),
		)
		selSpan.End()
	} else {
		mode = "unauthenticated"

		for _, s := range LuaFilters.LuaScripts {
			if s.WhenUnauthenticated {
				scripts = append(scripts, s)
			}
		}
	}

	if r.Logs == nil {
		r.Logs = new(lualib.CustomLogKeyValue)
	}

	r.Logs.Set("filter_mode", mode)

	// If no scripts should run in this mode, return early with empty aggregates
	if len(scripts) == 0 {
		mergedBackendResult := &lualib.LuaBackendResult{Attributes: make(map[any]any)}

		return false, mergedBackendResult, nil, nil
	}

	// Structure to collect per-filter results
	type filtResult struct {
		name            string
		action          bool
		ret             int
		err             error
		logs            lualib.CustomLogKeyValue
		statusText      **string
		backendResult   *lualib.LuaBackendResult
		removeAttrsList []string
	}

	var (
		mu      sync.Mutex
		results = make([]*filtResult, 0, len(scripts))
	)

	g, egCtx := errgroup.WithContext(ctx)

	pool := vmpool.GetManager().GetOrCreate("filter:default", vmpool.PoolOptions{MaxVMs: config.GetFile().GetLuaFilterVMPoolSize()})

	// Span to cover goroutine setup
	pstartCtx, pstart := tr.Start(fctx, "filters.parallel.start", attribute.Int("runnable", len(scripts)))
	_ = pstartCtx

	for _, script := range scripts {
		sc := script
		g.Go(func() error {
			// Per-script span
			sCtx, sSpan := tr.Start(fctx, "filters.script",
				attribute.String("name", sc.Name),
				attribute.String("mode", mode),
			)
			_ = sCtx

			// Per-filter state from bounded vmpool
			Llocal, acqErr := pool.Acquire(egCtx)
			if acqErr != nil {
				sSpan.RecordError(acqErr)
				sSpan.End()

				return acqErr
			}

			replaceVM := false
			defer func() {
				if r := recover(); r != nil {
					replaceVM = true
				}

				if replaceVM {
					pool.Replace(Llocal)
				} else {
					pool.Release(Llocal)
				}

				sSpan.End()
			}()

			// Local log and status to avoid races on r.Logs / r.StatusMessage
			localLogs := new(lualib.CustomLogKeyValue)
			var localStatus *string

			// Local backend result and remove-attributes that this filter may set
			localBackendResult := &lualib.LuaBackendResult{Attributes: make(map[any]any)}
			localRemoveAttrs := make([]string, 0)

			// Environment preparation span
			envCtx, envSpan := tr.Start(fctx, "filters.env.prepare",
				attribute.String("name", sc.Name),
			)
			_ = envCtx

			lualib.RegisterBackendResultType(Llocal, definitions.LuaBackendResultAttributes)

			// Globals for this state
			globals := Llocal.NewTable()

			globals.RawSet(lua.LString(definitions.LuaFilterAccept), lua.LBool(false))
			globals.RawSet(lua.LString(definitions.LuaFilterREJECT), lua.LBool(true))
			globals.RawSet(lua.LString(definitions.LuaFilterResultOk), lua.LNumber(0))
			globals.RawSet(lua.LString(definitions.LuaFilterResultFail), lua.LNumber(1))

			globals.RawSetString(definitions.LuaFnAddCustomLog, Llocal.NewFunction(lualib.AddCustomLog(localLogs)))
			globals.RawSetString(definitions.LuaFnSetStatusMessage, Llocal.NewFunction(lualib.SetStatusMessage(&localStatus)))

			Llocal.SetGlobal(definitions.LuaDefaultTable, globals)

			// Build request table
			request := Llocal.NewTable()

			r.CommonRequest.SetupRequest(request)

			// Timing and context
			stopTimer := stats.PrometheusTimer(definitions.PromFilter, sc.Name)

			luaCtx, luaCancel := context.WithTimeout(egCtx, viper.GetDuration(definitions.LogKeyLuaScripttimeout)*time.Second)
			defer luaCancel()

			Llocal.SetContext(luaCtx)

			// Prepare per-request environment so that request-local globals and module bindings are visible
			luapool.PrepareRequestEnv(Llocal)

			// Bind request-scoped modules into reqEnv so that require() resolves correctly.
			// 1) nauthilus_context
			if loader := lualib.LoaderModContext(r.Context); loader != nil {
				_ = loader(Llocal)
				if mod, ok := Llocal.Get(-1).(*lua.LTable); ok {
					Llocal.Pop(1)
					luapool.BindModuleIntoReq(Llocal, definitions.LuaModContext, mod)
				} else {
					Llocal.Pop(1)
				}
			}

			// 2) nauthilus_http_request
			if ctx != nil && ctx.Request != nil {
				loader := lualib.LoaderModHTTP(lualib.NewHTTPMetaFromRequest(ctx.Request))
				_ = loader(Llocal)
				if mod, ok := Llocal.Get(-1).(*lua.LTable); ok {
					Llocal.Pop(1)
					luapool.BindModuleIntoReq(Llocal, definitions.LuaModHTTPRequest, mod)
				} else {
					Llocal.Pop(1)
				}
			}

			// 3) nauthilus_http_response
			if ctx != nil {
				loader := lualib.LoaderModHTTPResponse(ctx)
				_ = loader(Llocal)
				if mod, ok := Llocal.Get(-1).(*lua.LTable); ok {
					Llocal.Pop(1)
					luapool.BindModuleIntoReq(Llocal, definitions.LuaModHTTPResponse, mod)
				} else {
					Llocal.Pop(1)
				}
			}

			// 4) nauthilus_redis
			if loader := redislib.LoaderModRedis(luaCtx); loader != nil {
				_ = loader(Llocal)
				if mod, ok := Llocal.Get(-1).(*lua.LTable); ok {
					Llocal.Pop(1)
					luapool.BindModuleIntoReq(Llocal, definitions.LuaModRedis, mod)
				} else {
					Llocal.Pop(1)
				}
			}

			// 5) nauthilus_ldap (optional)
			if config.GetFile().HaveLDAPBackend() {
				loader := backend.LoaderModLDAP(luaCtx)
				_ = loader(Llocal)
				if mod, ok := Llocal.Get(-1).(*lua.LTable); ok {
					Llocal.Pop(1)
					luapool.BindModuleIntoReq(Llocal, definitions.LuaModLDAP, mod)
				} else {
					Llocal.Pop(1)
				}
			}

			// 6) nauthilus_psnet (connection monitoring)
			if loader := connmgr.LoaderModPsnet(luaCtx); loader != nil {
				_ = loader(Llocal)
				if mod, ok := Llocal.Get(-1).(*lua.LTable); ok {
					Llocal.Pop(1)
					luapool.BindModuleIntoReq(Llocal, definitions.LuaModPsnet, mod)
				} else {
					Llocal.Pop(1)
				}
			}

			// 7) nauthilus_dns (DNS lookups)
			if loader := lualib.LoaderModDNS(luaCtx); loader != nil {
				_ = loader(Llocal)
				if mod, ok := Llocal.Get(-1).(*lua.LTable); ok {
					Llocal.Pop(1)
					luapool.BindModuleIntoReq(Llocal, definitions.LuaModDNS, mod)
				} else {
					Llocal.Pop(1)
				}
			}

			// 7.1) nauthilus_opentelemetry (OTel helpers for Lua)
			{
				var loader lua.LGFunction
				if config.GetFile().GetServer().GetInsights().GetTracing().IsEnabled() {
					loader = lualib.LoaderModOTEL(luaCtx)
				} else {
					loader = lualib.LoaderOTELStateless()
				}

				if loader != nil {
					_ = loader(Llocal)
					if mod, ok := Llocal.Get(-1).(*lua.LTable); ok {
						Llocal.Pop(1)
						luapool.BindModuleIntoReq(Llocal, definitions.LuaModOpenTelemetry, mod)
					} else {
						Llocal.Pop(1)
					}
				}
			}

			// 8) nauthilus_brute_force (toleration and blocking helpers)
			if loader := bflib.LoaderModBruteForce(luaCtx); loader != nil {
				_ = loader(Llocal)
				if mod, ok := Llocal.Get(-1).(*lua.LTable); ok {
					Llocal.Pop(1)
					luapool.BindModuleIntoReq(Llocal, definitions.LuaModBruteForce, mod)
				} else {
					Llocal.Pop(1)
				}
			}

			// 9) nauthilus_backend (preload stateless placeholder, then request-bound)
			Llocal.PreloadModule(definitions.LuaModBackend, LoaderBackendStateless())
			{
				loader := LoaderModBackend(r, &localBackendResult, &localRemoveAttrs)
				_ = loader(Llocal)
				if mod, ok := Llocal.Get(-1).(*lua.LTable); ok {
					Llocal.Pop(1)
					luapool.BindModuleIntoReq(Llocal, definitions.LuaModBackend, mod)
				} else {
					Llocal.Pop(1)
				}
			}

			envSpan.End()

			fr := &filtResult{name: sc.Name, statusText: &localStatus, backendResult: localBackendResult}

			// Execute script
			execCtx, execSpan := tr.Start(fctx, "filters.execute",
				attribute.String("name", sc.Name),
			)
			_ = execCtx

			if e := lualib.PackagePath(Llocal); e != nil {
				r.handleError(luaCancel, e, sc.Name, stopTimer)
				execSpan.RecordError(e)
				execSpan.End()

				return e
			}

			if e := lualib.DoCompiledFile(Llocal, sc.CompiledScript); e != nil {
				r.handleError(luaCancel, e, sc.Name, stopTimer)
				execSpan.RecordError(e)
				execSpan.End()

				return e
			}

			// Call filter function if present (reqEnv-first lookup)
			filterFunc := lua.LNil
			if v := Llocal.GetGlobal("__NAUTH_REQ_ENV"); v != nil && v.Type() == lua.LTTable {
				if fn := Llocal.GetField(v, definitions.LuaFnCallFilter); fn != nil {
					filterFunc = fn
				}
			}

			if filterFunc == lua.LNil {
				filterFunc = Llocal.GetGlobal(definitions.LuaFnCallFilter)
			}

			if filterFunc.Type() == lua.LTFunction {
				if e := Llocal.CallByParam(lua.P{Fn: filterFunc, NRet: 2, Protect: true}, request); e != nil {
					r.handleError(luaCancel, e, sc.Name, stopTimer)
					execSpan.RecordError(e)
					execSpan.End()

					return e
				}

				ret := Llocal.ToInt(-1)
				Llocal.Pop(1)
				takeAction := Llocal.ToBool(-1)
				Llocal.Pop(1)
				fr.ret = ret
				fr.action = takeAction

				execSpan.SetAttributes(
					attribute.Int("result", ret),
					attribute.Bool("action", takeAction),
				)
			}

			execSpan.End()

			// Snapshot local logs and remove-attrs for aggregation
			fr.logs = *localLogs
			fr.removeAttrsList = localRemoveAttrs

			// Emit debug log for this filter
			logs := []any{definitions.LogKeyGUID, r.Session, "name", sc.Name, definitions.LogKeyMsg, "Lua filter finished", "action", fr.action, "result", func() string {
				if fr.ret == 0 {
					return "ok"
				} else if fr.ret == 1 {
					return "fail"
				}

				return fmt.Sprintf("unknown(%d)", fr.ret)
			}()}

			if len(fr.logs) > 0 {
				for i := range fr.logs {
					logs = append(logs, fr.logs[i])
				}
			}

			util.DebugModule(definitions.DbgFilter, logs...)

			if stopTimer != nil {
				stopTimer()
			}

			mu.Lock()
			results = append(results, fr)
			mu.Unlock()

			return nil
		})
	}

	// End parallel start span after scheduling all goroutines
	pstart.End()

	// Wait span to cover synchronization
	wctx, wspan := tr.Start(fctx, "filters.parallel.wait")
	_ = wctx

	if e := g.Wait(); e != nil {
		wspan.RecordError(e)
		wspan.End()

		return false, nil, nil, e
	}

	wspan.SetAttributes(attribute.Int("completed", len(results)))
	wspan.End()

	// Aggregate results
	mctx, mspan := tr.Start(fctx, "filters.merge")
	_ = mctx

	mergedBackendResult := &lualib.LuaBackendResult{Attributes: make(map[any]any)}
	mergedRemoveAttributes := config.NewStringSet()

	var statusSet bool

	for _, fr := range results {
		if fr.action {
			action = true
		}

		if fr.backendResult != nil && len(fr.backendResult.Attributes) > 0 {
			mergedBackendResult.Attributes = mergeMaps(mergedBackendResult.Attributes, fr.backendResult.Attributes)
		}

		for _, attr := range fr.removeAttrsList {
			mergedRemoveAttributes.Set(attr)
		}

		// Merge per-filter status message and logs via common helper
		lualib.MergeStatusAndLogs(&statusSet, &r.Logs, &r.StatusMessage, *fr.statusText, fr.logs)
	}

	// After aggregating results, log rejected filters and per-filter return codes
	if r.Logs == nil {
		r.Logs = new(lualib.CustomLogKeyValue)
	}

	rejectedFilters := make([]string, 0)
	resultPairs := make([]string, 0, len(results))

	for _, fr := range results {
		if fr.action {
			rejectedFilters = append(rejectedFilters, fr.name)
		}

		status := "unknown("
		switch fr.ret {
		case 0:
			status = "ok"
		case 1:
			status = "fail"
		default:
			status = fmt.Sprintf("unknown(%d)", fr.ret)
		}

		resultPairs = append(resultPairs, fmt.Sprintf("%s:%s", fr.name, status))
	}

	if len(rejectedFilters) > 0 {
		r.Logs.Set(definitions.LogKeyRejectedFilters, strings.Join(rejectedFilters, ","))
	}

	if len(resultPairs) > 0 {
		r.Logs.Set(definitions.LogKeyFilterResults, strings.Join(resultPairs, ","))
	}

	// Finalize merge span with sizes
	mspan.SetAttributes(
		attribute.Int("merged_attrs", len(mergedBackendResult.Attributes)),
		attribute.Int("removed_attrs_unique", len(mergedRemoveAttributes.GetStringSlice())),
		attribute.Int("rejected_count", len(rejectedFilters)),
	)
	mspan.End()

	backendResult = mergedBackendResult
	removeAttributes = mergedRemoveAttributes.GetStringSlice()

	return action, backendResult, removeAttributes, nil
}
