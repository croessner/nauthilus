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
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/luapool"
	"github.com/croessner/nauthilus/server/monitoring"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	lua "github.com/yuin/gopher-lua"
	"golang.org/x/sync/errgroup"
)

// httpClient is a pre-configured instance of http.Client with custom timeout and TLS settings for making HTTP requests.
var httpClient *http.Client

// InitHTTPClient initializes the global httpClient variable with a pre-configured instance from util.NewHTTPClient.
func InitHTTPClient() {
	httpClient = util.NewHTTPClient()
}

// registerDynamicLoader sets up a global function "dynamic_loader" in the Lua state to dynamically load Lua modules.
func registerDynamicLoader(L *lua.LState, ctx *gin.Context, r *Request, backendResult **lualib.LuaBackendResult, removeAttributes *[]string) {
	dynamicLoader := L.NewFunction(func(L *lua.LState) int {
		modName := L.CheckString(1)

		registry := make(map[string]bool)
		if _, found := registry[modName]; found {
			return 0
		}

		lualib.RegisterCommonLuaLibraries(L, ctx, modName, registry, httpClient)
		registerModule(L, ctx, r, modName, registry, backendResult, removeAttributes)

		return 0
	})

	L.SetGlobal("dynamic_loader", dynamicLoader)
}

// registerModule registers a Lua module in the given Lua state if it matches predefined module names.
// It also ensures the module is added to the registry map to prevent duplicate registrations.
// Modules include context, HTTP request, LDAP, and backend, with validation for dependencies.
func registerModule(L *lua.LState, ctx *gin.Context, r *Request, modName string, registry map[string]bool, backendResult **lualib.LuaBackendResult, removeAttributes *[]string) {
	switch modName {
	case definitions.LuaModContext:
		L.PreloadModule(modName, lualib.LoaderModContext(r.Context))
	case definitions.LuaModHTTPRequest:
		L.PreloadModule(modName, lualib.LoaderModHTTPRequest(ctx.Request))
	case definitions.LuaModHTTPResponse:
		L.PreloadModule(modName, lualib.LoaderModHTTPResponse(ctx.Writer))
	case definitions.LuaModLDAP:
		if config.GetFile().HaveLDAPBackend() {
			L.PreloadModule(modName, backend.LoaderModLDAP(ctx))
		} else {
			L.RaiseError("LDAP backend not activated")
		}
	case definitions.LuaModBackend:
		L.PreloadModule(modName, LoaderModBackend(r, backendResult, removeAttributes))
	default:
		return
	}

	registry[modName] = true
}

// LuaFilters holds pre-compiled Lua scripts for use across the application.
// It allows faster access and execution of frequently used scripts.
var LuaFilters *PreCompiledLuaFilters

// LoaderModBackend initializes and returns a Lua module containing backend-related functionalities for LuaState.
func LoaderModBackend(request *Request, backendResult **lualib.LuaBackendResult, removeAttributes *[]string) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnGetBackendServers:       getBackendServers(request.BackendServers),
			definitions.LuaFnSelectBackendServer:     selectBackendServer(&request.UsedBackendAddress, &request.UsedBackendPort),
			definitions.LuaFnCheckBackendConnection:  lualib.CheckBackendConnection(monitoring.NewMonitor()),
			definitions.LuaFnApplyBackendResult:      applyBackendResult(backendResult),
			definitions.LuaFnRemoveFromBackendResult: removeFromBackendResult(removeAttributes),
		})

		L.Push(mod)

		return 1
	}
}

// PreCompileLuaFilters prepares and pre-compiles Lua filters based on the configuration, ensuring optimized filter execution.
// Returns an error if pre-compilation fails or configuration is missing.
// Initializes or resets the global LuaFilters container, adding compiled Lua filters sequentially.
func PreCompileLuaFilters() (err error) {
	if config.GetFile().HaveLuaFilters() {
		if LuaFilters == nil {
			LuaFilters = &PreCompiledLuaFilters{}
		} else {
			LuaFilters.Reset()
		}

		for index := range config.GetFile().GetLua().Filters {
			var luaFilter *LuaFilter

			luaFilter, err = NewLuaFilter(config.GetFile().GetLua().Filters[index].Name, config.GetFile().GetLua().Filters[index].ScriptPath)
			if err != nil {
				return err
			}

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

// applyBackendResult sets the backendResult pointer to the value from Lua userdata if it's of type LuaBackendResult.
func applyBackendResult(backendResult **lualib.LuaBackendResult) lua.LGFunction {
	return func(L *lua.LState) int {
		userData := L.CheckUserData(1)

		if luaBackendResult, assertOk := userData.Value.(*lualib.LuaBackendResult); assertOk {
			*backendResult = luaBackendResult
		} else {
			L.ArgError(1, "expected lua backend_result")
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
	startTime := time.Now()
	defer func() {
		latency := time.Since(startTime)
		if r.Logs == nil {
			r.Logs = new(lualib.CustomLogKeyValue)
		}

		r.Logs.Set(definitions.LogKeyFilterLatency, fmt.Sprintf("%v", latency))
	}()

	if LuaFilters == nil || len(LuaFilters.LuaScripts) == 0 {
		return false, nil, nil, errors.ErrNoFiltersDefined
	}

	LuaFilters.Mu.RLock()
	defer LuaFilters.Mu.RUnlock()

	// Structure to collect per-filter results
	type filtResult struct {
		name            string
		action          bool
		ret             int
		err             error
		logs            lualib.CustomLogKeyValue
		statusText      *string
		backendResult   *lualib.LuaBackendResult
		removeAttrsList []string
	}

	var (
		mu      sync.Mutex
		results = make([]*filtResult, 0, len(LuaFilters.LuaScripts))
	)

	g, egCtx := errgroup.WithContext(ctx)

	for _, script := range LuaFilters.LuaScripts {
		sc := script
		g.Go(func() error {
			// Per-filter state
			Llocal := luapool.Get()
			defer luapool.Put(Llocal)

			// Local log and status to avoid races on r.Logs / r.StatusMessage
			localLogs := new(lualib.CustomLogKeyValue)
			var localStatus *string

			// Local backend result and remove-attributes that this filter may set
			localBackendResult := &lualib.LuaBackendResult{Attributes: make(map[any]any)}
			localRemoveAttrs := make([]string, 0)

			// Register dynamic loader and backend result type for this state
			registerDynamicLoader(Llocal, ctx, r, &localBackendResult, &localRemoveAttrs)
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

			fr := &filtResult{name: sc.Name, statusText: localStatus, backendResult: localBackendResult}

			// Execute script
			if e := lualib.PackagePath(Llocal); e != nil {
				if stopTimer != nil {
					stopTimer()
				}

				return e
			}

			if e := lualib.DoCompiledFile(Llocal, sc.CompiledScript); e != nil {
				if stopTimer != nil {
					stopTimer()
				}

				return e
			}

			// Call filter function if present
			filterFunc := Llocal.GetGlobal(definitions.LuaFnCallFilter)
			if filterFunc.Type() == lua.LTFunction {
				if e := Llocal.CallByParam(lua.P{Fn: filterFunc, NRet: 2, Protect: true}, request); e != nil {
					if stopTimer != nil {
						stopTimer()
					}

					return e
				}

				ret := Llocal.ToInt(-1)
				Llocal.Pop(1)
				takeAction := Llocal.ToBool(-1)
				Llocal.Pop(1)
				fr.ret = ret
				fr.action = takeAction
			}

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

	if e := g.Wait(); e != nil {
		return false, nil, nil, e
	}

	// Aggregate results
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
		lualib.MergeStatusAndLogs(&statusSet, &r.Logs, &r.StatusMessage, fr.statusText, fr.logs)
	}

	backendResult = mergedBackendResult
	removeAttributes = mergedRemoveAttributes.GetStringSlice()

	return action, backendResult, removeAttributes, nil
}
