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
	stderrors "errors"
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

// setGlobals initializes Lua global variables and functions for the given request and state.
func setGlobals(r *Request, L *lua.LState) {
	r.Logs = new(lualib.CustomLogKeyValue)

	globals := L.NewTable()

	globals.RawSet(lua.LString(definitions.LuaFilterAccept), lua.LBool(false))
	globals.RawSet(lua.LString(definitions.LuaFilterREJECT), lua.LBool(true))
	globals.RawSet(lua.LString(definitions.LuaFilterResultOk), lua.LNumber(0))
	globals.RawSet(lua.LString(definitions.LuaFilterResultFail), lua.LNumber(1))

	globals.RawSetString(definitions.LuaFnAddCustomLog, L.NewFunction(lualib.AddCustomLog(r.Logs)))
	globals.RawSetString(definitions.LuaFnSetStatusMessage, L.NewFunction(lualib.SetStatusMessage(&r.StatusMessage)))

	L.SetGlobal(definitions.LuaDefaultTable, globals)
}

// setRequest constructs a new lua.LTable and assigns fields based on the supplied Request struct 'r'.
// Upon completion, it returns the constructed lua.LTable.
func setRequest(r *Request, L *lua.LState) *lua.LTable {
	request := L.NewTable()

	r.CommonRequest.SetupRequest(request)

	return request
}

// executeScriptWithinContext runs a Lua script within a provided execution context and Lua state.
// It uses a timeout configuration to limit script execution time.
// The function sets up the Lua state, executes the script, and processes the result.
// Returns a boolean indicating success and an error in case of failure.
func executeScriptWithinContext(request *lua.LTable, script *LuaFilter, r *Request, ctx *gin.Context, L *lua.LState) (bool, error) {
	var err error

	stopTimer := stats.PrometheusTimer(definitions.PromFilter, script.Name)

	if stopTimer != nil {
		defer stopTimer()
	}

	luaCtx, luaCancel := context.WithTimeout(ctx, viper.GetDuration(definitions.LogKeyLuaScripttimeout)*time.Second)

	defer luaCancel()

	L.SetContext(luaCtx)

	packagePathErr := lualib.PackagePath(L)
	if packagePathErr != nil {
		return false, packagePathErr
	}

	scriptErr := lualib.DoCompiledFile(L, script.CompiledScript)
	if scriptErr != nil {
		return false, scriptErr
	}

	filterFunc := L.GetGlobal(definitions.LuaFnCallFilter)

	if filterFunc.Type() == lua.LTFunction {
		callErr := L.CallByParam(lua.P{Fn: L.GetGlobal(definitions.LuaFnCallFilter), NRet: 2, Protect: true}, request)
		if callErr != nil {
			return false, callErr
		}

		result := L.ToInt(-1)
		L.Pop(1)

		action := L.ToBool(-1)
		L.Pop(1)

		logResult(r, script, action, result)

		if action {
			return true, err
		}
	}

	return false, err
}

// logResult logs the completion of a Lua filter execution including action taken, result, and optional custom logs.
func logResult(r *Request, script *LuaFilter, action bool, ret int) {
	resultMap := map[int]string{definitions.ResultOk: "ok", definitions.ResultFail: "fail"}

	logs := []any{
		definitions.LogKeyGUID, r.Session,
		"name", script.Name,
		definitions.LogKeyMsg, "Lua filter finished",
		"action", action,
		"result", resultMap[ret],
	}

	if ret != 0 {
		if r.Logs != nil {
			for index := range *r.Logs {
				logs = append(logs, (*r.Logs)[index])
			}
		}
	}

	util.DebugModule(definitions.DbgFilter, logs...)
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

// mapsEqual checks if two maps are equal by comparing their key-value pairs.
// It returns true if the maps are equal, and false otherwise.
func mapsEqual(m1, m2 map[any]any) bool {
	if len(m1) != len(m2) {
		return false
	}

	for k, v := range m1 {
		if v2, ok := m2[k]; !ok || v != v2 {
			return false
		}
	}

	return true
}

// CallFilterLua executes predefined Lua filter scripts in a secured Lua state using the provided Gin context and request.
// It evaluates each script sequentially, merging backend results and attributes for successful executions.
// Returns a boolean indicating action, the merged backend result, a list of remove attributes, and an error if any occur.
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

	backendResult = &lualib.LuaBackendResult{}
	removeAttributes = make([]string, 0)

	LuaFilters.Mu.RLock()

	defer LuaFilters.Mu.RUnlock()

	L := luapool.Get()

	defer luapool.Put(L)

	registerDynamicLoader(L, ctx, r, &backendResult, &removeAttributes)

	lualib.RegisterBackendResultType(L, definitions.LuaBackendResultAttributes)
	setGlobals(r, L)

	request := setRequest(r, L)

	mergedBackendResult := &lualib.LuaBackendResult{Attributes: make(map[any]any)}
	mergedRemoveAttributes := config.NewStringSet()

	for _, script := range LuaFilters.LuaScripts {
		if L.GetTop() != 0 {
			L.SetTop(0)
		}

		if stderrors.Is(ctx.Err(), context.Canceled) {
			return
		}

		prevBackendResult := backendResult

		result, errLua := executeScriptWithinContext(request, script, r, ctx, L)
		if errLua != nil {
			err = errLua

			break
		}

		if !mapsEqual(prevBackendResult.Attributes, backendResult.Attributes) {
			mergedBackendResult.Attributes = mergeMaps(mergedBackendResult.Attributes, backendResult.Attributes)
		}

		for _, attr := range removeAttributes {
			mergedRemoveAttributes.Set(attr)
		}

		if result {
			action = true

			break
		}
	}

	backendResult = mergedBackendResult
	removeAttributes = mergedRemoveAttributes.GetStringSlice()

	return
}
