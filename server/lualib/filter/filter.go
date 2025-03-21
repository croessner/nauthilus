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
	"net/http"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/monitoring"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"github.com/yuin/gopher-lua"
)

// httpClient is a pre-configured instance of http.Client with custom timeout and TLS settings for making HTTP requests.
var httpClient *http.Client

// InitHTTPClient initializes the global httpClient variable with a pre-configured instance from util.NewHTTPClient.
func InitHTTPClient() {
	httpClient = util.NewHTTPClient()
}

// registerDynamicLoader registers a dynamic loader function in the Lua state.
// The dynamic loader function allows loading Lua modules on-demand based on their names.
// It takes an *lua.LState, *gin.Context, *Request, **lualib.LuaBackendResult, and *[]string as input parameters.
// Inside the function, it creates a new Lua function using Lua's NewFunction function, which takes a function as a parameter.
// The created function takes a string parameter representing the module name.
// First, it checks if the module name is already registered in the registry map.
// If it is, the function returns without registering the module.
// If the module name is not registered, it calls lualib.RegisterCommonLuaLibraries to register common Lua libraries.
// Then, it calls registerModule to register module-specific libraries based on the module name.
// After registering the libraries, it sets the global variable "dynamic_loader" in the Lua state to the created function.
// The function does not return any value.
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

// registerModule registers a Lua module based on the given modName. It loads and preloads the respective Lua functions
// based on the modName using the provided Lua state (L). The modName and its respective Lua functions are taken from
// the lualib package and registered using the L.PreloadModule function. The registry map is used to keep track of
// the registered modules. If the modName is not recognized, the function returns without registering any module.
// The modName parameter specifies the name of the module.
// The L parameter is a pointer to the Lua state.
// The ctx parameter is a pointer to the gin.Context object.
// The r parameter is a pointer to the Request struct.
// The registry parameter is a map[string]bool that keeps track of all registered modules.
// The backendResult parameter is a pointer to a pointer of the LuaBackendResult struct.
// The removeAttributes parameter is a pointer to a slice of strings.
// The function does not return any value.
func registerModule(L *lua.LState, ctx *gin.Context, r *Request, modName string, registry map[string]bool, backendResult **lualib.LuaBackendResult, removeAttributes *[]string) {
	switch modName {
	case definitions.LuaModContext:
		L.PreloadModule(modName, lualib.LoaderModContext(r.Context))
	case definitions.LuaModHTTPRequest:
		L.PreloadModule(modName, lualib.LoaderModHTTPRequest(ctx.Request))
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

// LoaderModBackend is a higher-order function that takes a pointer to a Request struct as a parameter.
// It returns a Lua LGFunction.
// The returned LGFunction creates a new Lua table and populates it with Lua functions.
// Each Lua function corresponds to a specific functionality related to the backend servers.
// The LGFunction sets up the necessary global variables and request context, and then pushes the created Lua table onto the Lua stack.
//
// Params:
//   - request *Request : A pointer to a Request struct.
//
// Returns:
//   - lua.LGFunction : A Lua LGFunction that creates a Lua table and populates it with functions related to backend servers.
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

// PreCompileLuaFilters is a function that pre-compiles Lua filters.
// It iterates over the filters available in the configuration. For each filter,
// it creates a new LuaFilter instance passing the filter name and script path, and then adds it to the LuaFilters.
// Note: If LuaFilters is nil, a new instance of PreCompiledLuaFilters is created.
// If LuaFilters already exists, it's reset before the new filters are added.
// If an error occurs when creating a new LuaFilter, it returns immediately with that error.
// It returns nil if no error occurs.
//
// Returns:
//
//	error if any error occurs while initializing the Lua filters
func PreCompileLuaFilters() (err error) {
	if config.GetFile().HaveLuaFilters() {
		if LuaFilters == nil {
			LuaFilters = &PreCompiledLuaFilters{}
		} else {
			LuaFilters.Reset()
		}

		for index := range config.GetFile().Lua.Filters {
			var luaFilter *LuaFilter

			luaFilter, err = NewLuaFilter(config.GetFile().Lua.Filters[index].Name, config.GetFile().Lua.Filters[index].ScriptPath)
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

// Add appends a LuaFilter to the LuaScripts in the
// PreCompiledLuaFilters. It ensures thread-safety by
// obtaining a lock before performing the operation,
// and then unlocking once the operation is complete.
//
// Parameters:
//
//	luaFilter: The LuaFilter instance that should be added.
//
// Usage:
//
//	luaFilters := &PreCompiledLuaFilters{}
//	filter := &LuaFilter{}
//	luaFilters.Add(filter)
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

// NewLuaFilter creates a new instance of LuaFilter. It requires two parameters: name and scriptPath.
// The name parameter is a string representing the name of the LuaFilter. If it is empty, an error is returned.
// The scriptPath parameter is a string representing the path to a Lua script file.
// If the scriptPath is empty, an error is returned.
// If the scriptPath is valid, the Lua script at the given path is compiled.
// If script compilation fails, it returns the related error.
// If both parameters are valid and the script compilation is successful, a pointer to the LuaFilter instance is returned.
// The returned LuaFilter instance includes the provided name and the compiled script.
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

// setGlobals sets up the necessary global variables in the Lua state.
// It initializes the global table 'globals' and adds key-value pairs to it.
// It adds keys representing filter accept, filter reject, filter result ok,
// and filter result fail, with their respective values.
// It adds Lua functions 'custom_log_add' and 'status_message_set' to the global table,
// along with their corresponding implementations.
// Finally, it sets the global variable 'nauthilus_builtin' to the 'globals' table.
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

// executeScriptWithinContext executes a Lua script within a provided context.
// It takes in a Lua LTable, a LuaFilter, a Request, a gin context and a Lua LState as parameters.
// The function sets a timeout for the execution of the Lua script, runs the script, and handles any errors that occur during the execution.
// It also calls the Lua function with the given parameters and logs the result.
// The function will return a boolean indicating whether the Lua function was called successfully, and an error if any occurred.
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

	return false, err
}

// logResult logs the output of a LuaFilter execution for a given request.
// The outcome (ok or fail) and whether an action was taken is logged along with the session ID and script name.
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

// CallFilterLua attempts to execute Lua scripts defined in LuaFilters. It returns true if at least
// one of the scripts executed successfully, otherwise it returns false.
// The error return value is used to indicate any issues with the Lua filters.
//
// It initially checks if any LuaFilters are defined. If none are found, it returns
// false with an ErrNoFiltersDefined error.
// It then creates a new Lua state and sets up the necessary global variables and request context.
// Scripts from the LuaFilters are executed in sequence within the provided context until a script
// executes successfully or all scripts have been attempted.
// If the context has been cancelled, the function returns without executing any more scripts.
// If a script returns an error, it is skipped and the next script is tried.
func (r *Request) CallFilterLua(ctx *gin.Context) (action bool, backendResult *lualib.LuaBackendResult, removeAttributes []string, err error) {
	if LuaFilters == nil || len(LuaFilters.LuaScripts) == 0 {
		return false, nil, nil, errors.ErrNoFiltersDefined
	}

	backendResult = &lualib.LuaBackendResult{}
	removeAttributes = make([]string, 0)

	LuaFilters.Mu.RLock()

	defer LuaFilters.Mu.RUnlock()

	L := lua.NewState()

	defer L.Close()

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
