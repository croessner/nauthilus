package filter

import (
	"context"
	stderrors "errors"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/monitoring"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/spf13/viper"
	lua "github.com/yuin/gopher-lua"
)

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

		lualib.RegisterCommonLuaLibraries(L, modName, registry)
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
	case global.LuaModContext:
		L.PreloadModule(modName, lualib.LoaderModContext(r.Context))
	case global.LuaModHTTPRequest:
		L.PreloadModule(modName, lualib.LoaderModHTTPRequest(ctx.Request))
	case global.LuaModLDAP:
		if config.LoadableConfig.HaveLDAPBackend() {
			L.PreloadModule(modName, backend.LoaderModLDAP(ctx))
		} else {
			L.RaiseError("LDAP backend not activated")
		}
	case global.LuaModBackend:
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
			global.LuaFnGetBackendServers:       getBackendServers(request.BackendServers),
			global.LuaFnSelectBackendServer:     selectBackendServer(&request.UsedBackendAddress, &request.UsedBackendPort),
			global.LuaFnCheckBackendConnection:  lualib.CheckBackendConnection(monitoring.NewMonitor()),
			global.LuaFnApplyBackendResult:      applyBackendResult(backendResult),
			global.LuaFnRemoveFromBackendResult: removeFromBackendResult(removeAttributes),
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
	if config.LoadableConfig.HaveLuaFilters() {
		if LuaFilters == nil {
			LuaFilters = &PreCompiledLuaFilters{}
		} else {
			LuaFilters.Reset()
		}

		for index := range config.LoadableConfig.Lua.Filters {
			var luaFilter *LuaFilter

			luaFilter, err = NewLuaFilter(config.LoadableConfig.Lua.Filters[index].Name, config.LoadableConfig.Lua.Filters[index].ScriptPath)
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

type Request struct {
	BackendServers []*config.BackendServer

	UsedBackendAddress *string

	UsedBackendPort *int

	// Log is used to capture logging information.
	Logs *lualib.CustomLogKeyValue

	// Context includes context data from the caller.
	*lualib.Context

	*lualib.CommonRequest
}

type LuaBackendServer struct {
	Protocol  string
	IP        string
	Port      int
	HAProxyV2 bool
	TLS       bool
}

// The userData constellation method:
func newLuaBackendServer(userData *lua.LUserData) *LuaBackendServer {
	if v, ok := userData.Value.(*LuaBackendServer); ok {
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
	case "ip":
		L.Push(lua.LString(server.IP))
	case "port":
		L.Push(lua.LNumber(server.Port))
	case "haproxy_v2":
		L.Push(lua.LBool(server.HAProxyV2))
	case "tls":
		L.Push(lua.LBool(server.TLS))
	default:
		return 0 // The field does not exist
	}

	return 1 // Number of return values
}

// getBackendServers is a higher-order function that returns a LGFunction.
// The returned LGFunction creates a new Lua table and populates it with userdata objects representing backend servers.
// Each userdata object has a metatable set, allowing Lua code to index the object and retrieve its properties.
// The userdata objects are created based on the provided backendServers slice.
// The userdata values are instances of the LuaBackendServer struct, with Protocol, IP, Port, and HAProxyV2 fields.
// The metatable of the userdata objects has __index method set to the indexMethod function.
// The indexMethod function retrieves the corresponding property value from the userdata object based on the requested field name.
// The userdata objects are added to the created Lua table.
// The created Lua table is pushed onto the Lua stack before returning from the LGFunction.
func getBackendServers(backendServers []*config.BackendServer) lua.LGFunction {
	return func(L *lua.LState) int {
		servers := L.NewTable()

		// Create the metatable
		mt := L.NewTypeMetatable(global.LuaBackendServerTypeName)

		L.SetField(mt, "__index", L.NewFunction(indexMethod))

		for _, backendServer := range backendServers {
			if backendServer == nil {
				continue
			}

			// Create an userdata and set its metatable
			serverUserData := L.NewUserData()

			serverUserData.Value = &LuaBackendServer{
				Protocol:  backendServer.Protocol,
				IP:        backendServer.IP,
				Port:      backendServer.Port,
				HAProxyV2: backendServer.HAProxyV2,
				TLS:       backendServer.TLS,
			}

			L.SetMetatable(serverUserData, L.GetTypeMetatable(global.LuaBackendServerTypeName))

			// Add userdata into the servers table
			servers.Append(serverUserData)
		}

		L.Push(servers)

		return 1
	}
}

// selectBackendServer is a function that takes a server pointer (expected to be a string) and a port
// pointer (expected to be an integer) as parameters. It returns a Lua function. This Lua function
// wraps the functionality of checking the count of passed arguments and assigning the values of
// server and port based on Lua's stack. The Lua function throws an error if the count of passed
// arguments is not 2. If the argument count is correct, it gets the server and port values from the
// 1st and the 2nd positions in the Lua stack respectively, and assigns them to the server and port pointers.
//
// It's important to note that this function doesn't perform any kind of connection or communication
// with a server or port. It only assigns values based on Lua stack positions.
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

// applyBackendResult is a function that returns a Lua LGFunction.
// The returned function is used to assign the value of the backendResult to the LuaBackendResult
// extracted from the provided user data. If the user data does not contain a LuaBackendResult,
// the backendResult remains unchanged.
//
// Params:
// - backendResult: A double pointer to a LuaBackendResult
//
// Returns:
// - A Lua LGFunction that assigns the value of the userData to the backendResult
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

// removeFromBackendResult is a function that creates and returns a Lua LGFunction.
// The LGFunction takes a Lua state as argument and modifies a slice (attributes)
// by appending values from a Lua table passed as argument to the LGFunction.
// The function returns 0, indicating no values are returned to Lua.
// If the attributes slice is nil, the function returns 0 immediately.
// The function extracts a Lua table from the Lua stack and iterates over its
// values. For each value, it appends its string representation to the attributes slice.
// Finally, the function returns 0 to Lua.
//
// Params:
//
//	attributes *[]string : Pointer to a slice of strings to store the extracted attributes
//
// Returns:
//
//	the LGFunction that takes a Lua state as argument and modifies the attributes slice
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

	globals.RawSet(lua.LString(global.LuaFilterAccept), lua.LBool(false))
	globals.RawSet(lua.LString(global.LuaFilterREJECT), lua.LBool(true))
	globals.RawSet(lua.LString(global.LuaFilterResultOk), lua.LNumber(0))
	globals.RawSet(lua.LString(global.LuaFilterResultFail), lua.LNumber(1))

	globals.RawSetString(global.LuaFnAddCustomLog, L.NewFunction(lualib.AddCustomLog(r.Logs)))
	globals.RawSetString(global.LuaFnSetStatusMessage, L.NewFunction(lualib.SetStatusMessage(&r.StatusMessage)))

	L.SetGlobal(global.LuaDefaultTable, globals)
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
	stopTimer := stats.PrometheusTimer(global.PromFeature, script.Name)

	defer stopTimer()

	luaCtx, luaCancel := context.WithTimeout(ctx, viper.GetDuration(global.LogKeyLuaScripttimeout)*time.Second)

	defer luaCancel()

	L.SetContext(luaCtx)

	packagePathErr := lualib.PackagePath(L)
	if packagePathErr != nil {
		logError(r, script, packagePathErr)

		return false, packagePathErr
	}

	scriptErr := lualib.DoCompiledFile(L, script.CompiledScript)
	if scriptErr != nil {
		logError(r, script, scriptErr)

		return false, scriptErr
	}

	callErr := L.CallByParam(lua.P{Fn: L.GetGlobal(global.LuaFnCallFilter), NRet: 2, Protect: true}, request)
	if callErr != nil {
		logError(r, script, callErr)

		return false, callErr
	}

	result := L.ToInt(-1)
	L.Pop(1)

	action := L.ToBool(-1)
	L.Pop(1)

	logResult(r, script, action, result)

	if action {
		return true, nil
	}

	return false, nil
}

// logError is a function that logs error information when a LuaFilter script fails during a Request session.
// It logs the Session GUID, the name of the script, and the error message to the default error logger with an Error level.
func logError(r *Request, script *LuaFilter, err error) {
	level.Error(log.Logger).Log(
		global.LogKeyGUID, r.Session,
		"name", script.Name,
		global.LogKeyError, err,
	)
}

// logResult logs the output of a LuaFilter execution for a given request.
// The outcome (ok or fail) and whether an action was taken is logged along with the session ID and script name.
func logResult(r *Request, script *LuaFilter, action bool, ret int) {
	resultMap := map[int]string{global.ResultOk: "ok", global.ResultFail: "fail"}

	if ret != 0 {
		logs := []any{
			global.LogKeyGUID, r.Session,
			"name", script.Name,
		}

		if r.Logs != nil {
			for index := range *r.Logs {
				logs = append(logs, (*r.Logs)[index])
			}
		}

		level.Info(log.Logger).Log(logs...)
	}

	util.DebugModule(
		global.DbgFilter,
		global.LogKeyGUID, r.Session,
		"name", script.Name,
		global.LogKeyMsg, "Lua filter finished",
		"action", action,
		"result", resultMap[ret],
	)
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
	lualib.RegisterBackendResultType(L, global.LuaBackendResultAttributes)
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
