package filter

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/config"
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/viper"
	lua "github.com/yuin/gopher-lua"
)

// LuaFilters holds pre-compiled Lua scripts for use across the application.
// It allows faster access and execution of frequently used scripts.
var LuaFilters *PreCompiledLuaFilters

// LuaPool is a pool of Lua state instances.
var LuaPool = lualib.NewLuaBackendResultStatePool(
	global.LuaBackendResultAttributes,
)

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
		return nil, errors2.ErrFilterLuaNameMissing
	}

	if scriptPath == "" {
		return nil, errors2.ErrFilterLuaScriptPathEmpty
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
		mt := L.NewTypeMetatable("backend_server")
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

			L.SetMetatable(serverUserData, L.GetTypeMetatable("backend_server"))

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

// setGlobals is a function that initializes a set of global variables in the provided lua.LState.
// The globals are set using the provided context (r) and lua table (globals).
// The following lua variables are set:
//   - FILTER_ACCEPT: a boolean flag set to false
//   - FILTER_REJECT: a boolean flag set to true
//   - FILTER_RESULT_OK: a number set to 0
//   - FILTER_RESULT_FAIL: a number set to 1
//
// Further, functions related to Context and Logging are also set as lua functions in the globals table.
//
// Params:
//
//		r *Request : The request context which includes logs and other context specific data
//		L *lua.LState : The lua state onto which the globals are being set
//	 httpRequest *http.Request : A pointer to http.Request to deliver all HTTP headers to Lua scripts
//	 backendResult **lualib.LuaBackendResult : Double pointer to a lualib.BackendResult to change attributes
//
// Returns:
//
//	A new request table
func setGlobals(r *Request, L *lua.LState, httpRequest *http.Request, backendResult **lualib.LuaBackendResult) *lua.LTable {
	r.Logs = new(lualib.CustomLogKeyValue)

	globals := L.NewTable()

	globals.RawSet(lua.LString(global.LuaFilterAccept), lua.LBool(false))
	globals.RawSet(lua.LString(global.LuaFilterREJECT), lua.LBool(true))
	globals.RawSet(lua.LString(global.LuaFilterResultOk), lua.LNumber(0))
	globals.RawSet(lua.LString(global.LuaFilterResultFail), lua.LNumber(1))

	globals.RawSetString(global.LuaFnCtxSet, L.NewFunction(lualib.ContextSet(r.Context)))
	globals.RawSetString(global.LuaFnCtxGet, L.NewFunction(lualib.ContextGet(r.Context)))
	globals.RawSetString(global.LuaFnCtxDelete, L.NewFunction(lualib.ContextDelete(r.Context)))
	globals.RawSetString(global.LuaFnAddCustomLog, L.NewFunction(lualib.AddCustomLog(r.Logs)))
	globals.RawSetString(global.LuaFnSetStatusMessage, L.NewFunction(lualib.SetStatusMessage(&r.StatusMessage)))
	globals.RawSetString(global.LuaFnApplyBackendResult, L.NewFunction(applyBackendResult(backendResult)))
	globals.RawSetString(global.LuaFnGetAllHTTPRequestHeaders, L.NewFunction(lualib.GetAllHTTPRequestHeaders(httpRequest)))
	globals.RawSetString(global.LuaFnRedisGet, L.NewFunction(lualib.RedisGet))
	globals.RawSetString(global.LuaFnRedisSet, L.NewFunction(lualib.RedisSet))
	globals.RawSetString(global.LuaFnRedisIncr, L.NewFunction(lualib.RedisIncr))
	globals.RawSetString(global.LuaFnRedisDel, L.NewFunction(lualib.RedisDel))
	globals.RawSetString(global.LuaFnRedisExpire, L.NewFunction(lualib.RedisExpire))

	if config.LoadableConfig.HasFeature(global.FeatureBackendServersMonitoring) {
		globals.RawSetString(global.LuaFnGetBackendServers, L.NewFunction(getBackendServers(r.BackendServers)))
		globals.RawSetString(global.LuaFnSelectBackendServer, L.NewFunction(selectBackendServer(&r.UsedBackendAddress, &r.UsedBackendPort)))
		globals.RawSetString(global.LuaFnCheckBackendConnection, L.NewFunction(lualib.CheckBackendConnection()))
	}

	L.SetGlobal(global.LuaDefaultTable, globals)

	return globals
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
	timer := prometheus.NewTimer(stats.FunctionDuration.WithLabelValues("Feature", script.Name))

	defer timer.ObserveDuration()

	luaCtx, luaCancel := context.WithTimeout(ctx, viper.GetDuration(global.LogKeyLuaScripttimeout)*time.Second)

	defer luaCancel()

	L.SetContext(luaCtx)

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
	level.Error(logging.DefaultErrLogger).Log(
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

		level.Info(logging.DefaultErrLogger).Log(logs...)
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
func (r *Request) CallFilterLua(ctx *gin.Context) (action bool, backendResult *lualib.LuaBackendResult, err error) {
	if LuaFilters == nil || len(LuaFilters.LuaScripts) == 0 {
		return false, nil, errors2.ErrNoFiltersDefined
	}

	LuaFilters.Mu.RLock()

	defer LuaFilters.Mu.RUnlock()

	L := LuaPool.Get()

	defer LuaPool.Put(L)
	defer L.SetGlobal(global.LuaDefaultTable, lua.LNil)

	globals := setGlobals(r, L, ctx.Request, &backendResult)
	request := setRequest(r, L)

	for _, script := range LuaFilters.LuaScripts {
		if errors.Is(ctx.Err(), context.Canceled) {
			return
		}

		result, errLua := executeScriptWithinContext(request, script, r, ctx, L)
		if errLua != nil {
			err = errLua

			break
		}

		if result {
			action = true

			break
		}
	}

	lualib.CleanupLTable(request)
	lualib.CleanupLTable(globals)

	request = nil
	globals = nil

	return
}
