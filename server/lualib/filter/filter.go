package filter

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/decl"
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/spf13/viper"
	"github.com/tengattack/gluacrypto"
	libs "github.com/vadv/gopher-lua-libs"
	lua "github.com/yuin/gopher-lua"
)

// LuaFilters holds pre-compiled Lua scripts for use across the application.
// It allows faster access and execution of frequently used scripts.
var LuaFilters *PreCompiledLuaFilters

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
	if config.LoadableConfig.Lua != nil {
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

// Request represents the data received in a client request.
type Request struct {
	// Debug is a flag that is set if running in debug more.
	Debug bool

	// UserFound indicates whether a user has been found on the system.
	UserFound bool

	// Authenticated indicates whether the user has authenticated.
	Authenticated bool

	// NoAuth indicates if any authentication method has no effect.
	NoAuth bool

	// Session is a GUID representing the user's session.
	Session string

	// ClientIP is the IP address of the client making the request.
	ClientIP string

	// ClientPort is the port being used by the client making the request.
	ClientPort string

	// ClientHost is the hostname of the client making the request.
	ClientHost string

	// ClientID is a unique ID representing the client making the request.
	ClientID string

	// LocalIP is the local IP address the request is made to.
	LocalIP string

	// LocalPort is the local port the request is made to.
	LocalPort string

	// Username is the username of the authenticated user.
	Username string

	// Account is the account name of the authenticated user.
	Account string

	// UniqueUserID is the unique user identifier of the authenticated user.
	UniqueUserID string

	// DisplayName is the display name of the authenticated user.
	DisplayName string

	// Password is the password of the authenticated user. Please ensure this is handled securely.
	Password string

	// Protocol is the protocol used by the client making the request.
	Protocol string

	// Log is used to capture logging information.
	Logs *lualib.CustomLogKeyValue

	// Context includes context data from the caller.
	*lualib.Context
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
//	r *Request : The request context which includes logs and other context specific data
//	L *lua.LState : The lua state onto which the globals are being set
//	globals *lua.LTable : The lua table which is being used to set the globals
func setGlobals(r *Request, L *lua.LState, globals *lua.LTable) {
	r.Logs = new(lualib.CustomLogKeyValue)

	globals.RawSet(lua.LString(decl.LuaFilterAccept), lua.LBool(false))
	globals.RawSet(lua.LString(decl.LuaFilterREJECT), lua.LBool(true))
	globals.RawSet(lua.LString(decl.LuaFilterResultOk), lua.LNumber(0))
	globals.RawSet(lua.LString(decl.LuaFilterResultFail), lua.LNumber(1))

	globals.RawSetString(decl.LuaFnCtxSet, L.NewFunction(lualib.ContextSet(r.Context)))
	globals.RawSetString(decl.LuaFnCtxGet, L.NewFunction(lualib.ContextGet(r.Context)))
	globals.RawSetString(decl.LuaFnCtxDelete, L.NewFunction(lualib.ContextDelete(r.Context)))
	globals.RawSetString(decl.LuaFnAddCustomLog, L.NewFunction(lualib.AddCustomLog(r.Logs)))

	L.SetGlobal(decl.LuaDefaultTable, globals)
}

// setRequest fills a provided *lua.LTable with corresponding values obtained from a supplied *Request object.
// The function key in the lua.LTable is set to the field name in the Request object, and the value in lua.LTable is the corresponding value in Request object.
// For instance, a key like decl.LuaRequestDebug in lua.LTable corresponds to the Debug field in Request and its value is set to the Boost value in the Request object.
func setRequest(r *Request, request *lua.LTable) {
	request.RawSet(lua.LString(decl.LuaRequestDebug), lua.LBool(r.Debug))
	request.RawSet(lua.LString(decl.LuaRequestNoAuth), lua.LBool(r.NoAuth))
	request.RawSet(lua.LString(decl.LuaRequestAuthenticated), lua.LBool(r.Authenticated))
	request.RawSet(lua.LString(decl.LuaRequestUserFound), lua.LBool(r.UserFound))

	request.RawSetString(decl.LuaRequestSession, lua.LString(r.Session))
	request.RawSetString(decl.LuaRequestClientIP, lua.LString(r.ClientIP))
	request.RawSetString(decl.LuaRequestClientPort, lua.LString(r.ClientPort))
	request.RawSetString(decl.LuaRequestClientHost, lua.LString(r.ClientHost))
	request.RawSetString(decl.LuaRequestClientID, lua.LString(r.ClientID))
	request.RawSetString(decl.LuaRequestLocalIP, lua.LString(r.LocalIP))
	request.RawSetString(decl.LuaRequestLocalPort, lua.LString(r.LocalPort))
	request.RawSetString(decl.LuaRequestUsername, lua.LString(r.Username))
	request.RawSetString(decl.LuaRequestAccount, lua.LString(r.Account))
	request.RawSetString(decl.LuaRequestUniqueUserID, lua.LString(r.UniqueUserID))
	request.RawSetString(decl.LuaRequestDisplayName, lua.LString(r.DisplayName))
	request.RawSetString(decl.LuaRequestPassword, lua.LString(r.Password))
	request.RawSetString(decl.LuaRequestProtocol, lua.LString(r.Protocol))
}

// executeScriptWithinContext executes a Lua script within a provided context.
// It takes in a Lua LTable, a LuaFilter, a Request, a gin context and a Lua LState as parameters.
// The function sets a timeout for the execution of the Lua script, runs the script, and handles any errors that occur during the execution.
// It also calls the Lua function with the given parameters and logs the result.
// The function will return a boolean indicating whether the Lua function was called successfully, and an error if any occurred.
func executeScriptWithinContext(request *lua.LTable, script *LuaFilter, r *Request, ctx *gin.Context, L *lua.LState) (bool, error) {
	luaCtx, luaCancel := context.WithTimeout(ctx, viper.GetDuration(decl.LogKeyLuaScripttimeout)*time.Second)

	defer luaCancel()

	L.SetContext(luaCtx)

	scriptErr := lualib.DoCompiledFile(L, script.CompiledScript)
	if scriptErr != nil {
		logError(r, script, scriptErr)

		return false, scriptErr
	}

	callErr := L.CallByParam(lua.P{Fn: L.GetGlobal(decl.LuaFnCallFilter), NRet: 2, Protect: true}, request)
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
		decl.LogKeyGUID, r.Session,
		"name", script.Name,
		decl.LogKeyError, err,
	)
}

// logResult logs the output of a LuaFilter execution for a given request.
// The outcome (ok or fail) and whether an action was taken is logged along with the session ID and script name.
func logResult(r *Request, script *LuaFilter, action bool, ret int) {
	resultMap := map[int]string{decl.ResultOk: "ok", decl.ResultFail: "fail"}

	level.Info(logging.DefaultLogger).Log(
		decl.LogKeyGUID, r.Session,
		"name", script.Name,
		"Iua Filter finished",
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
func (r *Request) CallFilterLua(ctx *gin.Context) (action bool, err error) {
	if LuaFilters == nil || len(LuaFilters.LuaScripts) == 0 {
		return false, errors2.ErrNoFiltersDefined
	}

	LuaFilters.Mu.RLock()

	defer LuaFilters.Mu.RUnlock()

	L := lua.NewState()

	defer L.Close()

	libs.Preload(L)
	gluacrypto.Preload(L)

	globals := L.NewTable()
	setGlobals(r, L, globals)

	request := L.NewTable()
	setRequest(r, request)

	for _, script := range LuaFilters.LuaScripts {
		if errors.Is(ctx.Err(), context.Canceled) {
			return
		}

		result, err := executeScriptWithinContext(request, script, r, ctx, L)
		if err != nil {
			continue
		}

		if result {
			action = true

			break
		}
	}

	return
}
