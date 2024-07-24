package callback

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/smtp"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/spf13/viper"
	"github.com/yuin/gopher-lua"
)

var (

	// luaPool represents a variable of type LuaBaseStatePool that holds a pool of Lua state instances.
	// It is created using the NewLuaStatePool function from the lualib package.
	// The pool allows safe concurrent access to the Lua states and provides methods for retrieving and returning states,
	// as well as shutting down the pool and logging pool statistics.
	// Example usage:
	//   luaPool := lualib.NewLuaStatePool()
	luaPool = lualib.NewLuaStatePool()

	// LuaCallback represents a variable that holds a precompiled Lua script and allows safe concurrent access to the script.
	LuaCallback *PreCompiledLuaCallback
)

// PreCompiledLuaCallback represents a type that holds a precompiled Lua script and
// allows safe concurrent access to the script.
type PreCompiledLuaCallback struct {
	// LuaScript is a pointers to a precompiled Lua script *lua.FunctionProto.,
	LuaScript *lua.FunctionProto

	// Mu is a read/write mutex used to allow safe concurrent access to the LuaScript.
	Mu sync.RWMutex
}

// Replace is a method of the PreCompiledLuaCallback struct that replaces the LuaScript of p
// with the LuaScript of luaCallback. The method locks the read/write mutex of the PreCompiledLuaCallback
// using Lock() before assigning the new LuaScript to the target PreCompiledLuaCallback.
// It then unlocks the mutex using Unlock() in a deferred statement.
//
// Parameters:
//   - luaCallback *PreCompiledLuaCallback: The PreCompiledLuaCallback with the LuaScript to replace the existing one.
//
// Example usage:
//
//	newLuaCallback := &PreCompiledLuaCallback{
//	  LuaScript: compiledScript,
//	}
//	currentLuaCallback.Replace(newLuaCallback)
//
// PreCompiledLuaCallback declaration:
//
//	type PreCompiledLuaCallback struct {
//	  LuaScript *lua.FunctionProto
//	  Mu        sync.RWMutex
//	}
//
// PreCompiledLuaCallback.GetPrecompiledScript declaration:
//
//	func (p *PreCompiledLuaCallback) GetPrecompiledScript() *lua.FunctionProto
//
// config.LoadableConfig declaration:
//
//	var LoadableConfig *File
//
// LuaCallback declaration:
//
//	var LuaCallback *PreCompiledLuaCallback
//
// NewLuaCallback declaration:
//
//	func NewLuaCallback() (*PreCompiledLuaCallback, error)
//
// lualib.CompileLua declaration:
//
//	func CompileLua(filePath string) (*lua.FunctionProto, error)
func (p *PreCompiledLuaCallback) Replace(luaCallback *PreCompiledLuaCallback) {
	p.Mu.Lock()

	defer p.Mu.Unlock()

	p.LuaScript = luaCallback.LuaScript
}

// GetPrecompiledScript is a method of the PreCompiledLuaCallback struct. It returns the precompiled Lua script
// as a pointer to the lua.FunctionProto. The method locks the read/write mutex of the PreCompiledLuaCallback
// using RLock() before returning the LuaScript. It then unlocks the mutex using RUnlock() in a deferred statement.
//
// Returns:
//   - LuaScript *lua.FunctionProto: The precompiled Lua script as a pointer to the lua.FunctionProto.
//
// Example usage:
//
//	script := p.GetPrecompiledScript()
//	// Use the script for further processing
func (p *PreCompiledLuaCallback) GetPrecompiledScript() *lua.FunctionProto {
	p.Mu.RLock()

	defer p.Mu.RUnlock()

	return p.LuaScript
}

// NewLuaCallback compiles a Lua script based on the provided file path and returns a new instance
// of PreCompiledLuaCallback with the compiled script. If there is an error during the compilation,
// the function returns nil and the error. The returned PreCompiledLuaCallback can be used to replace the
// LuaScript of the current LuaCallback.
//
// Example usage:
//
//	compiledScript, err := NewLuaCallback()
//	if err != nil {
//	    fmt.Println("Error:", err)
//	    return
//	}
//	LuaCallback.Replace(compiledScript)
//
// PreCompiledLuaCallback declaration:
//
//	type PreCompiledLuaCallback struct {
//	    LuaScript *lua.FunctionProto
//	    Mu        sync.RWMutex
//	}
//
// PreCompiledLuaCallback.Replace declaration:
//
//	func (p *PreCompiledLuaCallback) Replace(luaCallback *PreCompiledLuaCallback)
//
// PreCompiledLuaCallback.GetPrecompiledScript declaration:
//
//	func (p *PreCompiledLuaCallback) GetPrecompiledScript() *lua.FunctionProto
//
// lualib.CompileLua declaration:
//
//	func CompileLua(filePath string) (*lua.FunctionProto, error)
//
// config.LoadableConfig declaration:
//
//	var LoadableConfig *File
//
// LuaCallback declaration:
//
//	var LuaCallback *PreCompiledLuaCallback
func NewLuaCallback() (*PreCompiledLuaCallback, error) {
	compiledScript, err := lualib.CompileLua(config.LoadableConfig.GetLuaCallbackScriptPath())
	if err != nil {
		return nil, err
	}

	return &PreCompiledLuaCallback{
		LuaScript: compiledScript,
	}, nil
}

// PreCompileLuaCallback pre-compiles the Lua callback script and replaces the current LuaCallback with the new one.
// If the LoadableConfig has a Lua callback and the current LuaCallback is nil, a new instance of PreCompiledLuaCallback is created.
// The function calls NewLuaCallback to get the new pre-compiled Lua callback script.
// If an error occurs during the pre-compilation, the function returns the error.
// If no error occurs, the new Lua callback script replaces the current LuaCallback's LuaScript.
// The function returns nil if it executes successfully.
func PreCompileLuaCallback() (err error) {
	var luaCallbackNew *PreCompiledLuaCallback

	if config.LoadableConfig.HaveLuaCallback() {
		if LuaCallback == nil {
			LuaCallback = &PreCompiledLuaCallback{}
		}

		luaCallbackNew, err = NewLuaCallback()
		if err != nil {
			return err
		}

		LuaCallback.Replace(luaCallbackNew)
	}

	return nil
}

// getHTTPRequestBody reads the HTTP request body and returns it as a Lua string.
// The function expects one parameter: the HTTP request object.
// It returns the request body as a Lua string.
// If an error occurs, it raises a Lua error with the error message and returns 0.
// The read request body is then assigned back to the request's body for the next handler.
func getHTTPRequestBody(httpRequest *http.Request) lua.LGFunction {
	return func(L *lua.LState) int {
		// Read the HTTP body
		bodyBytes, err := io.ReadAll(httpRequest.Body)
		if err != nil {
			L.RaiseError("failed to read request body: %v", err)

			return 0
		}

		// Make sure the body is readable for the next handler...
		httpRequest.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		L.Push(lua.LString(bodyBytes))

		return 1
	}
}

// setupLogging creates a Lua table and sets up the "log_format" and "log_level" global variables based on the
// configuration settings in the LoadableConfig.Server.Log.JSON and LoadableConfig.Server.Log.Level.Get values.
// It returns the created Lua table.
//
// Parameters:
//   - L *lua.LState: The Lua state in which the Lua table will be created.
//
// Returns:
//
//	*lua.LTable: The Lua table containing the "log_format" and "log_level" global variables.
func setupLogging(L *lua.LState) *lua.LTable {
	logTable := L.NewTable()
	logFormat := global.LogFormatDefault
	logLevel := config.LoadableConfig.Server.Log.Level.Get()

	if config.LoadableConfig.Server.Log.JSON {
		logFormat = global.LogFormatJSON
	}

	logTable.RawSetString(global.LuaRequestLogFormat, lua.LString(logFormat))
	logTable.RawSetString(global.LuaRequestLogLevel, lua.LString(logLevel))

	return logTable
}

// setupGlobals creates a Lua table and sets up global variables for the Lua state.
// The global variables represent various Redis and HTTP request functions that can be called from Lua.
// The function expects two parameters: ctx *gin.Context, L *lua.LState.
// It returns a pointer to the Lua table that contains the global variables.
//
// The global variables are set using the `RawSetString` method of the Lua table.
// The key is a constant representing the function name, and the value is a new Lua function.
//
// The global Redis functions are:
// - "redis_get_str": lualib.RedisGet
// - "redis_set_str": lualib.RedisSet
// - "redis_incr": lualib.RedisIncr
// - "redis_del": lualib.RedisDel
// - "redis_expire": lualib.RedisExpire
//
// The global HTTP request functions are:
// - "get_all_http_request_headers": lualib.GetAllHTTPRequestHeaders(ctx.Request)
// - "get_http_request_body": getHTTPRequestBody(ctx.Request)
//
// The Lua table is then set as a global variable using the `SetGlobal` method of the Lua state.
//
// Finally, the Lua table is returned.
func setupGlobals(ctx *gin.Context, L *lua.LState) *lua.LTable {
	globals := L.NewTable()

	globals.RawSetString(global.LuaFnGetAllHTTPRequestHeaders, L.NewFunction(lualib.GetAllHTTPRequestHeaders(ctx.Request)))
	globals.RawSetString(global.LuaFnGetHTTPRequestHeader, L.NewFunction(lualib.GetHTTPRequestHeader(ctx.Request)))
	globals.RawSetString(global.LuaFnGetHTTPRequestBody, L.NewFunction(getHTTPRequestBody(ctx.Request)))
	globals.RawSetString(global.LuaFnSendMail, L.NewFunction(lualib.SendMail(&smtp.EmailClient{})))

	lualib.SetUPRedisFunctions(globals, L)

	L.SetGlobal(global.LuaDefaultTable, globals)

	return globals
}

// RunCallbackLuaRequest is a function that runs a Lua callback request in a Gin context.
// It creates a new context with a specified timeout taken from the "lua_script_timeout" configuration.
// The function fetches a Lua State object from a pool of Lua states and ensures its safe return to the pool upon completion.
// The Lua state is configured with the coroutine-aware version of the context.
// Global variables are then set up for the Lua state, and a precompiled Lua script is executed.
// Any encountered error during the execution of the script is captured and returned.
// Finally, the Lua table containing globals is cleaned up to prevent memory leaks.
//
// Parameters:
// ctx *gin.Context - The Gin context for the HTTP request.
//
// Returns:
// err error - An error if any occurred during the execution of the function.
func RunCallbackLuaRequest(ctx *gin.Context) (err error) {
	luaCtx, luaCancel := context.WithTimeout(ctx, viper.GetDuration("lua_script_timeout")*time.Second)

	L := luaPool.Get()

	defer luaPool.Put(L)

	L.SetContext(luaCtx)

	defer luaCancel()

	logTable := setupLogging(L)
	globals := setupGlobals(ctx, L)

	err = executeAndHandleError(LuaCallback.GetPrecompiledScript(), logTable, L)

	lualib.CleanupLTable(globals)

	globals = nil

	return
}

// executeAndHandleError executes the compiled Lua script and handles any errors that occur.
// It first sets the Lua package path using lualib.PackagePath and includes the directory where the Lua modules reside.
// Then it calls lualib.DoCompiledFile to run the script in the LState and checks for any errors.
// Finally, it calls L.CallByParam to call the Lua function specified by global.LuaFnRunCallback, and checks for any errors.
// If any errors occur during these steps, the function calls processError to log the error message.
// This function takes two arguments: the compiled Lua script pointer (*lua.FunctionProto) and the LState (*lua.LState).
// It returns an error, which will be nil if no errors occurred during the execution of the Lua script.
// Parameters:
//   - compiledScript: The compiled Lua script to be executed.
//   - logTable: The logTable provides the current log level and log format.
//   - L: The Lua state in which the script will be executed.
//
// Example usage:
//
//	err := executeAndHandleError(compiledScript, logTable, L)
//	if err != nil {
//	    // handle error
//	}
func executeAndHandleError(compiledScript *lua.FunctionProto, logTable *lua.LTable, L *lua.LState) (err error) {
	if err = lualib.PackagePath(L); err != nil {
		processError(err)
	}

	if err = lualib.DoCompiledFile(L, compiledScript); err != nil {
		processError(err)
	}

	if err = L.CallByParam(lua.P{
		Fn:      L.GetGlobal(global.LuaFnRunCallback),
		NRet:    0,
		Protect: true,
	}, logTable); err != nil {
		processError(err)
	}

	return err
}

// processError logs the given error message with the specified error level. It includes the script path and the error itself in the log entry.
// Parameters:
//   - err: The error to be logged.
//
// Usage Example:
//
//	executeAndHandleError(compiledScript, L)
func processError(err error) {
	level.Error(logging.DefaultErrLogger).Log(
		"script", config.LoadableConfig.GetLuaCallbackScriptPath(),
		global.LogKeyError, err,
	)
}
