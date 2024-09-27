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

package callback

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/spf13/viper"
	"github.com/yuin/gopher-lua"
)

var (
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

// registerDynamicLoader registers a dynamic loader function in the Lua state (L)
// that can load Lua modules on demand. It creates a new Lua function that takes
// a module name as its argument and registers the module if it hasn't been
// registered before. The function uses the registry map to keep track of registered
// modules. The registry map is updated after successfully registering a module.
// The function also sets the global variable "dynamic_loader" to the created
// dynamic loader function.
// Parameters:
//   - L: The Lua state on which the dynamic loader function will be registered.
//   - ctx: The Gin context object associated with the request. This is used by
//     certain module loaders.
//
// Note: The implementation of the dynamic loader function is not shown in this
// documentation. Please refer to the source code for more details on the
// implementation of the dynamic loader function.
func registerDynamicLoader(L *lua.LState, ctx *gin.Context, httpClient *http.Client) {
	dynamicLoader := L.NewFunction(func(L *lua.LState) int {
		modName := L.CheckString(1)

		registry := make(map[string]bool)
		if _, found := registry[modName]; found {
			return 0
		}

		lualib.RegisterCommonLuaLibraries(L, modName, registry, httpClient)
		registerModule(L, ctx, modName, registry)

		return 0
	})

	L.SetGlobal("dynamic_loader", dynamicLoader)
}

// registerModule registers a Lua module in the provided Lua state (L).
// The module name (modName) is used as a key in the registry map to indicate that it has been registered.
// The function also takes a *gin.Context object (ctx) to be used by certain module loaders.
// The registry map is updated to include the registered module.
// If the module name is unknown, the function returns immediately.
// If the module name is "nauthilus_http_request", it preloads the module using the lualib.LoaderModHTTPRequest function.
// If the module name is "nauthilus_ldap" and the LDAP backend is activated, it preloads the module using the backend.LoaderModLDAP function.
// If the LDAP backend is not activated, it raises an error.
func registerModule(L *lua.LState, ctx *gin.Context, modName string, registry map[string]bool) {
	switch modName {
	case global.LuaModHTTPRequest:
		L.PreloadModule(modName, lualib.LoaderModHTTPRequest(ctx.Request))
	case global.LuaModLDAP:
		if config.LoadableConfig.HaveLDAPBackend() {
			L.PreloadModule(modName, backend.LoaderModLDAP(ctx))
		} else {
			L.RaiseError("LDAP backend not activated")
		}
	default:
		return
	}

	registry[modName] = true
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

	defer luaCancel()

	L := lua.NewState()

	defer L.Close()

	httpClient, closeHHTPClient := util.NewClosingHTTPClient()

	defer closeHHTPClient()

	registerDynamicLoader(L, ctx, httpClient)

	L.SetContext(luaCtx)

	logTable := setupLogging(L)

	err = executeAndHandleError(LuaCallback.GetPrecompiledScript(), logTable, L)

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
	level.Error(log.Logger).Log(
		"script", config.LoadableConfig.GetLuaCallbackScriptPath(),
		global.LogKeyError, err,
	)
}
