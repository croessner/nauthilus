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

package hook

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/spf13/viper"
	"github.com/yuin/gopher-lua"
)

var (
	// LuaScripts is a map that stores precompiled Lua scripts, allowing safe concurrent access and manipulation.
	LuaScripts = make(map[string]*PrecompiledLuaScript)

	mu sync.Mutex
)

// customLocation is a map that associates each Location with its corresponding CustomHook.
// It allows retrieving precompiled Lua scripts based on location and HTTP method.
var customLocation CustomLocation

// httpClient is a pre-configured instance of http.Client with custom timeout and TLS settings for making HTTP requests.
var httpClient *http.Client

// InitHTTPClient initializes the global httpClient variable with a pre-configured instance from util.NewHTTPClient.
func InitHTTPClient() {
	httpClient = util.NewHTTPClient()
}

// PrecompiledLuaScript represents a type that holds a precompiled Lua script and
// allows safe concurrent access to the script.
type PrecompiledLuaScript struct {
	// luaScript is a pointers to a precompiled Lua script *lua.FunctionProto.,
	luaScript *lua.FunctionProto

	// mu is a read/write mutex used to allow safe concurrent access to the luaScript.
	mu sync.RWMutex
}

// Replace is a method of the PrecompiledLuaScript struct that replaces the luaScript of p
// with the luaScript of luaCallback. The method locks the read/write mutex of the PrecompiledLuaScript
// using Lock() before assigning the new luaScript to the target PrecompiledLuaScript.
// It then unlocks the mutex using Unlock() in a deferred statement.
func (p *PrecompiledLuaScript) Replace(luaScript *PrecompiledLuaScript) {
	p.mu.Lock()

	defer p.mu.Unlock()

	p.luaScript = luaScript.luaScript
}

// GetPrecompiledScript is a method of the PrecompiledLuaScript struct. It returns the precompiled Lua script
// as a pointer to the lua.FunctionProto. The method locks the read/write mutex of the PrecompiledLuaScript
// using RLock() before returning the luaScript. It then unlocks the mutex using RUnlock() in a deferred statement.
//
// Returns:
//   - luaScript *lua.FunctionProto: The precompiled Lua script as a pointer to the lua.FunctionProto.
//
// Example usage:
//
//	script := p.GetPrecompiledScript()
//	// Use the script for further processing
func (p *PrecompiledLuaScript) GetPrecompiledScript() *lua.FunctionProto {
	p.mu.RLock()

	defer p.mu.RUnlock()

	return p.luaScript
}

// NewLuaHook compiles a Lua script based on the provided file path and returns a new instance
// of PrecompiledLuaScript with the compiled script. If there is an error during the compilation,
// the function returns nil and the error. The returned PrecompiledLuaScript can be used to replace the
// luaScript of the current luaScript.
func NewLuaHook(filePath string) (*PrecompiledLuaScript, error) {
	compiledScript, err := lualib.CompileLua(filePath)
	if err != nil {
		return nil, err
	}

	return &PrecompiledLuaScript{
		luaScript: compiledScript,
	}, nil
}

// HttpMethod represents the HTTP methods used in HTTP requests.
type HttpMethod string

// CustomHook maps an HTTP method to its corresponding precompiled Lua script for handling specific requests.
type CustomHook map[HttpMethod]*PrecompiledLuaScript

// GetScript retrieves a precompiled Lua script associated with the provided HTTP method string.
// method: The HTTP method as a string.
// Returns the corresponding *PrecompiledLuaScript, or nil if not found.
func (h CustomHook) GetScript(method string) *PrecompiledLuaScript {
	if script, found := h[HttpMethod(method)]; found {
		return script
	}

	return nil
}

// SetScript assigns a precompiled Lua script to a specific HTTP method.
// method: The HTTP method as a string.
// script: A pointer to the precompiled Lua script to be associated with the method.
func (h CustomHook) SetScript(method string, script *PrecompiledLuaScript) {
	h[HttpMethod(method)] = script
}

// NewCustomHook creates a new CustomHook with the specified HTTP method and precompiled Lua script.
func NewCustomHook(httpMethod string, script *PrecompiledLuaScript) CustomHook {
	hook := make(CustomHook)

	hook[HttpMethod(httpMethod)] = script

	return hook
}

// Location represents a string type specifically used to denote a location.
type Location string

// CustomLocation is a map where each key is a Location and each value is a CustomHook.
type CustomLocation map[Location]CustomHook

// GetCustomHook retrieves the CustomHook associated with the provided location string.
// Returns the corresponding CustomHook if found, otherwise nil.
func (l CustomLocation) GetCustomHook(location string) CustomHook {
	if hook, found := l[Location(location)]; found {
		return hook
	}

	return nil
}

// GetScript retrieves a precompiled Lua script for a specified location and method.
// Parameters:
//   - location: The location string to search for.
//   - method: The HTTP method string to search for.
//
// Returns:
//
//	*PrecompiledLuaScript: The precompiled Lua script if found, otherwise nil.
func (l CustomLocation) GetScript(location, method string) *PrecompiledLuaScript {
	if hook := l.GetCustomHook(location); hook != nil {
		if script := hook.GetScript(method); script != nil {
			return script
		}
	}

	return nil
}

// SetScript assigns a precompiled Lua script to a specific HTTP method for the given location.
func (l CustomLocation) SetScript(location, method string, script *PrecompiledLuaScript) {
	if hook := l.GetCustomHook(location); hook != nil {
		hook.SetScript(method, script)
	} else {
		l[Location(location)] = NewCustomHook(method, script)
	}
}

// NewCustomLocation creates a new CustomLocation, which is a map of Location keys to CustomHook values.
func NewCustomLocation() CustomLocation {
	return make(CustomLocation)
}

// PreCompileLuaScript pre-compiles the Lua callback script and replaces the current luaScript with the new one.
// If the LoadableConfig has a Lua callback and the current luaScript is nil, a new instance of PrecompiledLuaScript is created.
// The function calls NewLuaHook to get the new pre-compiled Lua callback script.
// If an error occurs during the pre-compilation, the function returns the error.
// If no error occurs, the new Lua callback script replaces the current luaScript's luaScript.
// The function returns nil if it executes successfully.
func PreCompileLuaScript(filePath string) (err error) {
	var luaScriptNew *PrecompiledLuaScript

	mu.Lock()

	defer mu.Unlock()

	if _, found := LuaScripts[filePath]; !found {
		LuaScripts[filePath] = &PrecompiledLuaScript{}
	}

	luaScriptNew, err = NewLuaHook(filePath)
	if err != nil {
		return err
	}

	LuaScripts[filePath].Replace(luaScriptNew)

	for luaScriptName := range LuaScripts {
		if luaScriptName != config.LoadableConfig.GetLuaCallbackScriptPath() && luaScriptName != config.LoadableConfig.GetLuaInitScriptPath() {
			if LuaScripts[luaScriptName].GetPrecompiledScript() == nil {
				delete(LuaScripts, luaScriptName)
			}
		}
	}

	return nil
}

// PreCompileLuaHooks precompiles Lua scripts for pre-defined hooks in the configuration. If Lua hooks are enabled in the
// configuration and no custom location exists, a new custom location is created. Iterates through the hooks list, precompiles
// each Lua script, and associates it with the corresponding HTTP method and location.
func PreCompileLuaHooks() error {
	if config.LoadableConfig.HaveLuaHooks() {
		if customLocation == nil {
			customLocation = NewCustomLocation()
		}

		for index := range config.LoadableConfig.Lua.Hooks {
			script, err := NewLuaHook(config.LoadableConfig.Lua.Hooks[index].ScriptPath)
			if err != nil {
				return err
			}

			// Add compiled Lua hook.
			customLocation.SetScript(config.LoadableConfig.Lua.Hooks[index].Location, config.LoadableConfig.Lua.Hooks[index].Method, script)
		}
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
	logFormat := definitions.LogFormatDefault
	logLevel := config.LoadableConfig.Server.Log.Level.Get()

	if config.LoadableConfig.Server.Log.JSON {
		logFormat = definitions.LogFormatJSON
	}

	logTable.RawSetString(definitions.LuaRequestLogFormat, lua.LString(logFormat))
	logTable.RawSetString(definitions.LuaRequestLogLevel, lua.LString(logLevel))

	return logTable
}

// registerDynamicLoader sets up a new function in the Lua state that allows for dynamic loading of modules based on their names.
func registerDynamicLoader(L *lua.LState, ctx context.Context, useGin bool) {
	dynamicLoader := L.NewFunction(func(L *lua.LState) int {
		modName := L.CheckString(1)
		registry := make(map[string]bool)
		if _, found := registry[modName]; found {
			return 0
		}

		lualib.RegisterCommonLuaLibraries(L, ctx, modName, registry, httpClient)

		if useGin {
			registerModule(L, ctx.(*gin.Context), modName, registry, useGin)
		} else {
			registerModule(L, ctx, modName, registry, useGin)
		}

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
func registerModule(L *lua.LState, ctx context.Context, modName string, registry map[string]bool, useGin bool) {
	switch modName {
	case definitions.LuaModHTTPRequest:
		if useGin {
			L.PreloadModule(modName, lualib.LoaderModHTTPRequest(ctx.(*gin.Context).Request))
		} else {
			return
		}
	case definitions.LuaModLDAP:
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

// runLuaCommonWrapper executes a requested precompiled Lua script with the given hook name within a provided context.
// It registers a dynamic loader within the Lua state, sets up logging, and handles script execution errors.
// Parameters:
// - ctx: The execution context for managing cancellation and timeouts.
// - hook: The identifier for selecting the precompiled Lua script to run.
// - registerDynamicLoader: The function to register dynamic modules in the Lua state.
// Returns an error if the script is not found or fails to execute correctly.
func runLuaCommonWrapper(ctx context.Context, hook string, registerDynamicLoader func(*lua.LState, context.Context)) error {
	var (
		found  bool
		script *PrecompiledLuaScript
	)

	if script, found = LuaScripts[hook]; !found || script == nil {
		return fmt.Errorf("lua script for hook %s not found", hook)
	}

	luaCtx, luaCancel := context.WithTimeout(ctx, viper.GetDuration("lua_script_timeout")*time.Second)

	defer luaCancel()

	L := lua.NewState()

	defer L.Close()

	registerDynamicLoader(L, ctx)

	L.SetContext(luaCtx)

	logTable := setupLogging(L)

	_, err := executeAndHandleError(script.GetPrecompiledScript(), logTable, L, hook)

	return err
}

// runLuaCustomWrapper runs a precompiled Lua script for a specified hook with a given dynamic loader registration function.
// It retrieves the Lua script, sets up the Lua state, registers the dynamic loader, and logs the execution process.
func runLuaCustomWrapper(ctx *gin.Context, registerDynamicLoader func(*lua.LState, context.Context)) (gin.H, error) {
	var script *PrecompiledLuaScript

	hook := ctx.Param("hook")

	if script = customLocation.GetScript(hook, ctx.Request.Method); script == nil {
		return gin.H{}, fmt.Errorf("lua script for location '%s' not found", hook)
	}

	luaCtx, luaCancel := context.WithTimeout(ctx, viper.GetDuration("lua_script_timeout")*time.Second)

	defer luaCancel()

	L := lua.NewState()

	defer L.Close()

	registerDynamicLoader(L, ctx)

	L.SetContext(luaCtx)

	logTable := setupLogging(L)

	return executeAndHandleError(script.GetPrecompiledScript(), logTable, L, hook)
}

// registerDynamicLoaderGin registers a dynamic loader function in the Lua state (L)
func registerDynamicLoaderGin(L *lua.LState, ctx context.Context) {
	registerDynamicLoader(L, ctx, true)
}

// registerDynamicLoaderInit initializes the dynamic loader functionality within the given Lua state.
func registerDynamicLoaderInit(L *lua.LState, ctx context.Context) {
	registerDynamicLoader(L, ctx, false)
}

// RunLuaCallback runs a Lua callback request in a Gin context.
func RunLuaCallback(ctx *gin.Context, hook string) error {
	return runLuaCommonWrapper(ctx, hook, registerDynamicLoaderGin)
}

// RunLuaHook executes a precompiled Lua script based on a hook parameter from the gin.Context.
func RunLuaHook(ctx *gin.Context) (gin.H, error) {
	return runLuaCustomWrapper(ctx, registerDynamicLoaderGin)
}

// RunLuaInit initializes and runs a Lua script based on the specified hook.
func RunLuaInit(ctx context.Context, hook string) error {
	return runLuaCommonWrapper(ctx, hook, registerDynamicLoaderInit)
}

// executeAndHandleError executes the compiled Lua script and handles any errors that occur.
// It first sets the Lua package path using lualib.PackagePath and includes the directory where the Lua modules reside.
// Then it calls lualib.DoCompiledFile to run the script in the LState and checks for any errors.
// Finally, it calls L.CallByParam to call the Lua function specified by definitions.LuaFnRunHook, and checks for any errors.
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
func executeAndHandleError(compiledScript *lua.FunctionProto, logTable *lua.LTable, L *lua.LState, hook string) (result gin.H, err error) {
	if err = lualib.PackagePath(L); err != nil {
		processError(err, hook)
	}

	if err = lualib.DoCompiledFile(L, compiledScript); err != nil {
		processError(err, hook)
	}

	if err = L.CallByParam(lua.P{
		Fn:      L.GetGlobal(definitions.LuaFnRunHook),
		NRet:    1,
		Protect: true,
	}, logTable); err != nil {
		processError(err, hook)
	}

	if L.GetTop() == 1 {
		luaResult := L.ToTable(-1)
		result = make(gin.H)

		anyTable := convert.LuaValueToGo(luaResult).(map[any]any)

		for key, value := range anyTable {
			if keyName, okay := key.(string); okay {
				result[keyName] = value
			} else {
				result[fmt.Sprintf("%v", key)] = value
			}
		}
	}

	return
}

// processError logs the given error message with the specified error level. It includes the script path and the error itself in the log entry.
// Parameters:
//   - err: The error to be logged.
//
// Usage Example:
//
//	executeAndHandleError(compiledScript, L)
func processError(err error, hook string) {
	level.Error(log.Logger).Log(
		"script", hook,
		definitions.LogKeyMsg, err,
	)
}
