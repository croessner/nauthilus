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
	"strings"
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
	lua "github.com/yuin/gopher-lua"
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

// Replace updates the luaScript field of the current PrecompiledLuaScript instance with the luaScript from the provided instance.
func (p *PrecompiledLuaScript) Replace(luaScript *PrecompiledLuaScript) {
	p.mu.Lock()

	defer p.mu.Unlock()

	p.luaScript = luaScript.luaScript
}

// GetPrecompiledScript retrieves the stored precompiled Lua script (*lua.FunctionProto) with read lock for thread safety.
func (p *PrecompiledLuaScript) GetPrecompiledScript() *lua.FunctionProto {
	p.mu.RLock()

	defer p.mu.RUnlock()

	return p.luaScript
}

// NewLuaHook compiles a Lua script from the given file path and returns a PrecompiledLuaScript instance or an error.
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

// GetScript retrieves the precompiled Lua script associated with the specified HTTP method from the CustomHook.
// Returns the Lua script if found, otherwise returns nil.
func (h CustomHook) GetScript(method string) *PrecompiledLuaScript {
	if script, found := h[HttpMethod(method)]; found {
		return script
	}

	return nil
}

// SetScript associates a precompiled Lua script with a specific HTTP method in the CustomHook.
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

// GetCustomHook retrieves a CustomHook associated with the given location string.
// Returns the CustomHook if found, otherwise returns nil.
func (l CustomLocation) GetCustomHook(location string) CustomHook {
	if hook, found := l[Location(strings.TrimLeft(location, "/"))]; found {
		return hook
	}

	return nil
}

// GetScript retrieves a precompiled Lua script based on the provided location and HTTP method. Returns the script or nil.
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
		l[Location(strings.TrimLeft(location, "/"))] = NewCustomHook(method, script)
	}
}

// NewCustomLocation creates a new CustomLocation, which is a map of Location keys to CustomHook values.
func NewCustomLocation() CustomLocation {
	return make(CustomLocation)
}

// PreCompileLuaScript compiles a Lua script from the specified file path and manages the script in a thread-safe map.
// Updates or removes entries in the LuaScripts map based on the configuration and compilation status.
// Returns an error if the compilation fails or if the script cannot be managed properly.
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
		if luaScriptName != config.GetFile().GetLuaInitScriptPath() {
			if LuaScripts[luaScriptName].GetPrecompiledScript() == nil {
				delete(LuaScripts, luaScriptName)
			}
		}
	}

	return nil
}

// PreCompileLuaHooks pre-compiles Lua hook scripts defined in the configuration and assigns them to specified locations and methods.
// Returns an error if the compilation or setup fails.
func PreCompileLuaHooks() error {
	if config.GetFile().HaveLuaHooks() {
		if customLocation == nil {
			customLocation = NewCustomLocation()
		}

		for index := range config.GetFile().GetLua().Hooks {
			script, err := NewLuaHook(config.GetFile().GetLua().Hooks[index].ScriptPath)
			if err != nil {
				return err
			}

			// Add compiled Lua hook.
			customLocation.SetScript(config.GetFile().GetLua().Hooks[index].Location, config.GetFile().GetLua().Hooks[index].Method, script)
		}
	}

	return nil
}

// setupLogging configures the logging settings in the Lua state and returns a table containing the log format and level.
func setupLogging(L *lua.LState) *lua.LTable {
	logTable := L.NewTable()
	logFormat := definitions.LogFormatDefault
	logLevel := config.GetFile().GetServer().GetLog().GetLogLevelName()

	if config.GetFile().GetServer().GetLog().IsLogFormatJSON() {
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

// registerModule registers a specific Lua module into the given Lua state based on the provided module name and context.
func registerModule(L *lua.LState, ctx context.Context, modName string, registry map[string]bool, useGin bool) {
	switch modName {
	case definitions.LuaModHTTPRequest:
		if useGin {
			L.PreloadModule(modName, lualib.LoaderModHTTPRequest(ctx.(*gin.Context).Request))
		} else {
			return
		}
	case definitions.LuaModLDAP:
		if config.GetFile().HaveLDAPBackend() {
			L.PreloadModule(modName, backend.LoaderModLDAP(ctx))
		} else {
			L.RaiseError("LDAP backend not activated")
		}
	default:
		return
	}

	registry[modName] = true
}

// runLuaCommonWrapper executes a precompiled Lua script associated with the given hook within a controlled Lua state context.
// It applies the specified dynamic loader to register custom modules or functions, enforces a timeout for execution, and configures logging.
// Returns an error if the script is not found or if execution fails.
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

	_, err := executeAndHandleError(script.GetPrecompiledScript(), logTable, L, hook, "")

	return err
}

// runLuaCustomWrapper executes a precompiled Lua script and returns its result or any occurring error.
// It retrieves the script based on the HTTP request context and dynamically registers Lua libraries before execution.
func runLuaCustomWrapper(ctx *gin.Context, registerDynamicLoader func(*lua.LState, context.Context)) (gin.H, error) {
	var script *PrecompiledLuaScript

	guid := ctx.GetString(definitions.CtxGUIDKey)
	hook := ctx.Param("hook")

	if script = customLocation.GetScript(hook, ctx.Request.Method); script == nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "lua script for location '" + hook + "' not found", "guid": guid})

		return nil, nil
	}

	luaCtx, luaCancel := context.WithTimeout(ctx, viper.GetDuration("lua_script_timeout")*time.Second)

	defer luaCancel()

	L := lua.NewState()

	defer L.Close()

	registerDynamicLoader(L, ctx)

	L.SetContext(luaCtx)

	logTable := setupLogging(L)

	return executeAndHandleError(script.GetPrecompiledScript(), logTable, L, hook, guid)
}

// registerDynamicLoaderGin registers a dynamic loader function in the Lua state (L)
func registerDynamicLoaderGin(L *lua.LState, ctx context.Context) {
	registerDynamicLoader(L, ctx, true)
}

// registerDynamicLoaderInit initializes the dynamic loader functionality within the given Lua state.
func registerDynamicLoaderInit(L *lua.LState, ctx context.Context) {
	registerDynamicLoader(L, ctx, false)
}

// RunLuaHook executes a precompiled Lua script based on a hook parameter from the gin.Context.
func RunLuaHook(ctx *gin.Context) (gin.H, error) {
	return runLuaCustomWrapper(ctx, registerDynamicLoaderGin)
}

// RunLuaInit initializes and runs a Lua script based on the specified hook.
func RunLuaInit(ctx context.Context, hook string) error {
	return runLuaCommonWrapper(ctx, hook, registerDynamicLoaderInit)
}

// executeAndHandleError executes a Lua script, invoking a predefined hook and processing its results or errors.
// Parameters:
//   - compiledScript: Precompiled Lua script to execute.
//   - logTable: Lua table for logging configuration.
//   - L: Lua state.
//   - hook: Identifier for the script's hook.
//   - guid: Unique identifier for tracing execution.
//
// Returns a Gin-compatible result or an error encountered during executi
// Returns a Gin-compatible result or an error encountered during execution.
func executeAndHandleError(compiledScript *lua.FunctionProto, logTable *lua.LTable, L *lua.LState, hook, guid string) (result gin.H, err error) {
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
	}, logTable, lua.LString(guid)); err != nil {
		processError(err, hook)
	}

	if L.GetTop() == 1 {
		luaResult := L.ToTable(-1)
		switch value := convert.LuaValueToGo(luaResult).(type) {
		case map[any]any:
			result = convert.ToGinH(value)

			if result == nil {
				result = gin.H{}
				err = fmt.Errorf("custom location '%s' returned invalid result", hook)
			}
		case []any:
			// An empty Lua table is treated as a list, not a map!
			if len(value) > 0 {
				result = gin.H{}
				err = fmt.Errorf("custom location '%s' returned invalid result, expected a map", hook)
			}
		}
	}

	return
}

// processError logs an error with the associated script hook for debugging or monitoring purposes.
func processError(err error, hook string) {
	level.Error(log.Logger).Log(
		"script", hook,
		definitions.LogKeyMsg, err,
	)
}
