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
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/jwtutil"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib"
	bflib "github.com/croessner/nauthilus/server/lualib/bruteforce"
	"github.com/croessner/nauthilus/server/lualib/connmgr"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/lualib/luapool"
	"github.com/croessner/nauthilus/server/lualib/redislib"
	"github.com/croessner/nauthilus/server/lualib/vmpool"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/svcctx"
	"github.com/croessner/nauthilus/server/util"

	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/gin-gonic/gin"
	lua "github.com/yuin/gopher-lua"
	"go.opentelemetry.io/otel/attribute"
)

var (
	// LuaScripts is a map that stores precompiled Lua scripts, allowing safe concurrent access and manipulation.
	LuaScripts = make(map[string]*PrecompiledLuaScript)

	// hookRoles is a map that associates each Location and HTTP method with its corresponding roles.
	hookRoles = make(map[string][]string)

	mu sync.RWMutex
)

// customLocation is a map that associates each Location with its corresponding CustomHook.
// It allows retrieving precompiled Lua scripts based on location and HTTP method.
var customLocation CustomLocation

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
	// Try with the original location
	if hook := l.GetCustomHook(location); hook != nil {
		if script := hook.GetScript(method); script != nil {
			return script
		}
	}

	// If not found and location doesn't have a leading slash, try with a leading slash
	if !strings.HasPrefix(location, "/") {
		if hook := l.GetCustomHook("/" + location); hook != nil {
			if script := hook.GetScript(method); script != nil {
				return script
			}
		}
	}

	// If not found and location has a leading slash, try without it
	if strings.HasPrefix(location, "/") {
		if hook := l.GetCustomHook(strings.TrimPrefix(location, "/")); hook != nil {
			if script := hook.GetScript(method); script != nil {
				return script
			}
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

// getHookKey generates a unique key for a hook based on its location and method.
func getHookKey(location, method string) string {
	return strings.TrimLeft(location, "/") + ":" + method
}

// GetHookRoles returns the roles required for a specific hook.
func GetHookRoles(location, method string) []string {
	hookKey := getHookKey(location, method)

	mu.RLock()
	roles := hookRoles[hookKey]
	mu.RUnlock()

	return roles
}

// HasRequiredRoles checks if the user has any of the required roles for a hook.
// If no roles are configured for the hook, it returns true (allowing access).
// If JWT is not enabled or not properly configured, it returns true (allowing access).
func HasRequiredRoles(ctx *gin.Context, cfg config.File, logger *slog.Logger, location, method string) bool {
	guid := ctx.GetString(definitions.CtxGUIDKey)

	// Check if JWT auth is enabled
	jwtAuth := cfg.GetServer().GetJWTAuth()
	if !jwtAuth.IsEnabled() {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			cfg,
			logger,
			definitions.DbgLua,
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "JWT authentication is not enabled, allowing access",
		)

		return true
	}

	// Check if JWT auth is properly configured
	if jwtAuth.GetSecretKey() == "" || len(jwtAuth.GetUsers()) == 0 {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			cfg,
			logger,
			definitions.DbgLua,
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "JWT authentication is not properly configured, allowing access",
		)

		return true
	}

	// Get the roles required for this hook
	requiredRoles := GetHookRoles(location, method)
	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		cfg,
		logger,
		definitions.DbgLua,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, fmt.Sprintf("Required roles for hook %s %s: %v", location, method, requiredRoles),
	)

	// If no roles are configured, allow access
	if len(requiredRoles) == 0 {
		// Try with a leading slash if no roles were found
		if !strings.HasPrefix(location, "/") {
			locationWithSlash := "/" + location
			requiredRoles = GetHookRoles(locationWithSlash, method)
			util.DebugModuleWithCfg(
				ctx.Request.Context(),
				cfg,
				logger,
				definitions.DbgLua,
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, fmt.Sprintf("Trying with leading slash: %s, required roles: %v", locationWithSlash, requiredRoles),
			)
		}

		// If still no roles are configured, allow access
		if len(requiredRoles) == 0 {
			util.DebugModuleWithCfg(
				ctx.Request.Context(),
				cfg,
				logger,
				definitions.DbgLua,
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "No roles configured for this hook, allowing access",
			)

			return true
		}
	}

	// Check if the user has any of the required roles
	for _, role := range requiredRoles {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			cfg,
			logger,
			definitions.DbgLua,
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, fmt.Sprintf("Checking if user has role: %s", role),
		)

		if jwtutil.HasRole(ctx, role) {
			util.DebugModuleWithCfg(
				ctx.Request.Context(),
				cfg,
				logger,
				definitions.DbgLua,
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, fmt.Sprintf("User has required role: %s, allowing access", role),
			)

			return true
		}
	}

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		cfg,
		logger,
		definitions.DbgLua,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, fmt.Sprintf("User does not have any of the required roles: %v, denying access", requiredRoles),
	)

	return false
}

// PreCompileLuaScript compiles a Lua script from the specified file path and manages the script in a thread-safe map.
// Updates or removes entries in the LuaScripts map based on the configuration and compilation status.
// Returns an error if the compilation fails or if the script cannot be managed properly.
func PreCompileLuaScript(cfg config.File, filePath string) (err error) {
	tr := monittrace.New("nauthilus/hooks")
	ctx, sp := tr.Start(svcctx.Get(), "hooks.precompile_script",
		attribute.String("file", filePath),
	)

	_ = ctx

	defer func() {
		if err != nil {
			sp.RecordError(err)
		}
		sp.End()
	}()

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

	// Get all init script paths
	initScriptPaths := cfg.GetLuaInitScriptPaths()

	for luaScriptName := range LuaScripts {
		// Check if this script is one of the init scripts
		isInitScript := false
		for _, initScriptPath := range initScriptPaths {
			if luaScriptName == initScriptPath {
				isInitScript = true

				break
			}
		}

		// If it's not an init script and has no compiled script, delete it
		if !isInitScript {
			if LuaScripts[luaScriptName].GetPrecompiledScript() == nil {
				delete(LuaScripts, luaScriptName)
			}
		}
	}

	return nil
}

// PreCompileLuaHooks pre-compiles Lua hook scripts defined in the configuration and assigns them to specified locations and methods.
// It also stores the roles associated with each hook for role-based access control.
// Returns an error if the compilation or setup fails.
func PreCompileLuaHooks(cfg config.File) error {
	tr := monittrace.New("nauthilus/hooks")
	ctx, sp := tr.Start(svcctx.Get(), "hooks.precompile_all",
		attribute.Int("configured", func() int {
			if cfg.HaveLuaHooks() {
				return len(cfg.GetLua().Hooks)
			}
			return 0
		}()),
	)
	_ = ctx

	defer sp.End()

	if cfg.HaveLuaHooks() {
		if customLocation == nil {
			customLocation = NewCustomLocation()
		}

		// Clear the hookRoles map before repopulating it
		mu.Lock()
		hookRoles = make(map[string][]string)
		mu.Unlock()

		for index := range cfg.GetLua().Hooks {
			hook := cfg.GetLua().Hooks[index]

			script, err := NewLuaHook(hook.ScriptPath)
			if err != nil {
				sp.RecordError(err)

				return err
			}

			customLocation.SetScript(hook.Location, hook.Method, script)

			// Store the roles for this hook
			hookKey := getHookKey(hook.Location, hook.Method)

			mu.Lock()
			hookRoles[hookKey] = hook.GetRoles()
			mu.Unlock()
		}
	}

	return nil
}

// setupLogging configures the logging settings in the Lua state and returns a table containing the log format and level.
func setupLogging(cfg config.File, L *lua.LState) *lua.LTable {
	logTable := L.NewTable()
	logFormat := definitions.LogFormatDefault
	logLevel := cfg.GetServer().GetLog().GetLogLevelName()

	if cfg.GetServer().GetLog().IsLogFormatJSON() {
		logFormat = definitions.LogFormatJSON
	}

	logTable.RawSetString(definitions.LuaRequestLogFormat, lua.LString(logFormat))
	logTable.RawSetString(definitions.LuaRequestLogLevel, lua.LString(logLevel))

	return logTable
}

// runLuaCommonWrapper executes a precompiled Lua script associated with the given hook within a controlled Lua state context.
// It applies the specified dynamic loader to register custom modules or functions, enforces a timeout for execution, and configures logging.
// Returns an error if the script is not found or if execution fails.
func runLuaCommonWrapper(ctx context.Context, cfg config.File, logger *slog.Logger, redis rediscli.Client, hook string) error {
	tr := monittrace.New("nauthilus/hooks")
	cctx, csp := tr.Start(ctx, "hooks.execute_common",
		attribute.String("hook", hook),
	)

	_ = cctx

	defer func() {
		if r := recover(); r != nil {
			// do not record panic as error here; existing code handles replaceVM; but we still mark error
			// leave as attribute to avoid double logging
			csp.SetAttributes(attribute.String("panic", "true"))
		}
		csp.End()
	}()

	var (
		found  bool
		script *PrecompiledLuaScript
	)

	if script, found = LuaScripts[hook]; !found || script == nil {
		return fmt.Errorf("lua script for hook %s not found", hook)
	}

	luaCtx, luaCancel := context.WithTimeout(ctx, cfg.GetServer().GetTimeouts().GetLuaScript())
	defer luaCancel()

	pool := vmpool.GetManager().GetOrCreate("hook:default", vmpool.PoolOptions{
		MaxVMs: cfg.GetLuaHookVMPoolSize(),
		Config: cfg,
	})

	L, acqErr := pool.Acquire(luaCtx)
	if acqErr != nil {
		return acqErr
	}

	replaceVM := false
	defer func() {
		if r := recover(); r != nil {
			replaceVM = true
		}

		if replaceVM {
			pool.Replace(L)
		} else {
			pool.Release(L)
		}
	}()

	L.SetContext(luaCtx)

	// Prepare per-request environment so that request-local globals and module bindings are visible
	luapool.PrepareRequestEnv(L)

	// Bind required per-request modules so that require() resolves to the bound versions.
	// 1) nauthilus_context (fresh per-request context)
	if loader := lualib.LoaderModContext(lualib.NewContext()); loader != nil {
		_ = loader(L)
		if mod, ok := L.Get(-1).(*lua.LTable); ok {
			L.Pop(1)
			luapool.BindModuleIntoReq(L, definitions.LuaModContext, mod)
		} else {
			L.Pop(1)
		}
	}

	// 2) nauthilus_redis (use luaCtx deadline)
	if loader := redislib.LoaderModRedis(luaCtx, cfg, redis); loader != nil {
		_ = loader(L)
		if mod, ok := L.Get(-1).(*lua.LTable); ok {
			L.Pop(1)
			luapool.BindModuleIntoReq(L, definitions.LuaModRedis, mod)
		} else {
			L.Pop(1)
		}
	}

	// 3) nauthilus_ldap (if enabled)
	if cfg.HaveLDAPBackend() {
		loader := backend.LoaderModLDAP(luaCtx, cfg)
		_ = loader(L)
		if mod, ok := L.Get(-1).(*lua.LTable); ok {
			L.Pop(1)
			luapool.BindModuleIntoReq(L, definitions.LuaModLDAP, mod)
		} else {
			L.Pop(1)
		}
	}

	// 4) nauthilus_psnet (connection monitoring)
	if loader := connmgr.LoaderModPsnet(luaCtx, cfg, logger); loader != nil {
		_ = loader(L)
		if mod, ok := L.Get(-1).(*lua.LTable); ok {
			L.Pop(1)
			luapool.BindModuleIntoReq(L, definitions.LuaModPsnet, mod)
		} else {
			L.Pop(1)
		}
	}

	// 5) nauthilus_dns (DNS lookups)
	if loader := lualib.LoaderModDNS(luaCtx, cfg, logger); loader != nil {
		_ = loader(L)
		if mod, ok := L.Get(-1).(*lua.LTable); ok {
			L.Pop(1)
			luapool.BindModuleIntoReq(L, definitions.LuaModDNS, mod)
		} else {
			L.Pop(1)
		}
	}

	// 5.1) nauthilus_opentelemetry (OTel helpers for Lua)
	{
		var loader lua.LGFunction
		if cfg.GetServer().GetInsights().GetTracing().IsEnabled() {
			loader = lualib.LoaderModOTEL(luaCtx, cfg, logger)
		} else {
			loader = lualib.LoaderOTELStateless()
		}

		if loader != nil {
			_ = loader(L)
			if mod, ok := L.Get(-1).(*lua.LTable); ok {
				L.Pop(1)
				luapool.BindModuleIntoReq(L, definitions.LuaModOpenTelemetry, mod)
			} else {
				L.Pop(1)
			}
		}
	}

	// 6) nauthilus_brute_force (toleration and blocking helpers)
	if loader := bflib.LoaderModBruteForce(luaCtx, cfg, logger, redis, tolerate.GetTolerate()); loader != nil {
		_ = loader(L)
		if mod, ok := L.Get(-1).(*lua.LTable); ok {
			L.Pop(1)
			luapool.BindModuleIntoReq(L, definitions.LuaModBruteForce, mod)
		} else {
			L.Pop(1)
		}
	}

	logTable := setupLogging(cfg, L)

	_, err := executeAndHandleError(cfg, logger, script.GetPrecompiledScript(), logTable, L, hook, "")
	if err != nil {
		csp.RecordError(err)
	}

	return err
}

// runLuaCustomWrapper executes a precompiled Lua script and returns its result or any occurring error.
// It retrieves the script based on the HTTP request context and dynamically registers Lua libraries before execution.
func runLuaCustomWrapper(ctx *gin.Context, cfg config.File, logger *slog.Logger, redis rediscli.Client) (gin.H, error) {
	tr := monittrace.New("nauthilus/hooks")
	xctx, xsp := tr.Start(ctx.Request.Context(), "hooks.execute_custom",
		attribute.String("path", ctx.Param("hook")),
		attribute.String("method", ctx.Request.Method),
	)

	// propagate tracing context into request
	ctx.Request = ctx.Request.WithContext(xctx)

	defer xsp.End()

	var script *PrecompiledLuaScript

	guid := ctx.GetString(definitions.CtxGUIDKey)
	hook := ctx.Param("hook")

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		cfg,
		logger,
		definitions.DbgLua,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, fmt.Sprintf("Looking for script for hook: %s, method: %s", hook, ctx.Request.Method),
	)

	if script = customLocation.GetScript(hook, ctx.Request.Method); script == nil {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			cfg,
			logger,
			definitions.DbgLua,
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, fmt.Sprintf("Script not found for hook: %s, method: %s", hook, ctx.Request.Method),
		)
		ctx.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "lua script for location '" + hook + "' not found", "guid": guid})

		return nil, nil
	}

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		cfg,
		logger,
		definitions.DbgLua,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, fmt.Sprintf("Script found for hook: %s, method: %s", hook, ctx.Request.Method),
	)

	luaCtx, luaCancel := context.WithTimeout(ctx, cfg.GetServer().GetTimeouts().GetLuaScript())

	defer luaCancel()

	pool := vmpool.GetManager().GetOrCreate("hook:default", vmpool.PoolOptions{
		MaxVMs: cfg.GetLuaHookVMPoolSize(),
		Config: cfg,
	})

	L, acqErr := pool.Acquire(luaCtx)
	if acqErr != nil {
		return nil, acqErr
	}

	replaceVM := false
	defer func() {
		if r := recover(); r != nil {
			replaceVM = true
		}

		if replaceVM {
			pool.Replace(L)
		} else {
			pool.Release(L)
		}
	}()

	L.SetContext(luaCtx)

	// Prepare per-request environment so that request-local globals and module bindings are visible
	luapool.PrepareRequestEnv(L)

	// Bind required per-request modules so that require() resolves to the bound versions.
	// 1) nauthilus_context (fresh per-request context)
	if loader := lualib.LoaderModContext(lualib.NewContext()); loader != nil {
		_ = loader(L)
		if mod, ok := L.Get(-1).(*lua.LTable); ok {
			L.Pop(1)
			luapool.BindModuleIntoReq(L, definitions.LuaModContext, mod)
		} else {
			L.Pop(1)
		}
	}

	// 2) nauthilus_http_request (from gin request)
	loader := lualib.LoaderModHTTP(lualib.NewHTTPMetaFromRequest(ctx.Request))
	_ = loader(L)
	if mod, ok := L.Get(-1).(*lua.LTable); ok {
		L.Pop(1)
		luapool.BindModuleIntoReq(L, definitions.LuaModHTTPRequest, mod)
	} else {
		L.Pop(1)
	}

	// 3) nauthilus_http_response
	loader = lualib.LoaderModHTTPResponse(ctx)
	_ = loader(L)
	if mod, ok := L.Get(-1).(*lua.LTable); ok {
		L.Pop(1)
		luapool.BindModuleIntoReq(L, definitions.LuaModHTTPResponse, mod)
	} else {
		L.Pop(1)
	}

	// 4) nauthilus_redis (use luaCtx deadline)
	if loader = redislib.LoaderModRedis(luaCtx, cfg, redis); loader != nil {
		_ = loader(L)
		if mod, ok := L.Get(-1).(*lua.LTable); ok {
			L.Pop(1)
			luapool.BindModuleIntoReq(L, definitions.LuaModRedis, mod)
		} else {
			L.Pop(1)
		}
	}

	// 5) nauthilus_ldap (if enabled)
	if cfg.HaveLDAPBackend() {
		loader := backend.LoaderModLDAP(luaCtx, cfg)
		_ = loader(L)
		if mod, ok := L.Get(-1).(*lua.LTable); ok {
			L.Pop(1)
			luapool.BindModuleIntoReq(L, definitions.LuaModLDAP, mod)
		} else {
			L.Pop(1)
		}
	}

	// 6) nauthilus_psnet (connection monitoring)
	if loader := connmgr.LoaderModPsnet(luaCtx, cfg, logger); loader != nil {
		_ = loader(L)
		if mod, ok := L.Get(-1).(*lua.LTable); ok {
			L.Pop(1)
			luapool.BindModuleIntoReq(L, definitions.LuaModPsnet, mod)
		} else {
			L.Pop(1)
		}
	}

	// 7) nauthilus_dns (DNS lookups)
	if loader := lualib.LoaderModDNS(luaCtx, cfg, logger); loader != nil {
		_ = loader(L)
		if mod, ok := L.Get(-1).(*lua.LTable); ok {
			L.Pop(1)
			luapool.BindModuleIntoReq(L, definitions.LuaModDNS, mod)
		} else {
			L.Pop(1)
		}
	}

	// 7.1) nauthilus_opentelemetry (OTel helpers for Lua)
	{
		var loader lua.LGFunction
		if cfg.GetServer().GetInsights().GetTracing().IsEnabled() {
			loader = lualib.LoaderModOTEL(luaCtx, cfg, logger)
		} else {
			loader = lualib.LoaderOTELStateless()
		}

		if loader != nil {
			_ = loader(L)
			if mod, ok := L.Get(-1).(*lua.LTable); ok {
				L.Pop(1)
				luapool.BindModuleIntoReq(L, definitions.LuaModOpenTelemetry, mod)
			} else {
				L.Pop(1)
			}
		}
	}

	// 8) nauthilus_brute_force (toleration and blocking helpers)
	if loader := bflib.LoaderModBruteForce(luaCtx, cfg, logger, redis, tolerate.GetTolerate()); loader != nil {
		_ = loader(L)
		if mod, ok := L.Get(-1).(*lua.LTable); ok {
			L.Pop(1)
			luapool.BindModuleIntoReq(L, definitions.LuaModBruteForce, mod)
		} else {
			L.Pop(1)
		}
	}

	logTable := setupLogging(cfg, L)

	result, err := executeAndHandleError(cfg, logger, script.GetPrecompiledScript(), logTable, L, hook, guid)
	if err != nil {
		xsp.RecordError(err)
		level.Error(logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, fmt.Sprintf("Error executing script for hook: %s, method: %s", hook, ctx.Request.Method),
			definitions.LogKeyError, err,
		)
	} else {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			cfg,
			logger,
			definitions.DbgLua,
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, fmt.Sprintf("Script executed successfully for hook: %s, method: %s", hook, ctx.Request.Method),
		)
	}

	return result, err
}

// RunLuaHook executes a precompiled Lua script based on a hook parameter from the gin.Context.
func RunLuaHook(ctx *gin.Context, cfg config.File, logger *slog.Logger, redis rediscli.Client) (gin.H, error) {
	return runLuaCustomWrapper(ctx, cfg, logger, redis)
}

func RunLuaInit(ctx context.Context, cfg config.File, logger *slog.Logger, redis rediscli.Client, hook string) error {
	return runLuaCommonWrapper(ctx, cfg, logger, redis, hook)
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
func executeAndHandleError(cfg config.File, logger *slog.Logger, compiledScript *lua.FunctionProto, logTable *lua.LTable, L *lua.LState, hook, guid string) (result gin.H, err error) {
	if err = lualib.PackagePath(L, cfg); err != nil {
		processError(logger, err, hook)
	}

	if err = lualib.DoCompiledFile(L, compiledScript); err != nil {
		processError(logger, err, hook)
	}

	// Resolve the entry function nauthilus_run_hook from the request env first, then fall back to _G.
	// Because the script chunk is executed under __NAUTH_REQ_ENV (via DoCompiledFile + SetFEnv),
	// global assignments inside the script land in the reqEnv table, not in _G.
	runHookFn := lua.LNil
	if v := L.GetGlobal("__NAUTH_REQ_ENV"); v != nil && v.Type() == lua.LTTable {
		if fn := L.GetField(v, definitions.LuaFnRunHook); fn != nil {
			runHookFn = fn
		}
	}

	if runHookFn == lua.LNil {
		runHookFn = L.GetGlobal(definitions.LuaFnRunHook)
	}

	if runHookFn.Type() != lua.LTFunction {
		// Provide a clear error instead of attempting to call a non-function (which results in "attempt to call a non-function object").
		return nil, fmt.Errorf("entry function '%s' is not defined as a function in the loaded script (hook: %s)", definitions.LuaFnRunHook, hook)
	}

	if err = L.CallByParam(lua.P{
		Fn:      runHookFn,
		NRet:    1,
		Protect: true,
	}, logTable, lua.LString(guid)); err != nil {
		processError(logger, err, hook)
	}

	// Interpret the Lua return value correctly:
	// - nil (or no return) => no Gin result (keep result == nil)
	// - table (map-like)   => convert to gin.H
	// - table (array-like) => error if non-empty (invalid result)
	if L.GetTop() == 1 {
		lv := L.Get(-1)
		if lv != lua.LNil {
			switch value := convert.LuaValueToGo(lv).(type) {
			case map[any]any:
				result = convert.ToGinH(value)
				if result == nil {
					// Non-map table provided; signal invalid result
					result = gin.H{}
					err = fmt.Errorf("custom location '%s' returned invalid result", hook)
				}
			case []any:
				// An empty Lua array means 'no content'; if non-empty, it's invalid for hooks
				if len(value) > 0 {
					result = gin.H{}
					err = fmt.Errorf("custom location '%s' returned invalid result, expected a map", hook)
				}
			}
		}
	}

	return
}

// processError logs an error with the associated script hook for debugging or monitoring purposes.
func processError(logger *slog.Logger, err error, hook string) {
	// Include Lua stacktrace when available to simplify debugging
	var ae *lua.ApiError
	if errors.As(err, &ae) && ae != nil {
		level.Error(logger).Log(
			"script", hook,
			definitions.LogKeyMsg, "Error executing script",
			definitions.LogKeyError, ae.Error(),
			"stacktrace", ae.StackTrace,
		)

		return
	}

	level.Error(logger).Log(
		"script", hook,
		definitions.LogKeyMsg, "Error executing script",
		definitions.LogKeyError, err,
	)
}
