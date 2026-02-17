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
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/lualib/luamod"
	"github.com/croessner/nauthilus/server/lualib/luapool"
	"github.com/croessner/nauthilus/server/lualib/vmpool"
	"github.com/croessner/nauthilus/server/middleware/oidcbearer"
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

// GetHookScopes returns the roles required for a specific hook.
func GetHookScopes(location, method string) []string {
	hookKey := getHookKey(location, method)

	mu.RLock()
	roles := hookRoles[hookKey]
	mu.RUnlock()

	return roles
}

// HasRequiredScopes checks if the user has any of the required scopes for a hook.
// It performs the full authentication and authorization flow for custom hooks:
//   - No scopes configured → public hook, access allowed without token.
//   - Scopes configured → bearer token is extracted, validated via the TokenValidator,
//     and the resulting claims are checked for the required scopes.
//
// On denial the function aborts the request with the appropriate HTTP status
// (401 for missing/invalid token, 403 for insufficient scopes) and returns false.
// The caller should return immediately without writing further responses.
//
// The validator parameter may be nil when OIDC authentication is not configured;
// in that case any hook that requires scopes will be denied.
func HasRequiredScopes(ctx *gin.Context, cfg config.File, logger *slog.Logger, validator oidcbearer.TokenValidator, location, method string) bool {
	guid := ctx.GetString(definitions.CtxGUIDKey)

	// Get the roles required for this hook
	requiredScopes := resolveRequiredScopes(location, method, cfg, logger, guid, ctx)

	// If no roles are configured, this is a public hook — allow access regardless of token
	if len(requiredScopes) == 0 {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			cfg,
			logger,
			definitions.DbgLua,
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "No scopes configured for this hook, allowing access",
		)

		return true
	}

	// Scopes required but OIDC auth not configured — deny access
	if validator == nil {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			cfg,
			logger,
			definitions.DbgLua,
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, fmt.Sprintf("Hook requires scopes %v but OIDC auth is not configured, denying access", requiredScopes),
		)

		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required but not configured"})

		return false
	}

	// Extract bearer token from request
	tokenString, ok := oidcbearer.ExtractBearerToken(ctx)
	if !ok {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			cfg,
			logger,
			definitions.DbgLua,
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, fmt.Sprintf("No bearer token but hook requires scopes %v, denying access", requiredScopes),
		)

		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid authorization header"})

		return false
	}

	// Validate token and store claims in context (aborts with 401 on failure)
	claims := oidcbearer.ValidateAndStoreClaims(ctx, validator, cfg, tokenString)
	if claims == nil {
		return false
	}

	// Check if the token has any of the required scopes
	for _, scope := range requiredScopes {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			cfg,
			logger,
			definitions.DbgLua,
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, fmt.Sprintf("Checking if token has scope: %s", scope),
		)

		if oidcbearer.HasScope(claims, scope) {
			util.DebugModuleWithCfg(
				ctx.Request.Context(),
				cfg,
				logger,
				definitions.DbgLua,
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, fmt.Sprintf("Token has required scope: %s, allowing access", scope),
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
		definitions.LogKeyMsg, fmt.Sprintf("Token does not have any of the required scopes: %v, denying access", requiredScopes),
	)

	ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})

	return false
}

// resolveRequiredScopes looks up the required roles for a hook, trying both with and without a leading slash.
func resolveRequiredScopes(location, method string, cfg config.File, logger *slog.Logger, guid string, ctx *gin.Context) []string {
	requiredScopes := GetHookScopes(location, method)

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		cfg,
		logger,
		definitions.DbgLua,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, fmt.Sprintf("Required scopes for hook %s %s: %v", location, method, requiredScopes),
	)

	if len(requiredScopes) == 0 && !strings.HasPrefix(location, "/") {
		locationWithSlash := "/" + location

		requiredScopes = GetHookScopes(locationWithSlash, method)

		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			cfg,
			logger,
			definitions.DbgLua,
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, fmt.Sprintf("Trying with leading slash: %s, required scopes: %v", locationWithSlash, requiredScopes),
		)
	}

	return requiredScopes
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
			hookRoles[hookKey] = hook.GetScopes()
			mu.Unlock()
		}
	}

	return nil
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

	modManager := luamod.NewModuleManager(ctx, cfg, logger, redis)

	modManager.BindAllDefault(L, lualib.NewContext(), luaCtx, tolerate.GetTolerate())
	modManager.BindLDAP(L, backend.LoaderModLDAP(luaCtx, cfg))

	requestTable := L.NewTable()
	cr := lualib.GetCommonRequest()

	defer lualib.PutCommonRequest(cr)

	cr.RedisPrefix = cfg.GetServer().GetRedis().GetPrefix()
	cr.SetupRequest(L, cfg, requestTable)

	_, err := executeAndHandleError(cfg, logger, script.GetPrecompiledScript(), L, hook, requestTable)
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

	modManager := luamod.NewModuleManager(ctx, cfg, logger, redis)

	modManager.BindAllDefault(L, lualib.NewContext(), luaCtx, tolerate.GetTolerate())
	modManager.BindHTTP(L, lualib.NewHTTPMetaFromRequest(ctx.Request))
	modManager.BindHTTPResponse(L, ctx)
	modManager.BindLDAP(L, backend.LoaderModLDAP(luaCtx, cfg))

	requestTable := L.NewTable()
	cr := lualib.GetCommonRequest()

	defer lualib.PutCommonRequest(cr)

	cr.Session = guid
	cr.RedisPrefix = cfg.GetServer().GetRedis().GetPrefix()
	cr.SetupRequest(L, cfg, requestTable)

	result, err := executeAndHandleError(cfg, logger, script.GetPrecompiledScript(), L, hook, requestTable)
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
//   - L: Lua state.
//   - hook: Identifier for the script's hook.
//   - requestTable: Lua table for the request object.
//
// Returns a Gin-compatible result or an error encountered during execution.
func executeAndHandleError(cfg config.File, logger *slog.Logger, compiledScript *lua.FunctionProto, L *lua.LState, hook string, requestTable *lua.LTable) (result gin.H, err error) {
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
	}, requestTable); err != nil {
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
	if ae, ok := errors.AsType[*lua.ApiError](err); ok && ae != nil {
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
