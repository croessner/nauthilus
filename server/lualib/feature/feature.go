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

package feature

import (
	"context"
	stderrors "errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/vmpool"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/spf13/viper"
	lua "github.com/yuin/gopher-lua"
	"golang.org/x/sync/errgroup"
)

// LuaFeatures is a global variable that holds a collection of pre-compiled Lua features for the application.
var LuaFeatures *PreCompiledLuaFeatures

// httpClient is a pre-configured instance of http.Client with custom timeout and TLS settings for making HTTP requests.
var httpClient *http.Client

// InitHTTPClient initializes the global httpClient variable with a pre-configured instance from util.NewHTTPClient.
func InitHTTPClient() {
	httpClient = util.NewHTTPClient()
}

// PreCompileLuaFeatures pre-compiles Lua features listed in the configuration and initializes the global `LuaFeatures` variable.
// Returns an error if the pre-compilation process or Lua feature initialization fails, otherwise returns nil.
func PreCompileLuaFeatures() (err error) {
	if config.GetFile().HaveLuaFeatures() {
		if LuaFeatures == nil {
			LuaFeatures = &PreCompiledLuaFeatures{}
		} else {
			LuaFeatures.Reset()
		}

		for index := range config.GetFile().GetLua().Features {
			var luaFeature *LuaFeature

			luaFeature, err = NewLuaFeature(config.GetFile().GetLua().Features[index].Name, config.GetFile().GetLua().Features[index].ScriptPath)
			if err != nil {
				return err
			}

			// Add compiled Lua features.
			LuaFeatures.Add(luaFeature)
		}
	}

	return nil
}

// PreCompiledLuaFeatures represents a collection of pre-compiled Lua features.
// It contains an array of LuaFeature objects and a read-write mutex for synchronization.
type PreCompiledLuaFeatures struct {
	LuaScripts []*LuaFeature
	Mu         sync.RWMutex
}

// Add appends the given LuaFeature to the slice of LuaScripts in PreCompiledLuaFeatures.
func (a *PreCompiledLuaFeatures) Add(luaFeature *LuaFeature) {
	a.Mu.Lock()

	defer a.Mu.Unlock()

	a.LuaScripts = append(a.LuaScripts, luaFeature)
}

// Reset clears the LuaScripts slice and resets it to an empty state while ensuring thread-safe access via locking.
func (a *PreCompiledLuaFeatures) Reset() {
	a.Mu.Lock()

	defer a.Mu.Unlock()

	a.LuaScripts = make([]*LuaFeature, 0)
}

// LuaFeature represents a Lua feature that has been compiled.
// It contains a name identifying the feature and the compiled Lua script.
type LuaFeature struct {
	Name           string
	CompiledScript *lua.FunctionProto
}

// NewLuaFeature creates a new LuaFeature instance by compiling the Lua script found at the given path and assigning its name.
// Returns the LuaFeature instance or an error if either the name or scriptPath is empty, or if script compilation fails.
func NewLuaFeature(name string, scriptPath string) (*LuaFeature, error) {
	if name == "" {
		return nil, errors.ErrFeatureLuaNameMissing
	}

	if scriptPath == "" {
		return nil, errors.ErrFeatureLuaScriptPathEmpty
	}

	compiledScript, err := lualib.CompileLua(scriptPath)
	if err != nil {
		return nil, err
	}

	return &LuaFeature{
		Name:           name,
		CompiledScript: compiledScript,
	}, nil
}

// Request represents a request data structure with all the necessary information about a connection and SSL usage.
type Request struct {
	// Logs holds the custom log key-value pairs.
	Logs *lualib.CustomLogKeyValue

	// Context contains additional context data.
	*lualib.Context

	*lualib.CommonRequest
}

// registerDynamicLoader registers a Lua function "dynamic_loader" to dynamically load Lua modules in the given context.
func (r *Request) registerDynamicLoader(L *lua.LState, ctx *gin.Context) {
	dynamicLoader := L.NewFunction(func(L *lua.LState) int {
		modName := L.CheckString(1)

		registry := make(map[string]bool)
		if _, found := registry[modName]; found {
			return 0
		}

		lualib.RegisterCommonLuaLibraries(L, ctx, modName, registry, httpClient)
		r.registerModule(L, ctx, modName, registry)

		return 0
	})

	L.SetGlobal("dynamic_loader", dynamicLoader)
}

// registerModule preloads a Lua module by its name into the Lua state if not already registered in the registry.
// It supports specific modules like context, HTTP requests, LDAP, and neural, raising errors for unsupported configurations.
func (r *Request) registerModule(L *lua.LState, ctx *gin.Context, modName string, registry map[string]bool) {
	switch modName {
	case definitions.LuaModContext:
		L.PreloadModule(modName, lualib.LoaderModContext(r.Context))
	case definitions.LuaModHTTPRequest:
		L.PreloadModule(modName, lualib.LoaderModHTTPRequest(ctx.Request))
	case definitions.LuaModHTTPResponse:
		L.PreloadModule(modName, lualib.LoaderModHTTPResponse(ctx))
	case definitions.LuaModLDAP:
		if config.GetFile().HaveLDAPBackend() {
			L.PreloadModule(definitions.LuaModLDAP, backend.LoaderModLDAP(ctx))
		} else {
			L.RaiseError("LDAP backend not activated")
		}
	default:
		return
	}

	registry[modName] = true
}

// CallFeatureLua executes Lua scripts associated with features within the context of a request.
// It triggers actions or aborts features based on script results.
// Returns whether a feature was triggered, if features should be aborted, and any execution error.
func (r *Request) CallFeatureLua(ctx *gin.Context) (triggered bool, abortFeatures bool, err error) {
	startTime := time.Now()
	defer func() {
		latency := time.Since(startTime)
		if r.Logs == nil {
			r.Logs = new(lualib.CustomLogKeyValue)
		}
		r.Logs.Set(definitions.LogKeyFeatureLatency, fmt.Sprintf("%v", latency))
	}()

	if LuaFeatures == nil || len(LuaFeatures.LuaScripts) == 0 {
		return
	}

	LuaFeatures.Mu.RLock()

	defer LuaFeatures.Mu.RUnlock()

	pool := vmpool.GetManager().GetOrCreate("feature:default", vmpool.PoolOptions{MaxVMs: config.GetFile().GetLuaFeatureVMPoolSize()})

	triggered, abortFeatures, err = r.executeScripts(ctx, pool)

	return
}

// setGlobals initializes global Lua variables and functions for the given Lua state, setting up essential Lua constants and utilities.
func (r *Request) setGlobals(L *lua.LState) {
	r.Logs = new(lualib.CustomLogKeyValue)
	globals := L.NewTable()

	globals.RawSet(lua.LString(definitions.LuaFeatureTriggerNo), lua.LBool(false))
	globals.RawSet(lua.LString(definitions.LuaFeatureTriggerYes), lua.LBool(true))
	globals.RawSet(lua.LString(definitions.LuaFeatureAbortNo), lua.LBool(false))
	globals.RawSet(lua.LString(definitions.LuaFeatureAbortYes), lua.LBool(true))
	globals.RawSet(lua.LString(definitions.LuaFeatureResultOk), lua.LNumber(0))
	globals.RawSet(lua.LString(definitions.LuaFeatureResultFail), lua.LNumber(1))

	globals.RawSetString(definitions.LuaFnAddCustomLog, L.NewFunction(lualib.AddCustomLog(r.Logs)))
	globals.RawSetString(definitions.LuaFnSetStatusMessage, L.NewFunction(lualib.SetStatusMessage(&r.StatusMessage)))

	L.SetGlobal(definitions.LuaDefaultTable, globals)
}

// setRequest creates a new Lua table and sets the request properties as key-value pairs in the table. The table is then returned.
// The request table is then returned.
func (r *Request) setRequest(L *lua.LState) *lua.LTable {
	request := L.NewTable()

	r.CommonRequest.SetupRequest(request)

	return request
}

// executeScripts executes all Lua feature scripts in parallel. It waits for all to finish,
// then aggregates their results considering error, abort, and triggered semantics.
func (r *Request) executeScripts(ctx *gin.Context, pool *vmpool.Pool) (triggered bool, abortFeatures bool, err error) {
	// Prepare synchronization primitives and results storage
	type featResult struct {
		name       string
		triggered  bool
		abort      bool
		ret        int
		err        error
		logs       lualib.CustomLogKeyValue
		statusText *string
	}

	var (
		mu      sync.Mutex
		results = make([]*featResult, 0, len(LuaFeatures.LuaScripts))
	)

	// Use errgroup for cleaner goroutine management and first-error propagation
	g, egCtx := errgroup.WithContext(ctx)

	// Fast cancel if request context already canceled
	if stderrors.Is(ctx.Err(), context.Canceled) {
		return false, false, ctx.Err()
	}

	for index := range LuaFeatures.LuaScripts {
		idx := index
		feature := LuaFeatures.LuaScripts[idx]

		g.Go(func() error {
			util.DebugModule(definitions.DbgFeature,
				definitions.LogKeyGUID, r.Session,
				definitions.LogKeyMsg, "Executing feature script",
				"name", feature.Name,
			)

			// Per-feature Lua state from bounded vmpool
			Llocal, acqErr := pool.Acquire(egCtx)
			if acqErr != nil {
				return acqErr
			}

			replaceVM := false
			defer func() {
				if r := recover(); r != nil {
					replaceVM = true
				}

				if replaceVM {
					pool.Replace(Llocal)
				} else {
					pool.Release(Llocal)
				}
			}()

			// Register dynamic loader for this state
			r.registerDynamicLoader(Llocal, ctx)

			// Per-feature globals and local logs/status
			localLogs := new(lualib.CustomLogKeyValue)

			var localStatus *string

			globals := Llocal.NewTable()

			globals.RawSet(lua.LString(definitions.LuaFeatureTriggerNo), lua.LBool(false))
			globals.RawSet(lua.LString(definitions.LuaFeatureTriggerYes), lua.LBool(true))
			globals.RawSet(lua.LString(definitions.LuaFeatureAbortNo), lua.LBool(false))
			globals.RawSet(lua.LString(definitions.LuaFeatureAbortYes), lua.LBool(true))
			globals.RawSet(lua.LString(definitions.LuaFeatureResultOk), lua.LNumber(0))
			globals.RawSet(lua.LString(definitions.LuaFeatureResultFail), lua.LNumber(1))

			globals.RawSetString(definitions.LuaFnAddCustomLog, Llocal.NewFunction(lualib.AddCustomLog(localLogs)))
			globals.RawSetString(definitions.LuaFnSetStatusMessage, Llocal.NewFunction(lualib.SetStatusMessage(&localStatus)))

			Llocal.SetGlobal(definitions.LuaDefaultTable, globals)

			// Build per-feature request table from the common request
			request := Llocal.NewTable()

			r.CommonRequest.SetupRequest(request)

			stopTimer := stats.PrometheusTimer(definitions.PromFeature, feature.Name)

			luaCtx, luaCancel := context.WithTimeout(egCtx, viper.GetDuration("lua_script_timeout")*time.Second)
			defer luaCancel()

			Llocal.SetContext(luaCtx)

			fr := &featResult{name: feature.Name, statusText: localStatus}

			// Load package path and execute compiled script
			if e := lualib.PackagePath(Llocal); e != nil {
				if stopTimer != nil {
					stopTimer()
				}

				return e
			}

			if e := lualib.DoCompiledFile(Llocal, feature.CompiledScript); e != nil {
				if stopTimer != nil {
					stopTimer()
				}

				return e
			}

			// Invoke nauthilus_call_feature if present
			callFeaturesFunc := Llocal.GetGlobal(definitions.LuaFnCallFeature)
			if callFeaturesFunc.Type() == lua.LTFunction {
				if e := Llocal.CallByParam(lua.P{Fn: callFeaturesFunc, NRet: 3, Protect: true}, request); e != nil {
					if stopTimer != nil {
						stopTimer()
					}

					return e
				} else {
					ret := Llocal.ToInt(-1)
					Llocal.Pop(1)
					ab := Llocal.ToBool(-1)
					Llocal.Pop(1)
					tr := Llocal.ToBool(-1)
					Llocal.Pop(1)
					fr.ret = ret
					fr.abort = ab
					fr.triggered = tr
				}
			}

			// Log per-feature outcome without touching shared r.Logs
			fr.logs = *localLogs
			logs := []any{
				definitions.LogKeyGUID, r.Session,
				"name", feature.Name,
				definitions.LogKeyMsg, "Lua feature finished",
				"triggered", fr.triggered,
				"abort_features", fr.abort,
				"result", func() string { return r.formatResult(fr.ret) }(),
			}

			if len(fr.logs) > 0 {
				for i := range fr.logs {
					logs = append(logs, fr.logs[i])
				}
			}

			util.DebugModule(definitions.DbgFeature, logs...)

			if stopTimer != nil {
				stopTimer()
			}

			mu.Lock()
			results = append(results, fr)
			mu.Unlock()

			return nil
		})
	}

	if e := g.Wait(); e != nil {
		return false, false, e
	}

	// Aggregate results: prioritize error, then abort, then triggered
	var statusSet bool
	for _, fr := range results {
		if fr.err != nil {
			// Return the first error encountered
			return false, false, fr.err
		}

		if fr.abort {
			abortFeatures = true
		}

		if fr.triggered {
			triggered = true
		}

		// Merge per-feature status message and logs via common helper
		lualib.MergeStatusAndLogs(&statusSet, &r.Logs, &r.StatusMessage, fr.statusText, fr.logs)
	}

	return triggered, abortFeatures, nil
}

// handleError logs the error message and cancels the Lua context.
func (r *Request) handleError(luaCancel context.CancelFunc, err error, scriptName string, stopTimer func()) {
	level.Error(log.Logger).Log(
		definitions.LogKeyGUID, r.Session,
		"name", scriptName,
		definitions.LogKeyMsg, err,
	)

	if stopTimer != nil {
		stopTimer()
	}

	luaCancel()
}

// generateLog creates a log entry with details about a Lua feature execution, including triggered state, abort flag, and result.
func (r *Request) generateLog(triggered, abortFeatures bool, ret int, scriptName string) {
	logs := []any{
		definitions.LogKeyGUID, r.Session,
		"name", scriptName,
		definitions.LogKeyMsg, "Lua feature finished",
		"triggered", triggered,
		"abort_features", abortFeatures,
		"result", func() string {
			return r.formatResult(ret)
		}(),
	}

	if r.Logs != nil {
		for index := range *r.Logs {
			logs = append(logs, (*r.Logs)[index])
		}
	}

	util.DebugModule(definitions.DbgFeature, logs...)
}

// formatResult returns a string representation of the given integer result.
// It maps 0 to "success", 1 to "fail", and any other value to the string "unknown(<value>)".
func (r *Request) formatResult(ret int) string {
	resultMap := map[int]string{
		0: definitions.LuaSuccess,
		1: definitions.LuaFail,
	}

	if ret == 0 || ret == 1 {
		return resultMap[ret]
	}

	return fmt.Sprintf("unknown(%d)", ret)
}
