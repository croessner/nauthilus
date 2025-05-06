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
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/spf13/viper"
	lua "github.com/yuin/gopher-lua"
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
	if LuaFeatures == nil || len(LuaFeatures.LuaScripts) == 0 {
		return
	}

	LuaFeatures.Mu.RLock()

	defer LuaFeatures.Mu.RUnlock()

	L := lua.NewState()

	defer L.Close()

	r.registerDynamicLoader(L, ctx)

	r.setGlobals(L)

	request := r.setRequest(L)

	triggered, abortFeatures, err = r.executeScripts(ctx, L, request)

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

// executeScripts executes a series of Lua scripts associated with the request context and Lua state, handling defined features.
// It manages Lua script execution within a timeout, processes errors, and updates execution flags: triggered and abortFeatures.
func (r *Request) executeScripts(ctx *gin.Context, L *lua.LState, request *lua.LTable) (triggered bool, abortFeatures bool, err error) {
	for index := range LuaFeatures.LuaScripts {
		util.DebugModule(definitions.DbgFeature,
			definitions.LogKeyGUID, r.Session,
			definitions.LogKeyMsg, "Executing feature script",
			"name", LuaFeatures.LuaScripts[index].Name,
		)

		if L.GetTop() != 0 {
			L.SetTop(0)
		}

		stopTimer := stats.PrometheusTimer(definitions.PromFeature, LuaFeatures.LuaScripts[index].Name)

		if stderrors.Is(ctx.Err(), context.Canceled) {
			if stopTimer != nil {
				stopTimer()
			}

			return
		}

		luaCtx, luaCancel := context.WithTimeout(ctx, viper.GetDuration("lua_script_timeout")*time.Second)

		L.SetContext(luaCtx)

		if err = lualib.PackagePath(L); err != nil {
			r.handleError(luaCancel, err, LuaFeatures.LuaScripts[index].Name, stopTimer)

			break
		}

		if err = lualib.DoCompiledFile(L, LuaFeatures.LuaScripts[index].CompiledScript); err != nil {
			r.handleError(luaCancel, err, LuaFeatures.LuaScripts[index].Name, stopTimer)

			break
		}

		// Check if the script has a nauthilus_call_feature function
		callFeaturesFunc := L.GetGlobal(definitions.LuaFnCallFeature)

		if callFeaturesFunc.Type() == lua.LTFunction {
			if err = L.CallByParam(lua.P{
				Fn:      L.GetGlobal(definitions.LuaFnCallFeature),
				NRet:    3,
				Protect: true,
			}, request); err != nil {
				r.handleError(luaCancel, err, LuaFeatures.LuaScripts[index].Name, stopTimer)

				break
			}

			ret := L.ToInt(-1)
			L.Pop(1)

			abortFeatures = L.ToBool(-1)
			L.Pop(1)

			triggered = L.ToBool(-1)
			L.Pop(1)

			r.generateLog(triggered, abortFeatures, ret, LuaFeatures.LuaScripts[index].Name)
		}

		if stopTimer != nil {
			stopTimer()
		}

		luaCancel()

		if triggered || abortFeatures {
			break
		}
	}

	return
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

// CollectAdditionalFeatures executes Lua scripts to collect additional features for the neural network.
// It creates a new Lua state, registers the neural module, and executes all feature scripts.
// The additional features are stored in the context for later use by the neural network.
// Returns an error if any occur during script execution.
func (r *Request) CollectAdditionalFeatures(ctx *gin.Context) error {
	if LuaFeatures == nil || len(LuaFeatures.LuaScripts) == 0 {
		return errors.ErrNoFeatureDefined
	}

	r.Logs = new(lualib.CustomLogKeyValue)

	LuaFeatures.Mu.RLock()

	defer LuaFeatures.Mu.RUnlock()

	L := lua.NewState()

	defer L.Close()

	// Register the dynamic loader
	r.registerDynamicLoader(L, ctx)
	L.PreloadModule(definitions.LuaModNeural, lualib.LoaderModNeural(r.Context))

	// Set up globals
	globals := L.NewTable()

	globals.RawSetString(definitions.LuaFnAddCustomLog, L.NewFunction(lualib.AddCustomLog(r.Logs)))

	L.SetGlobal(definitions.LuaDefaultTable, globals)

	request := r.setRequest(L)

	// Execute each feature script
	for index := range LuaFeatures.LuaScripts {
		util.DebugModule(definitions.DbgFeature,
			definitions.LogKeyGUID, r.Session,
			definitions.LogKeyMsg, "Executing feature script",
			"name", LuaFeatures.LuaScripts[index].Name,
		)

		if L.GetTop() != 0 {
			L.SetTop(0)
		}

		if stderrors.Is(ctx.Err(), context.Canceled) {
			return ctx.Err()
		}

		stopTimer := stats.PrometheusTimer(definitions.PromFeature, LuaFeatures.LuaScripts[index].Name)

		luaCtx, luaCancel := context.WithTimeout(ctx, viper.GetDuration("lua_script_timeout")*time.Second)

		L.SetContext(luaCtx)

		err := lualib.PackagePath(L)
		if err != nil {
			r.handleError(luaCancel, err, LuaFeatures.LuaScripts[index].Name, stopTimer)

			return err
		}

		err = lualib.DoCompiledFile(L, LuaFeatures.LuaScripts[index].CompiledScript)
		if err != nil {
			r.handleError(luaCancel, err, LuaFeatures.LuaScripts[index].Name, stopTimer)

			return err
		}

		// Check if the script has a nauthilus_call_neural_network function
		collectFeaturesFunc := L.GetGlobal(definitions.LuaFnCallNeuralNetwork)

		if collectFeaturesFunc.Type() == lua.LTFunction {
			err = L.CallByParam(lua.P{
				Fn:      collectFeaturesFunc,
				NRet:    0,
				Protect: true,
			}, request)

			if err != nil {
				r.handleError(luaCancel, err, LuaFeatures.LuaScripts[index].Name, stopTimer)

				return err
			}
		}

		if stopTimer != nil {
			stopTimer()
		}

		luaCancel()
	}

	return nil
}
