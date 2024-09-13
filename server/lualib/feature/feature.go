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
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/spf13/viper"
	lua "github.com/yuin/gopher-lua"
)

// LuaFeatures is a pointer to a PreCompiledLuaFeatures object. It represents a collection of pre-compiled Lua scripts that can be executed.
//
// The PreCompiledLuaFeatures struct has the following properties:
// - `LuaScripts`: a slice of LuaFeature objects representing the individual pre-compiled Lua scripts.
// - `mu`: a mutex used to synchronize access to the LuaScripts slice.
//
// The PreCompiledLuaFeatures has two methods:
// - `Add(luaFeature *LuaFeature)`: adds a LuaFeature object to the LuaScripts slice.
// - `Reset()`: clears the LuaScripts slice.
//
// Usage example:
// The PreCompileLuaFeatures function initializes the LuaFeatures variable by pre-compiling the Lua scripts specified in the configuration.
//
// The CallFeatureLua method of the Request struct executes the pre-compiled Lua scripts stored in LuaFeatures on the provided gin.Context.
// It retrieves a read lock on the LuaFeatures object and creates a new Lua state. It then sets up the necessary Lua libraries and global variables.
// The executeScripts method is called to execute each pre-compiled Lua script in order, passing in the request and the Lua state.
// If a script triggers or aborts the execution of features, the execution is halted and the method returns the appropriate values.
var LuaFeatures *PreCompiledLuaFeatures

// PreCompileLuaFeatures pre-compiles Lua features.
// It checks if the configuration for Lua features is loaded and if the LuaFeatures variable is already set.
// If the LuaFeatures variable is not set, it creates a new instance of PreCompiledLuaFeatures.
// If the LuaFeatures variable is already set, it resets it using the Reset method.
// Then it loops through the features in the configuration and creates a new LuaFeature instance for each feature.
// The LuaFeature instance is created using the NewLuaFeature function, passing the name and script path from the configuration.
// If there is an error creating the LuaFeature instance, the error is returned.
// The compiled Lua feature is added to the LuaFeatures variable using the Add method.
// Finally, it returns nil if there are no errors.
func PreCompileLuaFeatures() (err error) {
	if config.LoadableConfig.HaveLuaFeatures() {
		if LuaFeatures == nil {
			LuaFeatures = &PreCompiledLuaFeatures{}
		} else {
			LuaFeatures.Reset()
		}

		for index := range config.LoadableConfig.Lua.Features {
			var luaFeature *LuaFeature

			luaFeature, err = NewLuaFeature(config.LoadableConfig.Lua.Features[index].Name, config.LoadableConfig.Lua.Features[index].ScriptPath)
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

// Reset resets the slice of LuaScripts in PreCompiledLuaFeatures by creating a new empty slice.
// The method also acquires a lock on the PreCompiledLuaFeatures mutex before resetting the slice
// and defers the unlocking of the mutex until the method returns.
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

// NewLuaFeature creates a new instance of LuaFeature with the given name and script path.
// If the name or script path is empty, it returns an error.
// The function compiles the Lua script using lualib.CompileLua and assigns the compiled script to the CompiledScript field of the LuaFeature.
// The function returns the created LuaFeature instance and nil error if successful.
// Otherwise, it returns nil and the appropriate error.
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

// registerDynamicLoader creates a new Lua function `dynamic_loader` and registers it as a global variable in the Lua state.
// The `dynamic_loader` function is used to load and register modules in the Lua state based on the provided module name.
//
// Parameters:
// - L *lua.LState: the Lua state in which the module is to be registered
// - ctx *gin.Context: the gin Context containing the request data
//
// Returns: none
func (r *Request) registerDynamicLoader(L *lua.LState, ctx *gin.Context) {
	dynamicLoader := L.NewFunction(func(L *lua.LState) int {
		modName := L.CheckString(1)

		registry := make(map[string]bool)
		if _, found := registry[modName]; found {
			return 0
		}

		lualib.RegisterCommonLuaLibraries(L, modName, registry)
		r.registerModule(L, ctx, modName, registry)

		return 0
	})

	L.SetGlobal("dynamic_loader", dynamicLoader)
}

// registerModule registers a module in the LuaState based on the provided module name.
// The module is loaded using a corresponding loader function and added to the registry.
//
// Parameters:
// - L *lua.LState: the Lua state in which the module is to be registered
// - ctx *gin.Context: the gin Context containing the request data
// - modName string: the name of the module to be registered
// - registry map[string]bool: a map containing the registered modules
//
// Returns: none
func (r *Request) registerModule(L *lua.LState, ctx *gin.Context, modName string, registry map[string]bool) {
	switch modName {
	case global.LuaModContext:
		L.PreloadModule(modName, lualib.LoaderModContext(r.Context))
	case global.LuaModHTTPRequest:
		L.PreloadModule(modName, lualib.LoaderModHTTPRequest(ctx.Request))
	case global.LuaModLDAP:
		if config.LoadableConfig.HaveLDAPBackend() {
			L.PreloadModule(global.LuaModLDAP, backend.LoaderModLDAP(ctx))
		} else {
			L.RaiseError("LDAP backend not activated")
		}
	default:
		return
	}

	registry[modName] = true
}

// CallFeatureLua executes Lua scripts for a given request context.
// It acquires a read lock on the LuaFeatures mutex.
// It creates a new Lua state and preloads necessary libraries.
// It sets global variables in the Lua state.
// It sets fields for the request in the Lua state.
// It executes the Lua scripts for the request.
// It returns the triggered flag, abortFeatures flag, and related error if any.
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

// setGlobals sets the global variables in the Lua state for the request. It initializes a new table,
// sets the predefined Lua global variables, and adds custom functions to the table. Finally,
// it sets the table as the global variable in the Lua state.
func (r *Request) setGlobals(L *lua.LState) {
	r.Logs = new(lualib.CustomLogKeyValue)
	globals := L.NewTable()

	globals.RawSet(lua.LString(global.LuaFeatureTriggerNo), lua.LBool(false))
	globals.RawSet(lua.LString(global.LuaFeatureTriggerYes), lua.LBool(true))
	globals.RawSet(lua.LString(global.LuaFeatureAbortNo), lua.LBool(false))
	globals.RawSet(lua.LString(global.LuaFeatureAbortYes), lua.LBool(true))
	globals.RawSet(lua.LString(global.LuaFeatureResultOk), lua.LNumber(0))
	globals.RawSet(lua.LString(global.LuaFeatureResultFail), lua.LNumber(1))

	globals.RawSetString(global.LuaFnAddCustomLog, L.NewFunction(lualib.AddCustomLog(r.Logs)))
	globals.RawSetString(global.LuaFnSetStatusMessage, L.NewFunction(lualib.SetStatusMessage(&r.StatusMessage)))

	L.SetGlobal(global.LuaDefaultTable, globals)
}

// setRequest creates a new Lua table and sets the request properties as key-value pairs in the table. The table is then returned.
// The request table is then returned.
func (r *Request) setRequest(L *lua.LState) *lua.LTable {
	request := L.NewTable()

	r.CommonRequest.SetupRequest(request)

	return request
}

// executeScripts is a method for the Request struct. It iterates over a set of compiled Lua scripts
// and executes them within a context that respects a timeout value. If an error is encountered while
// executing a script, it will be handled and the method will continue onto the next script.
// The method stops executing scripts if one of them triggers an action or requires the features to be aborted.
//
// Parameters:
// ctx *gin.Context: the gin Context from which this method is invoked.
// L *lua.LState: the Lua state in which the scripts are to be executed.
// request *lua.LTable: the Lua table representing the request to be processed.
//
// Returns:
// triggered bool: a boolean indicating if any of the scripts has triggered an action.
// abortFeatures bool: a boolean indicating if any of the scripts has required to abort the features.
// err error: an error that might have occurred during the execution of the scripts.
func (r *Request) executeScripts(ctx *gin.Context, L *lua.LState, request *lua.LTable) (triggered bool, abortFeatures bool, err error) {
	for index := range LuaFeatures.LuaScripts {
		if L.GetTop() != 0 {
			L.SetTop(0)
		}

		stopTimer := stats.PrometheusTimer(global.PromFeature, LuaFeatures.LuaScripts[index].Name)

		if stderrors.Is(ctx.Err(), context.Canceled) {
			stopTimer()

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

		if err = L.CallByParam(lua.P{
			Fn:      L.GetGlobal(global.LuaFnCallFeature),
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

		stopTimer()
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
		global.LogKeyGUID, r.Session,
		"name", scriptName,
		global.LogKeyError, err,
	)

	stopTimer()
	luaCancel()
}

// generateLog generates a log entry for a Lua feature that has finished execution.
// It logs the following information:
// - GUID: the session ID of the request
// - name: the name of the script that was executed
// - msg: "Lua feature finished"
// - triggered: whether the feature was triggered (true/false)
// - abort_features: whether the feature should abort other features (true/false)
// - result: the result of the feature, formatted as a string
//
// Example usage:
// r.generateLog(triggered, abortFeatures, ret, scriptName)
//
// NOTE: This method uses the log.Logger logger.
//
// Dependencies:
// - log.Logger: the default error logger for logging the log entry
// - global.LogKeyGUID: the constant representing the log key for the session ID
// - global.LogKeyMsg: the constant representing the log key for the log message
// - r.formatResult: a helper method to format the feature result as a string
//
// Parameters:
// - triggered: a boolean indicating whether the feature was triggered by the script
// - abortFeatures: a boolean indicating whether the feature should abort other features
// - ret: the result of the feature execution (0 for success, 1 for failure)
// - scriptName: the name of the executed script
//
// Returns: none
func (r *Request) generateLog(triggered, abortFeatures bool, ret int, scriptName string) {
	logs := []any{
		global.LogKeyGUID, r.Session,
		"name", scriptName,
		global.LogKeyMsg, "Lua feature finished",
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

	util.DebugModule(global.DbgFeature, logs...)
}

// formatResult returns the formatted result based on the given ret value.
// It uses the resultMap to map the ret value to the corresponding string value.
// If ret is 0 or 1, it returns the corresponding string value from resultMap.
// Otherwise, it returns a string formatted as "unknown(ret)".
func (r *Request) formatResult(ret int) string {
	resultMap := map[int]string{
		0: global.LuaSuccess,
		1: global.LuaFail,
	}

	if ret == 0 || ret == 1 {
		return resultMap[ret]
	}

	return fmt.Sprintf("unknown(%d)", ret)
}
