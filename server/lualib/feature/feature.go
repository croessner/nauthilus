package feature

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/config"
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
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

// LuaPool is a pool of Lua state instances.
var LuaPool = lualib.NewLuaStatePool()

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
		return nil, errors2.ErrFeatureLuaNameMissing
	}

	if scriptPath == "" {
		return nil, errors2.ErrFeatureLuaScriptPathEmpty
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

	L := LuaPool.Get()

	defer LuaPool.Put(L)
	defer L.SetGlobal(global.LuaDefaultTable, lua.LNil)

	globals := r.setGlobals(L, ctx.Request)

	L.SetGlobal(global.LuaDefaultTable, globals)

	request := r.setRequest(L)

	triggered, abortFeatures, err = r.executeScripts(ctx, L, request)

	lualib.CleanupLTable(request)
	lualib.CleanupLTable(globals)

	request = nil
	globals = nil

	return
}

// setGlobals initializes and returns a new Lua table containing global variables for the Lua state L.
// The method also assigns a new instance of lualib.CustomLogKeyValue to r.Logs.
//
// The following global variables are set in the table:
// - `FEATURE_TRIGGER_NO`: false
// - `FEATURE_TRIGGER_YES`: true
// - `FEATURES_ABORT_NO`: false
// - `FEATURES_ABORT_YES`: true
// - `FEATURE_RESULT_OK`: 0
// - `FEATURE_RESULT_FAIL`: 1
//
// The following functions are also added to the table:
// - `context_set`: A function that sets a value in the request's Context.
// - `context_get`: A function that retrieves a value from the request's Context.
// - `context_delete`: A function that deletes a value from the request's Context.
// - `custom_log_add`: A function that adds a key-value pair to the request's Logs.
//
// The method returns the initialized table.
func (r *Request) setGlobals(L *lua.LState, httpRequest *http.Request) *lua.LTable {
	r.Logs = new(lualib.CustomLogKeyValue)
	globals := L.NewTable()

	globals.RawSet(lua.LString(global.LuaFeatureTriggerNo), lua.LBool(false))
	globals.RawSet(lua.LString(global.LuaFeatureTriggerYes), lua.LBool(true))
	globals.RawSet(lua.LString(global.LuaFeatureAbortNo), lua.LBool(false))
	globals.RawSet(lua.LString(global.LuaFeatureAbortYes), lua.LBool(true))
	globals.RawSet(lua.LString(global.LuaFeatureResultOk), lua.LNumber(0))
	globals.RawSet(lua.LString(global.LuaFeatureResultFail), lua.LNumber(1))

	globals.RawSetString(global.LuaFnCtxSet, L.NewFunction(lualib.ContextSet(r.Context)))
	globals.RawSetString(global.LuaFnCtxGet, L.NewFunction(lualib.ContextGet(r.Context)))
	globals.RawSetString(global.LuaFnCtxDelete, L.NewFunction(lualib.ContextDelete(r.Context)))
	globals.RawSetString(global.LuaFnAddCustomLog, L.NewFunction(lualib.AddCustomLog(r.Logs)))
	globals.RawSetString(global.LuaFnSetStatusMessage, L.NewFunction(lualib.SetStatusMessage(&r.StatusMessage)))
	globals.RawSetString(global.LuaFnGetAllHTTPRequestHeaders, L.NewFunction(lualib.GetAllHTTPRequestHeaders(httpRequest)))
	globals.RawSetString(global.LuaFnRedisGet, L.NewFunction(lualib.RedisGet))
	globals.RawSetString(global.LuaFnRedisSet, L.NewFunction(lualib.RedisSet))
	globals.RawSetString(global.LuaFnRedisDel, L.NewFunction(lualib.RedisDel))
	globals.RawSetString(global.LuaFnRedisExpire, L.NewFunction(lualib.RedisExpire))

	return globals
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
		timer := prometheus.NewTimer(stats.FunctionDuration.WithLabelValues("Feature", LuaFeatures.LuaScripts[index].Name))

		if errors.Is(ctx.Err(), context.Canceled) {
			return
		}

		luaCtx, luaCancel := context.WithTimeout(ctx, viper.GetDuration("lua_script_timeout")*time.Second)
		L.SetContext(luaCtx)

		if err = lualib.DoCompiledFile(L, LuaFeatures.LuaScripts[index].CompiledScript); err != nil {
			r.handleError(luaCancel, err, LuaFeatures.LuaScripts[index].Name, timer)

			continue
		}

		if err = L.CallByParam(lua.P{
			Fn:      L.GetGlobal(global.LuaFnCallFeature),
			NRet:    3,
			Protect: true,
		}, request); err != nil {
			r.handleError(luaCancel, err, LuaFeatures.LuaScripts[index].Name, timer)

			continue
		}

		ret := L.ToInt(-1)
		L.Pop(1)

		abortFeatures = L.ToBool(-1)
		L.Pop(1)

		triggered = L.ToBool(-1)
		L.Pop(1)

		if err == nil {
			r.generateLog(triggered, abortFeatures, ret, LuaFeatures.LuaScripts[index].Name)
		}

		timer.ObserveDuration()
		luaCancel()

		if triggered || abortFeatures {
			break
		}
	}

	return
}

// handleError logs the error message and cancels the Lua context.
func (r *Request) handleError(luaCancel context.CancelFunc, err error, scriptName string, timer *prometheus.Timer) {
	level.Error(logging.DefaultErrLogger).Log(
		global.LogKeyGUID, r.Session,
		"name", scriptName,
		global.LogKeyError, err,
	)

	timer.ObserveDuration()
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
// NOTE: This method uses the logging.DefaultErrLogger logger.
//
// Dependencies:
// - logging.DefaultErrLogger: the default error logger for logging the log entry
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
	level.Info(logging.DefaultLogger).Log(
		global.LogKeyGUID, r.Session,
		"name", scriptName,
		global.LogKeyMsg, "Lua feature finished",
		"triggered", triggered,
		"abort_features", abortFeatures,
		"result", func() string {
			return r.formatResult(ret)
		}(),
	)
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
