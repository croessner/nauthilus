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

package action

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib"
	bflib "github.com/croessner/nauthilus/server/lualib/bruteforce"
	"github.com/croessner/nauthilus/server/lualib/connmgr"
	"github.com/croessner/nauthilus/server/lualib/luapool"
	"github.com/croessner/nauthilus/server/lualib/redislib"
	"github.com/croessner/nauthilus/server/lualib/vmpool"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"

	"github.com/spf13/viper"
	lua "github.com/yuin/gopher-lua"
)

var (
	// RequestChan is a buffered channel of type `*Action` used to send action requests to a worker.
	RequestChan chan *Action
)

// Done is an empty struct that can be used to signal the completion of a task or operation.
type Done struct{}

// LuaScriptAction represents an action that can be executed using Lua script.
type LuaScriptAction struct {
	// ScriptPath is the path to the Lua script file.
	ScriptPath string

	// ScriptCompiled is the compiled Lua function.
	ScriptCompiled *lua.FunctionProto

	// ScriptName is the descriptive name of the script
	ScriptName string

	// LuaAction is the type of Lua action.
	LuaAction definitions.LuaAction
}

// Action contains a subset of the Authentication structure.
// Action represents all the information related to a user's action in the system.
type Action struct {
	// LuaAction stores the user's desired action in Lua format.
	LuaAction definitions.LuaAction

	// Context represents the shared Lua context which is used by all Lua states accross the request.
	*lualib.Context

	// FinishedChan is a channel signaling the completion of the action.
	FinishedChan chan Done

	// HTTPRequest is a pointer to an http.Request object. It represents an incoming HTTP request received by the server.
	HTTPRequest *http.Request

	// HTTPContext is a pointer to a gin.Context, representing the HTTP request context and managing request-specific data.
	HTTPContext *gin.Context

	*lualib.CommonRequest
}

// Worker struct holds the data required for a worker process.
type Worker struct {
	// ctx is a pointer to a Context object used for managing and carrying context deadlines, cancel signals, and other request-scoped values across API boundaries and between processes.
	ctx context.Context

	// luaActionRequest is a pointer to an Action. This specifies the action to be performed by the Lua scripting GetEnvironment().
	luaActionRequest *Action

	// actionScripts is a slice of pointers to LuaScriptAction. This holds a collection of scripts that are to be executed by the worker process.
	actionScripts []*LuaScriptAction

	// resultMap is a map where the key is an int representing the exit code from an executed action, and the value is the corresponding textual representation or description of the exit code.
	// The exit code is a system-generated status code returned when an action is executed. It allows for the determination of whether the script completed successfully, or an error occurred during its execution.
	resultMap map[int]string

	// DoneChan is a buffered channel of type `Done` used to signal the end of a worker.
	DoneChan chan Done
}

// NewWorker initializes and returns a new instance of Worker with preconfigured result mappings and request channel.
func NewWorker() *Worker {
	resultMap := make(map[int]string, 2)

	resultMap[0] = definitions.LuaSuccess
	resultMap[1] = definitions.LuaFail
	RequestChan = make(chan *Action, definitions.MaxChannelSize)

	return &Worker{
		resultMap: resultMap,
	}
}

// Work is a method of Worker that starts processing tasks in a loop until the context is canceled.
func (aw *Worker) Work(ctx context.Context) {
	aw.ctx = ctx

	if !config.GetFile().HaveLuaActions() {
		return
	}

	aw.DoneChan = make(chan Done)

	defer close(aw.DoneChan)

	aw.loadActionScriptsFromConfiguration()

	for {
		select {
		case <-ctx.Done():
			aw.DoneChan <- Done{}

			return
		case aw.luaActionRequest = <-RequestChan:
			aw.handleRequest(aw.luaActionRequest.HTTPRequest)
		}
	}
}

// loadActionScriptsFromConfiguration loads Lua action scripts from the current configuration into the worker instance.
func (aw *Worker) loadActionScriptsFromConfiguration() {
	for index := range config.GetFile().GetLua().Actions {
		aw.loadScriptAction(&config.GetFile().GetLua().Actions[index])
	}
}

// loadScriptAction loads a Lua action script and its metadata into the worker instance based on the action configuration.
func (aw *Worker) loadScriptAction(actionConfig *config.LuaAction) {
	luaAction := &LuaScriptAction{}
	actionType, scriptName, scriptPath := actionConfig.GetAction()

	luaAction.LuaAction = getLuaActionType(actionType)

	if luaAction.LuaAction != definitions.LuaActionNone {
		aw.loadScript(luaAction, scriptName, scriptPath)
	}
}

// loadScript loads a Lua script into the worker by compiling it and updating the LuaScriptAction with its metadata.
func (aw *Worker) loadScript(luaAction *LuaScriptAction, scriptName string, scriptPath string) {
	var (
		err            error
		scriptCompiled *lua.FunctionProto
	)

	if scriptCompiled, err = lualib.CompileLua(scriptPath); err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, aw.luaActionRequest.Session,
			definitions.LogKeyMsg, "failed to compile Lua script",
			definitions.LogKeyError, err,
		)

		return
	}

	luaAction.ScriptPath = scriptPath
	luaAction.ScriptName = scriptName
	luaAction.ScriptCompiled = scriptCompiled
	aw.actionScripts = append(aw.actionScripts, luaAction)
}

// logActionsSummary logs a summary of Lua actions including session details and additional provided key-value data.
func (aw *Worker) logActionsSummary(logs *lualib.CustomLogKeyValue) {
	level.Info(log.Logger).Log(
		append([]any{
			definitions.LogKeyGUID, aw.luaActionRequest.Session,
			definitions.LogKeyMsg, "Lua actions finished",
		}, toLoggable(logs)...)...,
	)
}

// handleRequest processes an HTTP request using Lua scripts and logs execution results for each script.
func (aw *Worker) handleRequest(httpRequest *http.Request) {
	startTime := time.Now()
	defer func() {
		latency := time.Since(startTime)
		logs := new(lualib.CustomLogKeyValue)
		logs.Set(definitions.LogKeyLatency, util.FormatDurationMs(latency))
		level.Info(log.Logger).Log(
			append([]any{
				definitions.LogKeyGUID, aw.luaActionRequest.Session,
				definitions.LogKeyMsg, "Lua action handler latency",
			}, toLoggable(logs)...)...,
		)
	}()

	if len(aw.actionScripts) == 0 {
		aw.luaActionRequest.FinishedChan <- Done{}

		return
	}

	pool := vmpool.GetManager().GetOrCreate("action:default", vmpool.PoolOptions{MaxVMs: config.GetFile().GetLuaActionNumberOfWorkers()})

	L, acqErr := pool.Acquire(aw.ctx)
	if acqErr != nil {
		aw.luaActionRequest.FinishedChan <- Done{}

		return
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

	// Prepare per-request environment: ensures request-local globals and module bindings
	luapool.PrepareRequestEnv(L)

	// Bind request-scoped modules into reqEnv so that require() resolves correctly.
	// 1) nauthilus_context
	if loader := lualib.LoaderModContext(aw.luaActionRequest.Context); loader != nil {
		_ = loader(L)
		if mod, ok := L.Get(-1).(*lua.LTable); ok {
			L.Pop(1)
			luapool.BindModuleIntoReq(L, definitions.LuaModContext, mod)
		} else {
			L.Pop(1)
		}
	}

	// 2) nauthilus_http_request
	if httpRequest != nil {
		loader := lualib.LoaderModHTTP(lualib.NewHTTPMetaFromRequest(httpRequest))
		_ = loader(L)
		if mod, ok := L.Get(-1).(*lua.LTable); ok {
			L.Pop(1)
			luapool.BindModuleIntoReq(L, definitions.LuaModHTTPRequest, mod)
		} else {
			L.Pop(1)
		}
	}

	// 3) nauthilus_http_response
	if aw.luaActionRequest.HTTPContext != nil {
		loader := lualib.LoaderModHTTPResponse(aw.luaActionRequest.HTTPContext)
		_ = loader(L)
		if mod, ok := L.Get(-1).(*lua.LTable); ok {
			L.Pop(1)
			luapool.BindModuleIntoReq(L, definitions.LuaModHTTPResponse, mod)
		} else {
			L.Pop(1)
		}
	}

	// 4) nauthilus_redis (use worker context for deadlines)
	if loader := redislib.LoaderModRedis(aw.ctx); loader != nil {
		_ = loader(L)
		if mod, ok := L.Get(-1).(*lua.LTable); ok {
			L.Pop(1)
			luapool.BindModuleIntoReq(L, definitions.LuaModRedis, mod)
		} else {
			L.Pop(1)
		}
	}

	// 5) nauthilus_ldap (if enabled)
	if config.GetFile().HaveLDAPBackend() {
		loader := backend.LoaderModLDAP(aw.ctx)
		_ = loader(L)
		if mod, ok := L.Get(-1).(*lua.LTable); ok {
			L.Pop(1)
			luapool.BindModuleIntoReq(L, definitions.LuaModLDAP, mod)
		} else {
			L.Pop(1)
		}
	}

	// 6) nauthilus_psnet (connection monitoring)
	if loader := connmgr.LoaderModPsnet(aw.ctx); loader != nil {
		_ = loader(L)
		if mod, ok := L.Get(-1).(*lua.LTable); ok {
			L.Pop(1)
			luapool.BindModuleIntoReq(L, definitions.LuaModPsnet, mod)
		} else {
			L.Pop(1)
		}
	}

	// 7) nauthilus_dns (DNS lookups)
	if loader := lualib.LoaderModDNS(aw.ctx); loader != nil {
		_ = loader(L)
		if mod, ok := L.Get(-1).(*lua.LTable); ok {
			L.Pop(1)
			luapool.BindModuleIntoReq(L, definitions.LuaModDNS, mod)
		} else {
			L.Pop(1)
		}
	}

	// 8) nauthilus_brute_force (toleration and blocking helpers)
	if loader := bflib.LoaderModBruteForce(aw.ctx); loader != nil {
		_ = loader(L)
		if mod, ok := L.Get(-1).(*lua.LTable); ok {
			L.Pop(1)
			luapool.BindModuleIntoReq(L, definitions.LuaModBruteForce, mod)
		} else {
			L.Pop(1)
		}
	}

	logs := new(lualib.CustomLogKeyValue)

	aw.setupGlobals(L, logs)

	request := aw.setupRequest(L)

	for index := range aw.actionScripts {
		if aw.actionScripts[index].LuaAction == aw.luaActionRequest.LuaAction && !errors.Is((aw.ctx).Err(), context.Canceled) {
			if L.GetTop() != 0 {
				L.SetTop(0)
			}

			ret := aw.runScript(index, L, request, logs)
			if ret < 0 {
				replaceVM = true
			}

			logs.Set(aw.actionScripts[index].ScriptPath, aw.createResultLogMessage(ret))
		}
	}

	aw.logActionsSummary(logs)

	aw.luaActionRequest.FinishedChan <- Done{}
}

// setupGlobals initializes and registers global Lua variables and functions into the provided Lua state.
func (aw *Worker) setupGlobals(L *lua.LState, logs *lualib.CustomLogKeyValue) {
	globals := L.NewTable()

	if config.GetEnvironment().GetDevMode() {
		util.DebugModule(definitions.DbgAction, definitions.LogKeyMsg, fmt.Sprintf("%+v", aw.luaActionRequest))
	}

	globals.RawSet(lua.LString(definitions.LuaActionResultOk), lua.LNumber(0))
	globals.RawSet(lua.LString(definitions.LuaActionResultFail), lua.LNumber(1))

	globals.RawSetString(definitions.LuaFnAddCustomLog, L.NewFunction(lualib.AddCustomLog(logs)))

	L.SetGlobal(definitions.LuaDefaultTable, globals)
}

// setupRequest prepares and returns a new Lua table for the request setup.
// It applies the common request configurations to the table.
func (aw *Worker) setupRequest(L *lua.LState) *lua.LTable {
	request := L.NewTable()

	aw.luaActionRequest.CommonRequest.SetupRequest(request)

	return request
}

// getTaskName returns a formatted string combining the Lua action name and the script name of the given action.
func getTaskName(action *LuaScriptAction) string {
	actionName := getLuaActionName(action)

	return fmt.Sprintf("%s:%s", actionName, action.ScriptName)
}

// runScript executes a specified Lua script by index in the Worker instance.
// It sets up a Lua runtime environment, passes the context and request to the script, and handles timeouts.
// Parameters:
// - index: The index of the action script to execute.
// - L: The Lua state to execute the script on.
// - request: A Lua table containing the request information to pass to the script.
// - logs: A custom log structure to add contextual logging information.
// Returns the result of the Lua script execution as an integer.
func (aw *Worker) runScript(index int, L *lua.LState, request *lua.LTable, logs *lualib.CustomLogKeyValue) (result int) {
	var err error

	scriptStartTime := time.Now()
	defer func() {
		scriptLatency := time.Since(scriptStartTime)
		scriptName := getTaskName(aw.actionScripts[index])
		logs.Set(fmt.Sprintf("latency_%s", scriptName), util.FormatDurationMs(scriptLatency))
	}()

	stopTimer := stats.PrometheusTimer(definitions.PromAction, getTaskName(aw.actionScripts[index]))

	if stopTimer != nil {
		defer stopTimer()
	}

	luaCtx, luaCancel := context.WithTimeout(aw.ctx, viper.GetDuration("lua_script_timeout")*time.Second)

	L.SetContext(luaCtx)

	result = -1

	if err = aw.executeScript(L, index, request); err != nil {
		aw.logScriptFailure(index, err, logs)
		luaCancel()

		return
	}

	ret := L.ToInt(-1)

	L.Pop(1)

	util.DebugModule(
		definitions.DbgAction,
		"context", fmt.Sprintf("%+v", aw.luaActionRequest.Context),
	)

	luaCancel()

	return ret
}

// executeScript runs a precompiled Lua script in the provided Lua state and invokes a specific function with a request table.
// It uses the given index to identify the script from a collection of action scripts.
// Errors encountered while setting up the Lua environment or executing the script are returned.
func (aw *Worker) executeScript(L *lua.LState, index int, request *lua.LTable) error {
	if err := lualib.PackagePath(L); err != nil {
		return err
	}

	if err := lualib.DoCompiledFile(L, aw.actionScripts[index].ScriptCompiled); err != nil {
		return err
	}

	// Check if the script has a nauthilus_call_action function (reqEnv-first lookup)
	actionFunc := lua.LNil
	if v := L.GetGlobal("__NAUTH_REQ_ENV"); v != nil && v.Type() == lua.LTTable {
		if fn := L.GetField(v, definitions.LuaFnCallAction); fn != nil {
			actionFunc = fn
		}
	}

	if actionFunc == lua.LNil {
		actionFunc = L.GetGlobal(definitions.LuaFnCallAction)
	}

	if actionFunc.Type() == lua.LTFunction {
		if err := L.CallByParam(lua.P{
			Fn:      actionFunc,
			NRet:    1,
			Protect: true,
		}, request); err != nil {
			return err
		}
	}

	return nil
}

// logScriptFailure logs details about a script failure, including session ID, script path, error, and custom log data.
func (aw *Worker) logScriptFailure(index int, err error, logs *lualib.CustomLogKeyValue) {
	parts := []any{
		definitions.LogKeyGUID, aw.luaActionRequest.Session,
		"script", aw.actionScripts[index].ScriptPath,
		definitions.LogKeyMsg, "failed to execute Lua script",
	}

	var ae *lua.ApiError
	if errors.As(err, &ae) && ae != nil {
		parts = append(parts,
			definitions.LogKeyError, ae.Error(),
			"stacktrace", ae.StackTrace,
		)
	}

	if logs != nil && len(*logs) > 0 {
		for i := range *logs {
			parts = append(parts, (*logs)[i])
		}
	}

	level.Error(log.Logger).Log(parts...)
}

// createResultLogMessage generates a log message based on the given result code.
func (aw *Worker) createResultLogMessage(resultCode int) string {
	if resultCode == 0 || resultCode == 1 {
		return aw.resultMap[resultCode]
	}

	return "unknown result"
}

// toLoggable converts a CustomLogKeyValue slice into a flat slice of any type, ensuring the input has an even length.
// Returns nil if the input slice is empty or has an odd length.
func toLoggable(logs *lualib.CustomLogKeyValue) []any {
	if len(*logs) > 0 && len(*logs)%2 == 0 {
		var l []any

		for i := range *logs {
			l = append(l, (*logs)[i])
		}

		return l
	}

	return nil
}

// getLuaActionType maps a given action name string to its corresponding LuaAction identifier.
// Returns LuaActionNone if the action name is not recognized.
func getLuaActionType(actionName string) definitions.LuaAction {
	switch actionName {
	case definitions.LuaActionBruteForceName:
		return definitions.LuaActionBruteForce
	case definitions.LuaActionRBLName:
		return definitions.LuaActionRBL
	case definitions.LuaActionTLSName:
		return definitions.LuaActionTLS
	case definitions.LuaActionRelayDomainsName:
		return definitions.LuaActionRelayDomains
	case definitions.LuaActionLuaName:
		return definitions.LuaActionLua
	case definitions.LuaActionPostName:
		return definitions.LuaActionPost
	default:
		return definitions.LuaActionNone
	}
}

// getLuaActionName returns the name of a Lua action based on the action type defined in the given LuaScriptAction.
func getLuaActionName(action *LuaScriptAction) string {
	switch action.LuaAction {
	case definitions.LuaActionBruteForce:
		return definitions.LuaActionBruteForceName
	case definitions.LuaActionRBL:
		return definitions.LuaActionRBLName
	case definitions.LuaActionTLS:
		return definitions.LuaActionTLSName
	case definitions.LuaActionRelayDomains:
		return definitions.LuaActionRelayDomainsName
	case definitions.LuaActionLua:
		return definitions.LuaActionLuaName
	case definitions.LuaActionPost:
		return definitions.LuaActionPostName
	default:
		return "-"
	}
}
