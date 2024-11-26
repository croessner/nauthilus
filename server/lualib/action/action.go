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
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	"github.com/spf13/viper"
	"github.com/yuin/gopher-lua"
)

var (
	// RequestChan is a buffered channel of type `*Action` used to send action requests to a worker.
	RequestChan chan *Action
)

// httpClient is a pre-configured instance of http.Client with custom timeout and TLS settings for making HTTP requests.
var httpClient *http.Client

// InitHTTPClient initializes the global httpClient variable with a pre-configured instance from util.NewHTTPClient.
func InitHTTPClient() {
	httpClient = util.NewHTTPClient()
}

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

	*lualib.CommonRequest
}

// Worker struct holds the data required for a worker process.
type Worker struct {
	// ctx is a pointer to a Context object used for managing and carrying context deadlines, cancel signals, and other request-scoped values across API boundaries and between processes.
	ctx context.Context

	// luaActionRequest is a pointer to an Action. This specifies the action to be performed by the Lua scripting environment.
	luaActionRequest *Action

	// actionScripts is a slice of pointers to LuaScriptAction. This holds a collection of scripts that are to be executed by the worker process.
	actionScripts []*LuaScriptAction

	// resultMap is a map where the key is an int representing the exit code from an executed action, and the value is the corresponding textual representation or description of the exit code.
	// The exit code is a system-generated status code returned when an action is executed. It allows for the determination of whether the script completed successfully, or an error occurred during its execution.
	resultMap map[int]string

	// DoneChan is a buffered channel of type `Done` used to signal the end of a worker.
	DoneChan chan Done
}

// NewWorker creates a new instance of the Worker struct.
// It initializes a resultMap map with two key-value pairs.
// It initializes a RequestChan channel with a maximum size of MaxChannelSize.
// It returns a pointer to the newly created Worker.
func NewWorker() *Worker {
	resultMap := make(map[int]string, 2)

	resultMap[0] = definitions.LuaSuccess
	resultMap[1] = definitions.LuaFail
	RequestChan = make(chan *Action, definitions.MaxChannelSize)

	return &Worker{
		resultMap: resultMap,
	}
}

// Work executes the worker logic in a continuous loop.
// It loads action scripts from the configuration and then waits for requests or context cancellation.
// If a request is received, it handles the request by running the corresponding script.
// If the context is cancelled, it sends a WorkerEndChan signal to indicate that the worker has ended.
func (aw *Worker) Work(ctx context.Context) {
	aw.ctx = ctx

	if !config.LoadableConfig.HaveLuaActions() {
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

// loadActionScriptsFromConfiguration loads action scripts from the configuration.
// For each action in the configuration, it calls loadScriptAction to load the action script.
// The action is passed by reference to loadScriptAction.
//
// It iterates over the actions in the configuration and loads the corresponding script.
// The loaded action script is added to Worker's actionScripts slice.
//
// Example:
//
//	 loadActionScriptsFromConfiguration()
//
//	 Actions in the configuration:
//		- action1: script1.lua
//		- action2: script2.lua
//		- action3: script3.lua
//
//	 After calling loadActionScriptsFromConfiguration(), the actionScripts slice will contain:
//		- script1.lua
//		- script2.lua
//		- script3.lua
func (aw *Worker) loadActionScriptsFromConfiguration() {
	for index := range config.LoadableConfig.Lua.Actions {
		aw.loadScriptAction(&config.LoadableConfig.Lua.Actions[index])
	}
}

// loadScriptAction loads an action script from the configuration and compiles it.
// It takes the actionConfig parameter, which specifies the action type and script path.
// It creates a LuaScriptAction struct and sets its properties based on the action type and script path.
// If the action type is not LuaActionNone, it calls the loadScript method with the LuaScriptAction and script path.
//
// Example:
//
//	actionConfig := &config.LoadableConfig.Lua.Actions[index]
//	aw.loadScriptAction(actionConfig)
func (aw *Worker) loadScriptAction(actionConfig *config.LuaAction) {
	luaAction := &LuaScriptAction{}
	actionType, scriptName, scriptPath := actionConfig.GetAction()

	luaAction.LuaAction = getLuaActionType(actionType)

	if luaAction.LuaAction != definitions.LuaActionNone {
		aw.loadScript(luaAction, scriptName, scriptPath)
	}
}

// loadScript loads a Lua script into a LuaScriptAction object.
// It compiles the script using lualib.CompileLua and stores the compiled script in LuaScriptAction.ScriptCompiled.
// If the compilation fails, it logs the error using log.Logger.
//
// Parameters:
// - luaAction: a pointer to a LuaScriptAction object.
// - scriptPath: the path to the Lua script file.
func (aw *Worker) loadScript(luaAction *LuaScriptAction, scriptName string, scriptPath string) {
	var (
		err            error
		scriptCompiled *lua.FunctionProto
	)

	if scriptCompiled, err = lualib.CompileLua(scriptPath); err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, err)

		return
	}

	luaAction.ScriptPath = scriptPath
	luaAction.ScriptName = scriptName
	luaAction.ScriptCompiled = scriptCompiled
	aw.actionScripts = append(aw.actionScripts, luaAction)
}

// registerDynamicLoader registers a dynamic loader function in the Lua state. The dynamic loader function
// is called when a Lua module is required or imported, and it loads the module into the Lua environment.
// The function takes the Lua state and an HTTP request as input parameters. It creates a new Lua function
// that acts as the dynamic loader. The dynamic loader function checks if the module name is already present
// in the registry. If it is, the function returns. Otherwise, it registers common Lua libraries, such as
// lualib.RegisterCommonLuaLibraries, in the Lua state and calls the worker's registerModule method to register
// the module in the Lua environment. Finally, it sets the global variable "dynamic_loader" to the created
// dynamic loader function.
//
// Note that this documentation assumes familiarity with the Lua programming language and its module system.
func (aw *Worker) registerDynamicLoader(L *lua.LState, httpRequest *http.Request) {
	dynamicLoader := L.NewFunction(func(L *lua.LState) int {
		modName := L.CheckString(1)

		registry := make(map[string]bool)
		if _, found := registry[modName]; found {
			return 0
		}

		lualib.RegisterCommonLuaLibraries(L, aw.ctx, modName, registry, httpClient)
		aw.registerModule(L, httpRequest, modName, registry)

		return 0
	})

	L.SetGlobal("dynamic_loader", dynamicLoader)
}

// registerModule registers a Lua module in the given Lua state.
// The modules are preloaded based on the module name and the provided registry.
// The available module names are `modName`.
// Once the module is registered, it will be added to the registry to track its availability.
//
// Only specific modules are supported, depending on the `modName` value,
// the appropriate preload module function is called to load the module.
// If the module name is not recognized, the function returns without any action.
//
// For module "ModContext", the `lualib.LoaderModContext` function is used to preload the module.
// For module "ModHTTPRequest", the `lualib.LoaderModHTTPRequest` function is used to preload the module.
// For module "ModLDAP", if the LDAP backend is activated, the `backend.LoaderModLDAP` function is used to preload the module.
// Otherwise, an error is raised indicating that the LDAP backend is not activated.
//
// The `registry` parameter is a map of module names to booleans.
// Once a module is registered, its name is added to the registry with a true value to indicate its availability.
//
// This function does not return any value.
func (aw *Worker) registerModule(L *lua.LState, httpRequest *http.Request, modName string, registry map[string]bool) {
	switch modName {
	case definitions.LuaModContext:
		L.PreloadModule(modName, lualib.LoaderModContext(aw.luaActionRequest.Context))
	case definitions.LuaModHTTPRequest:
		L.PreloadModule(modName, lualib.LoaderModHTTPRequest(httpRequest))
	case definitions.LuaModLDAP:
		if config.LoadableConfig.HaveLDAPBackend() {
			L.PreloadModule(definitions.LuaModLDAP, backend.LoaderModLDAP(aw.ctx))
		} else {
			L.RaiseError("LDAP backend not activated")
		}
	default:
		return
	}

	registry[modName] = true
}

// logActionsSummary logs a summary of the Lua actions that have been finished.
// It creates a log entry with the session identifier and a message indicating that Lua actions have finished.
// The log entry also includes any additional key-value pairs provided in the logs parameter.
// The log entry is logged at the Info level using the global Logger.
//
// Parameters:
//   - logs: A pointer to a CustomLogKeyValue instance representing additional key-value pairs to include in the log entry.
//     Each key-value pair is specified by calling the Set method on the CustomLogKeyValue instance.
//     The key-value pairs will be appended to the log entry in the order they were set.
//     If logs is nil or empty, no additional key-value pairs will be included in the log entry.
//
// Example:
//
//	aw := &Worker{}
//	logs := lualib.CustomLogKeyValue{}
//	logs.Set("key1", "value1")
//	logs.Set("key2", "value2")
//	aw.logActionsSummary(&logs)
//	// The log entry will include the session identifier, message, as well as the additional key-value pairs "key1: value1" and "key2: value2"
//
// Note:
//
//	The logActionsSummary method is typically called after executing a sequence of Lua actions to provide a summary of the actions that were performed.
//	The method is called internally within the handleRequest method, which handles a Lua action request.
func (aw *Worker) logActionsSummary(logs *lualib.CustomLogKeyValue) {
	level.Info(log.Logger).Log(
		append([]any{
			definitions.LogKeyGUID, aw.luaActionRequest.Session,
			definitions.LogKeyMsg, "Lua actions finished",
		}, toLoggable(logs)...)...,
	)
}

// handleRequest handles a Lua action request by running the corresponding script.
// It creates a new Lua state and loads necessary Lua libraries.
// Then, it sets up global variables and creates a Lua table for the request.
// It iterates through the action scripts, and if the LuaAction matches the request and the context is not canceled,
// it executes the script.
// If an error occurs while executing the script, it logs the failure.
// After executing the script, it logs the result and cancels the Lua context.
func (aw *Worker) handleRequest(httpRequest *http.Request) {
	if len(aw.actionScripts) == 0 {
		aw.luaActionRequest.FinishedChan <- Done{}

		return
	}

	L := lua.NewState()

	defer L.Close()

	aw.registerDynamicLoader(L, httpRequest)

	logs := new(lualib.CustomLogKeyValue)

	aw.setupGlobals(L, logs)

	request := aw.setupRequest(L)

	for index := range aw.actionScripts {
		if aw.actionScripts[index].LuaAction == aw.luaActionRequest.LuaAction && !errors.Is((aw.ctx).Err(), context.Canceled) {
			if L.GetTop() != 0 {
				L.SetTop(0)
			}

			ret := aw.runScript(index, L, request, logs)
			logs.Set(aw.actionScripts[index].ScriptPath, aw.createResultLogMessage(ret))
		}
	}

	aw.logActionsSummary(logs)

	aw.luaActionRequest.FinishedChan <- Done{}
}

// setupGlobals initializes the global variables in the Lua state.
// It creates a new Lua table and sets the necessary variables and functions.
// If the DevMode configuration is enabled, it logs the Lua action request.
// The Lua table includes two variables, LuaActionResultOk and LuaActionResultFail,
// which are set to 0 and 1 respectively.
// It also includes a function LuaFnAddCustomLog, which is set to the AddCustomLog function
// from the lualib package. Finally, it sets the LuaDefaultTable global variable to the created table.
func (aw *Worker) setupGlobals(L *lua.LState, logs *lualib.CustomLogKeyValue) {
	globals := L.NewTable()

	if config.EnvConfig.DevMode {
		util.DebugModule(definitions.DbgAction, definitions.LogKeyMsg, fmt.Sprintf("%+v", aw.luaActionRequest))
	}

	globals.RawSet(lua.LString(definitions.LuaActionResultOk), lua.LNumber(0))
	globals.RawSet(lua.LString(definitions.LuaActionResultFail), lua.LNumber(1))

	globals.RawSetString(definitions.LuaFnAddCustomLog, L.NewFunction(lualib.AddCustomLog(logs)))

	L.SetGlobal(definitions.LuaDefaultTable, globals)
}

// setupRequest creates a Lua table representing the request data.
// The table contains various fields from aw.luaActionRequest.
// Returns the created request table.
func (aw *Worker) setupRequest(L *lua.LState) *lua.LTable {
	request := L.NewTable()

	aw.luaActionRequest.CommonRequest.SetupRequest(request)

	return request
}

func getTaskName(action *LuaScriptAction) string {
	actionName := getLuaActionName(action)

	return fmt.Sprintf("%s:%s", actionName, action.ScriptName)
}

// runScript executes the Lua script at the specified index.
// It sets the context and timeout for the script execution.
// If an error occurs during script execution, it logs the failure and cancels the Lua context.
// It retrieves the return value of the script, logs the script execution details, and cancels the Lua context.
//
// Parameters:
// - index: the index of the Lua script to execute
// - L: the Lua State
// - request: the Lua table containing the request data
// - logs: the custom log key-value data
//
// Returns: none
func (aw *Worker) runScript(index int, L *lua.LState, request *lua.LTable, logs *lualib.CustomLogKeyValue) (result int) {
	var err error

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

// executeScript executes a Lua script by loading and calling a compiled Lua function.
// It takes in an LState, an index representing the script to execute, and a request table.
// It returns an error if there was a problem executing the script.
func (aw *Worker) executeScript(L *lua.LState, index int, request *lua.LTable) error {
	if err := lualib.PackagePath(L); err != nil {
		return err
	}

	if err := lualib.DoCompiledFile(L, aw.actionScripts[index].ScriptCompiled); err != nil {
		return err
	}

	if err := L.CallByParam(lua.P{
		Fn:      L.GetGlobal(definitions.LuaFnCallAction),
		NRet:    1,
		Protect: true,
	}, request); err != nil {
		return err
	}

	return nil
}

// logScriptFailure logs the failure of a script execution.
// It takes the index of the action script, the error that occurred, and the custom log key-value pair as parameters.
// It logs the error, script path, session ID, and custom log key-value pair using the error logger.
func (aw *Worker) logScriptFailure(index int, err error, logs *lualib.CustomLogKeyValue) {
	level.Error(log.Logger).Log(
		append([]any{
			definitions.LogKeyGUID, aw.luaActionRequest.Session,
			"script", aw.actionScripts[index].ScriptPath,
			definitions.LogKeyMsg, err,
		}, toLoggable(logs)...)...,
	)
}

// createResultLogMessage generates a log message based on the given result code.
func (aw *Worker) createResultLogMessage(resultCode int) string {
	if resultCode == 0 || resultCode == 1 {
		return aw.resultMap[resultCode]
	}

	return "unknown result"
}

// toLoggable is a function that takes a reference to log entries (type CustomLogKeyValue from lualib)
// and constructs a new slice (of type 'any') from these entries.
// The function iterates over each log entry and appends it to the new slice `l`.
// The function checks first if the length of the logs is greater than 0 and if it's even,
// in case the conditions are not met, nil will be returned.
// The resulting slice (`l`) is then returned.
//
// Parameters:
//   - logs: A pointer to a CustomLogKeyValue instance, representing logs to transform.
//
// Returns:
//   - If the length of 'logs' is more than 0 and is even-numbered, a slice of 'any' type including all elements in 'logs' is returned.
//   - Otherwise, nil is returned.
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

// getLuaActionType maps a given actionName string to its corresponding definitions.LuaAction constant.
// If actionName matches any of the predefined names, the corresponding constant is returned.
// Otherwise, definitions.LuaActionNone is returned.
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

// getLuaActionName returns the name of the Lua action based on the given LuaScriptAction.
// It takes an action of type LuaScriptAction as input and returns a string representing the name of the action.
// If the LuaAction is LuaActionBruteForce, it returns "brute_force".
// If the LuaAction is LuaActionRBL, it returns "rbl".
// If the LuaAction is LuaActionTLS, it returns "tls_encryption".
// If the LuaAction is LuaActionRelayDomains, it returns "relay_domains".
// If the LuaAction is LuaActionLua, it returns "lua".
// If the LuaAction is LuaActionPost, it returns "post".
// If the LuaAction is any other value, it returns an empty string.
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
