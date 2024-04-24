package action

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/viper"
	"github.com/yuin/gopher-lua"
)

var (
	// RequestChan is a buffered channel of type `*Action` used to send action requests to a worker.
	RequestChan chan *Action
)

// LuaPool is a pool of Lua state instances.
var LuaPool = lualib.NewLuaStatePool()

// Done is an empty struct that can be used to signal the completion of a task or operation.
type Done struct{}

// LuaScriptAction represents an action that can be executed using Lua script.
type LuaScriptAction struct {
	// ScriptPath is the path to the Lua script file.
	ScriptPath string

	// ScriptCompiled is the compiled Lua function.
	ScriptCompiled *lua.FunctionProto

	// LuaAction is the type of Lua action.
	LuaAction global.LuaAction
}

// Action contains a subset of the Authentication structure.
// Action represents all the information related to a user's action in the system.
type Action struct {
	// LuaAction stores the user's desired action in Lua format.
	LuaAction global.LuaAction

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
	ctx *context.Context

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

	resultMap[0] = global.LuaSuccess
	resultMap[1] = global.LuaFail
	RequestChan = make(chan *Action, global.MaxChannelSize)

	return &Worker{
		resultMap: resultMap,
	}
}

// Work executes the worker logic in a continuous loop.
// It loads action scripts from the configuration and then waits for requests or context cancellation.
// If a request is received, it handles the request by running the corresponding script.
// If the context is cancelled, it sends a WorkerEndChan signal to indicate that the worker has ended.
func (aw *Worker) Work(ctx context.Context) {
	aw.ctx = &ctx

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
	actionType, scriptPath := actionConfig.GetAction()

	luaAction.LuaAction = getLuaActionType(actionType)

	if luaAction.LuaAction != global.LuaActionNone {
		aw.loadScript(luaAction, scriptPath)
	}
}

// loadScript loads a Lua script into a LuaScriptAction object.
// It compiles the script using lualib.CompileLua and stores the compiled script in LuaScriptAction.ScriptCompiled.
// If the compilation fails, it logs the error using logging.DefaultErrLogger.
//
// Parameters:
// - luaAction: a pointer to a LuaScriptAction object.
// - scriptPath: the path to the Lua script file.
func (aw *Worker) loadScript(luaAction *LuaScriptAction, scriptPath string) {
	var (
		err            error
		scriptCompiled *lua.FunctionProto
	)

	if scriptCompiled, err = lualib.CompileLua(scriptPath); err != nil {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyError, err)

		return
	}

	luaAction.ScriptPath = scriptPath
	luaAction.ScriptCompiled = scriptCompiled
	aw.actionScripts = append(aw.actionScripts, luaAction)
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

	L := LuaPool.Get()

	defer LuaPool.Put(L)
	defer L.SetGlobal(global.LuaDefaultTable, lua.LNil)

	logs := new(lualib.CustomLogKeyValue)
	globals := aw.setupGlobals(L, logs, httpRequest)
	request := aw.setupRequest(L)

	for index := range aw.actionScripts {
		if aw.actionScripts[index].LuaAction == aw.luaActionRequest.LuaAction && !errors.Is((*aw.ctx).Err(), context.Canceled) {
			aw.runScript(index, L, request, logs)
		}
	}

	lualib.CleanupLTable(request)
	lualib.CleanupLTable(globals)

	request = nil
	globals = nil

	aw.luaActionRequest.FinishedChan <- Done{}
}

// setupGlobals sets up global Lua variables for the Worker.
// It creates a new Lua table to hold the global variables.
// If the DevMode flag is true in the EnvConfig, it calls the DebugModule function to log debug information.
// It sets the global variables LString(global.LuaActionResultOk) and LString(global.LuaActionResultFail) with the corresponding values.
// It sets the global functions LString(global.LuaFnCtxSet), LString(global.LuaFnCtxGet), LString(global.LuaFnCtxDelete), and LString(global.LuaFnAddCustomLog) to their respective Lua functions
func (aw *Worker) setupGlobals(L *lua.LState, logs *lualib.CustomLogKeyValue, httpRequest *http.Request) *lua.LTable {
	globals := L.NewTable()

	if config.EnvConfig.DevMode {
		util.DebugModule(global.DbgAction, global.LogKeyMsg, fmt.Sprintf("%+v", aw.luaActionRequest))
	}

	globals.RawSet(lua.LString(global.LuaActionResultOk), lua.LNumber(0))
	globals.RawSet(lua.LString(global.LuaActionResultFail), lua.LNumber(1))

	globals.RawSetString(global.LuaFnCtxSet, L.NewFunction(lualib.ContextSet(aw.luaActionRequest.Context)))
	globals.RawSetString(global.LuaFnCtxGet, L.NewFunction(lualib.ContextGet(aw.luaActionRequest.Context)))
	globals.RawSetString(global.LuaFnCtxDelete, L.NewFunction(lualib.ContextDelete(aw.luaActionRequest.Context)))
	globals.RawSetString(global.LuaFnAddCustomLog, L.NewFunction(lualib.AddCustomLog(logs)))
	globals.RawSetString(global.LuaFnGetAllHTTPRequestHeaders, L.NewFunction(lualib.GetAllHTTPRequestHeaders(httpRequest)))
	globals.RawSetString(global.LuaFnRedisGet, L.NewFunction(lualib.RedisGet))
	globals.RawSetString(global.LuaFnRedisSet, L.NewFunction(lualib.RedisSet))
	globals.RawSetString(global.LuaFnRedisIncr, L.NewFunction(lualib.RedisIncr))
	globals.RawSetString(global.LuaFnRedisDel, L.NewFunction(lualib.RedisDel))
	globals.RawSetString(global.LuaFnRedisExpire, L.NewFunction(lualib.RedisExpire))

	L.SetGlobal(global.LuaDefaultTable, globals)

	return globals
}

// setupRequest creates a Lua table representing the request data.
// The table contains various fields from aw.luaActionRequest.
// Returns the created request table.
func (aw *Worker) setupRequest(L *lua.LState) *lua.LTable {
	request := L.NewTable()

	request.RawSet(lua.LString(global.LuaRequestRepeating), lua.LBool(aw.luaActionRequest.Repeating))

	aw.luaActionRequest.CommonRequest.SetupRequest(request)

	return request
}

func getTaskName(action *LuaScriptAction) string {
	actionName := getLuaActionName(action)

	return fmt.Sprintf("%s:%s", actionName, action.ScriptPath)
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
func (aw *Worker) runScript(index int, L *lua.LState, request *lua.LTable, logs *lualib.CustomLogKeyValue) {
	var err error

	timer := prometheus.NewTimer(stats.FunctionDuration.WithLabelValues("Action", getTaskName(aw.actionScripts[index])))

	defer timer.ObserveDuration()

	luaCtx, luaCancel := context.WithTimeout(*(aw.ctx), viper.GetDuration("lua_script_timeout")*time.Second)
	L.SetContext(luaCtx)

	if err = aw.executeScript(L, index, request); err != nil {
		aw.logScriptFailure(index, err, logs)
		luaCancel()
	}

	ret := L.ToInt(-1)

	L.Pop(1)
	util.DebugModule(
		global.DbgAction,
		"context", fmt.Sprintf("%+v", aw.luaActionRequest.Context),
	)

	if err == nil {
		level.Info(logging.DefaultLogger).Log(
			append([]any{
				global.LogKeyGUID, aw.luaActionRequest.Session,
				"script", aw.actionScripts[index].ScriptPath,
				"feature", func() string {
					if aw.luaActionRequest.FeatureName != "" {
						return aw.luaActionRequest.FeatureName
					}

					return global.NotAvailable
				}(),
				global.LogKeyMsg, "Lua action finished",
				"result", aw.createResultLogMessage(ret),
			}, toLoggable(logs)...)...,
		)
	}

	luaCancel()
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
		Fn:      L.GetGlobal(global.LuaFnCallAction),
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
	level.Error(logging.DefaultErrLogger).Log(
		append([]any{
			global.LogKeyGUID, aw.luaActionRequest.Session,
			"script", aw.actionScripts[index].ScriptPath,
			global.LogKeyError, err,
		}, toLoggable(logs)...)...,
	)
}

// createResultLogMessage generates a log message based on the given result code.
func (aw *Worker) createResultLogMessage(resultCode int) string {
	if resultCode == 0 || resultCode == 1 {
		return aw.resultMap[resultCode]
	}

	return "undefined result"
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

// getLuaActionType maps a given actionName string to its corresponding global.LuaAction constant.
// If actionName matches any of the predefined names, the corresponding constant is returned.
// Otherwise, global.LuaActionNone is returned.
func getLuaActionType(actionName string) global.LuaAction {
	switch actionName {
	case global.LuaActionBruteForceName:
		return global.LuaActionBruteForce
	case global.LuaActionRBLName:
		return global.LuaActionRBL
	case global.LuaActionTLSName:
		return global.LuaActionTLS
	case global.LuaActionRelayDomainsName:
		return global.LuaActionRelayDomains
	case global.LuaActionLuaName:
		return global.LuaActionLua
	case global.LuaActionPostName:
		return global.LuaActionPost
	default:
		return global.LuaActionNone
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
	case global.LuaActionBruteForce:
		return global.LuaActionBruteForceName
	case global.LuaActionRBL:
		return global.LuaActionRBLName
	case global.LuaActionTLS:
		return global.LuaActionTLSName
	case global.LuaActionRelayDomains:
		return global.LuaActionRelayDomainsName
	case global.LuaActionLua:
		return global.LuaActionLuaName
	case global.LuaActionPost:
		return global.LuaActionPostName
	default:
		return "-"
	}
}
