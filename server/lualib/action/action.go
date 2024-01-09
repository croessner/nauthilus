package action

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/decl"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	"github.com/spf13/viper"
	"github.com/tengattack/gluacrypto"
	libs "github.com/vadv/gopher-lua-libs"
	"github.com/yuin/gopher-lua"
)

var (
	RequestChan   chan *Action
	WorkerEndChan chan lualib.Done
)

type Done struct{}

type LuaScriptAction struct {
	ScriptPath     string
	ScriptCompiled *lua.FunctionProto
	LuaAction      decl.LuaAction
}

// Action contains a subset of the Authentication structure.
type Action struct {
	LuaAction decl.LuaAction

	Debug         bool
	Repeating     bool
	UserFound     bool
	Authenticated bool
	NoAuth        bool

	BruteForceCounter uint

	Session      string // GUID
	ClientIP     string
	ClientPort   string
	ClientNet    string
	ClientHost   string
	ClientID     string
	LocalIP      string
	LocalPort    string
	Username     string
	Account      string
	UniqueUserID string
	DisplayName  string
	Password     string
	Protocol     string

	BruteForceName string
	FeatureName    string

	*lualib.Context

	FinishedChan chan Done
}

type Worker struct {
	ctx              *context.Context
	luaActionRequest *Action
	actionScripts    []*LuaScriptAction
	resultMap        map[int]string
}

// NewWorker creates a new instance of the Worker struct.
// It initializes a resultMap map with two key-value pairs.
// It initializes a RequestChan channel with a maximum size of MaxChannelSize.
// It returns a pointer to the newly created Worker.
func NewWorker() *Worker {
	resultMap := make(map[int]string, 2)

	resultMap[0] = decl.LuaSuccess
	resultMap[1] = decl.LuaFail
	RequestChan = make(chan *Action, decl.MaxChannelSize)

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

	if config.LoadableConfig.Lua == nil {
		return
	}

	aw.loadActionScriptsFromConfiguration()

	for {
		select {
		case <-ctx.Done():
			WorkerEndChan <- lualib.Done{}
			break
		case aw.luaActionRequest = <-RequestChan:
			aw.handleRequest()
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

	if luaAction.LuaAction != decl.LuaActionNone {
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
		level.Error(logging.DefaultErrLogger).Log(decl.LogKeyError, err)

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
func (aw *Worker) handleRequest() {
	L := lua.NewState()

	libs.Preload(L)
	gluacrypto.Preload(L)

	logs := new(lualib.CustomLogKeyValue)
	aw.setupGlobalVariables(L, logs)
	request := aw.createRequestTable(L)

	for index := range aw.actionScripts {
		if aw.actionScripts[index].LuaAction == aw.luaActionRequest.LuaAction && !errors.Is((*aw.ctx).Err(), context.Canceled) {
			aw.runScript(index, L, request, logs)
		}
	}
}

// setupGlobalVariables sets up global Lua variables for the Worker.
// It creates a new Lua table to hold the global variables.
// If the DevMode flag is true in the EnvConfig, it calls the DebugModule function to log debug information.
// It sets the global variables LString(decl.LuaActionResultOk) and LString(decl.LuaActionResultFail) with the corresponding values.
// It sets the global functions LString(decl.LuaFnCtxSet), LString(decl.LuaFnCtxGet), LString(decl.LuaFnCtxDelete), and LString(decl.LuaFnAddCustomLog) to their respective Lua functions
func (aw *Worker) setupGlobalVariables(L *lua.LState, logs *lualib.CustomLogKeyValue) *lua.LTable {
	globals := L.NewTable()

	if config.EnvConfig.DevMode {
		util.DebugModule(decl.DbgAction, decl.LogKeyMsg, fmt.Sprintf("%+v", aw.luaActionRequest))
	}

	globals.RawSet(lua.LString(decl.LuaActionResultOk), lua.LNumber(0))
	globals.RawSet(lua.LString(decl.LuaActionResultFail), lua.LNumber(1))

	globals.RawSetString(decl.LuaFnCtxSet, L.NewFunction(lualib.ContextSet(aw.luaActionRequest.Context)))
	globals.RawSetString(decl.LuaFnCtxGet, L.NewFunction(lualib.ContextGet(aw.luaActionRequest.Context)))
	globals.RawSetString(decl.LuaFnCtxDelete, L.NewFunction(lualib.ContextDelete(aw.luaActionRequest.Context)))
	globals.RawSetString(decl.LuaFnAddCustomLog, L.NewFunction(lualib.AddCustomLog(logs)))

	L.SetGlobal(decl.LuaDefaultTable, globals)

	return globals
}

// createRequestTable creates a Lua table representing the request data.
// The table contains various fields from aw.luaActionRequest.
// Each field is added to the Lua table using its respective Lua key and value type.
// Returns the created request table.
func (aw *Worker) createRequestTable(L *lua.LState) *lua.LTable {
	request := L.NewTable()

	request.RawSet(lua.LString(decl.LuaRequestDebug), lua.LBool(aw.luaActionRequest.Debug))
	request.RawSet(lua.LString(decl.LuaRequestRepeating), lua.LBool(aw.luaActionRequest.Repeating))
	request.RawSet(lua.LString(decl.LuaRequestBruteForceCounter), lua.LNumber(aw.luaActionRequest.BruteForceCounter))
	request.RawSet(lua.LString(decl.LuaRequestNoAuth), lua.LBool(aw.luaActionRequest.NoAuth))
	request.RawSet(lua.LString(decl.LuaRequestAuthenticated), lua.LBool(aw.luaActionRequest.Authenticated))
	request.RawSet(lua.LString(decl.LuaRequestUserFound), lua.LBool(aw.luaActionRequest.UserFound))
	request.RawSetString(decl.LuaRequestSession, lua.LString(aw.luaActionRequest.Session))
	request.RawSetString(decl.LuaRequestClientIP, lua.LString(aw.luaActionRequest.ClientIP))
	request.RawSetString(decl.LuaRequestClientPort, lua.LString(aw.luaActionRequest.ClientPort))
	request.RawSetString(decl.LuaRequestClientNet, lua.LString(aw.luaActionRequest.ClientNet))
	request.RawSetString(decl.LuaRequestClientHost, lua.LString(aw.luaActionRequest.ClientHost))
	request.RawSetString(decl.LuaRequestClientID, lua.LString(aw.luaActionRequest.ClientID))
	request.RawSetString(decl.LuaRequestLocalIP, lua.LString(aw.luaActionRequest.LocalIP))
	request.RawSetString(decl.LuaRequestLocalPort, lua.LString(aw.luaActionRequest.LocalPort))
	request.RawSetString(decl.LuaRequestUsername, lua.LString(aw.luaActionRequest.Username))
	request.RawSetString(decl.LuaRequestAccount, lua.LString(aw.luaActionRequest.Account))
	request.RawSetString(decl.LuaRequestUniqueUserID, lua.LString(aw.luaActionRequest.UniqueUserID))
	request.RawSetString(decl.LuaRequestDisplayName, lua.LString(aw.luaActionRequest.DisplayName))
	request.RawSetString(decl.LuaRequestPassword, lua.LString(aw.luaActionRequest.Password))
	request.RawSetString(decl.LuaRequestProtocol, lua.LString(aw.luaActionRequest.Protocol))
	request.RawSetString(decl.LuaRequestBruteForceBucket, lua.LString(aw.luaActionRequest.BruteForceName))
	request.RawSetString(decl.LuaRequestFeature, lua.LString(aw.luaActionRequest.FeatureName))

	return request
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

	luaCtx, luaCancel := context.WithTimeout(*(aw.ctx), viper.GetDuration("lua_script_timeout")*time.Second)
	L.SetContext(luaCtx)

	if err = aw.executeScript(L, index, request); err != nil {
		aw.logScriptFailure(index, err, logs)
		luaCancel()
	}

	ret := L.ToInt(-1)

	L.Pop(1)
	util.DebugModule(
		decl.DbgAction,
		"context", fmt.Sprintf("%+v", aw.luaActionRequest.Context),
	)

	if err == nil {
		level.Info(logging.DefaultLogger).Log(
			append([]any{
				decl.LogKeyGUID, aw.luaActionRequest.Session,
				"script", aw.actionScripts[index].ScriptPath,
				"feature", func() string {
					if aw.luaActionRequest.FeatureName != "" {
						return aw.luaActionRequest.FeatureName
					}

					return decl.NotAvailable
				}(),
				decl.LogKeyMsg, "Lua action finished",
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
	if err := lualib.DoCompiledFile(L, aw.actionScripts[index].ScriptCompiled); err != nil {
		return err
	}

	if err := L.CallByParam(lua.P{
		Fn:      L.GetGlobal(decl.LuaFnCallAction),
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
			decl.LogKeyGUID, aw.luaActionRequest.Session,
			"script", aw.actionScripts[index].ScriptPath,
			decl.LogKeyError, err,
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

// getLuaActionType maps a given actionName string to its corresponding decl.LuaAction constant.
// If actionName matches any of the predefined names, the corresponding constant is returned.
// Otherwise, decl.LuaActionNone is returned.
func getLuaActionType(actionName string) decl.LuaAction {
	switch actionName {
	case decl.LuaActionBruteForceName:
		return decl.LuaActionBruteForce
	case decl.LuaActionRBLName:
		return decl.LuaActionRBL
	case decl.LuaActionTLSName:
		return decl.LuaActionTLS
	case decl.LuaActionRelayDomainsName:
		return decl.LuaActionRelayDomains
	case decl.LuaActionLuaName:
		return decl.LuaActionLua
	case decl.LuaActionPostName:
		return decl.LuaActionPost
	default:
		return decl.LuaActionNone
	}
}
