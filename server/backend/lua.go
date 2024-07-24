package backend

import (
	"context"
	"fmt"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/smtp"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/spf13/viper"
	lua "github.com/yuin/gopher-lua"
)

// LuaRequestChan is a channel that carries LuaRequest pointers from various sources.
var LuaRequestChan chan *LuaRequest

// LuaMainWorkerEndChan is a channel that signals the termination of the main Lua worker.
var LuaMainWorkerEndChan chan Done

// LuaPool is a pool of Lua state instances.
var LuaPool = lualib.NewLuaBackendResultStatePool(
	global.LuaBackendResultAuthenticated,
	global.LuaBackendResultUserFound,
	global.LuaBackendResultAccountField,
	global.LuaBackendResultTOTPSecretField,
	global.LuaBackendResultTOTPRecoveryField,
	global.LuaBAckendResultUniqueUserIDField,
	global.LuaBackendResultDisplayNameField,
	global.LuaBackendResultAttributes,
)

// LuaRequest is a subset from the Authentication struct.
// LuaRequest is a struct that includes various information for a request to Lua.
type LuaRequest struct {
	// Function is the Lua command that will be executed.
	Function global.LuaCommand

	// TOTPSecret is the secret value used in time-based one-time password (TOTP) authentication.
	TOTPSecret string

	// Service is the specific service requested by the client.
	Service string

	// Protocol points to the protocol that was used by a client to make the request.
	Protocol *config.Protocol

	// Logs points to custom log key-value pairs to help track the request.
	Logs *lualib.CustomLogKeyValue

	// Context provides context for the Lua command request.
	*lualib.Context

	*lualib.CommonRequest

	// HTTPClientContext is the client request context from a remote party.
	HTTPClientContext *gin.Context

	// LuaReplyChan is a channel to receive the response from the Lua backend.
	LuaReplyChan chan *lualib.LuaBackendResult
}

// LuaMainWorker is responsible for executing Lua scripts using the provided context.
// It compiles a Lua script from the specified path and waits for incoming requests.
// When a request is received, it spawns a goroutine to handle the request asynchronously,
// passing the compiled script, the request, and the context.
// If the context is canceled, LuaMainWorker will send a Done signal to notify the caller.
func LuaMainWorker(ctx context.Context) {
	scriptPath := config.LoadableConfig.GetLuaScriptPath()

	compiledScript, err := lualib.CompileLua(scriptPath)
	if err != nil {
		panic(err)
	}

	for {
		select {
		case <-ctx.Done():
			LuaMainWorkerEndChan <- Done{}

			return

		case luaRequest := <-LuaRequestChan:
			go handleLuaRequest(ctx, luaRequest, compiledScript)
		}
	}
}

// handleLuaRequest handles a Lua request by executing the compiled script and handling any errors.
// It registers libraries and globals, sets Lua request parameters, and calls the Lua command function.
// It then handles the specific return types based on the Lua request function.
//
// Parameters:
// - luaRequest: The LuaRequest object containing the request parameters.
// - ctx: The Context object.
// - compiledScript: The compiled Lua script function.
//
// Returns: None.
func handleLuaRequest(ctx context.Context, luaRequest *LuaRequest, compiledScript *lua.FunctionProto) {
	var (
		nret       int
		luaCommand string
	)

	logs := new(lualib.CustomLogKeyValue)
	luaCtx, luaCancel := context.WithTimeout(ctx, viper.GetDuration("lua_script_timeout")*time.Second)

	L := LuaPool.Get()

	defer LuaPool.Put(L)

	L.SetContext(luaCtx)

	defer luaCancel()

	registerLibraries(L)

	globals := setupGlobals(luaRequest, L, logs)
	request := L.NewTable()

	luaCommand, nret = setLuaRequestParameters(luaRequest, request)

	err := executeAndHandleError(compiledScript, luaCommand, luaRequest, L, request, nret, logs)

	lualib.CleanupLTable(globals)

	request = nil
	globals = nil

	// Handle the specific return types
	if err == nil {
		handleReturnTypes(L, nret, luaRequest, logs)
	}
}

// registerLibraries registers various libraries to the given LState.
// It preloads libraries, registers the backend result type, and preloads a module.
func registerLibraries(L *lua.LState) {
	L.PreloadModule(global.LuaModUtil, lualib.Loader)
}

// setupGlobals registers global variables and functions used in Lua scripts.
// Registers the backend result types LuaBackendResultOk and LuaBackendResultFail with global variables 0 and 1 respectively.
// Registers the lua function ctx.Set with name "context_set" which sets a value in the LuaRequest.Context.
// Registers the lua function ctx.Get with name "context_get" which retrieves a value from the LuaRequest.Context.
// Registers the lua function ctx.Delete with name "context_delete" which deletes a value from the LuaRequest.Context.
// Registers the lua function AddCustomLog with name "custom_log_add" which adds a custom log entry to the LuaRequest.Logs.
// The registered global table is assigned to the global variable LuaDefaultTable.
// The generated table is returned from the function.
func setupGlobals(luaRequest *LuaRequest, L *lua.LState, logs *lualib.CustomLogKeyValue) *lua.LTable {
	globals := L.NewTable()

	globals.RawSet(lua.LString(global.LuaBackendResultOk), lua.LNumber(0))
	globals.RawSet(lua.LString(global.LuaBackendResultFail), lua.LNumber(1))

	globals.RawSetString(global.LuaFnAddCustomLog, L.NewFunction(lualib.AddCustomLog(logs)))
	globals.RawSetString(global.LuaFnSetStatusMessage, L.NewFunction(lualib.SetStatusMessage(&luaRequest.StatusMessage)))
	globals.RawSetString(global.LuaFnGetAllHTTPRequestHeaders, L.NewFunction(lualib.GetAllHTTPRequestHeaders(luaRequest.HTTPClientContext.Request)))
	globals.RawSetString(global.LuaFnGetHTTPRequestHeader, L.NewFunction(lualib.GetHTTPRequestHeader(luaRequest.HTTPClientContext.Request)))
	globals.RawSetString(global.LuaFnSendMail, L.NewFunction(lualib.SendMail(&smtp.EmailClient{})))

	lualib.SetUPContextFunctions(luaRequest.Context, globals, L)
	lualib.SetUPRedisFunctions(globals, L)

	if config.LoadableConfig.HaveLDAPBackend() {
		globals.RawSetString(global.LuaFnLDAPSearch, L.NewFunction(LuaLDAPSearch(luaRequest.HTTPClientContext)))
	}

	L.SetGlobal(global.LuaDefaultTable, globals)

	return globals
}

// setLuaRequestParameters sets the Lua request parameters based on the given LuaRequest object and Lua table.
// It also returns the Lua command string and the number of return values.
//
// Parameters:
// - luaRequest: The LuaRequest object.
// - request: The Lua table to set the parameters on.
//
// Returns:
// - luaCommand: The Lua command string.
// - nret: The number of return values.
func setLuaRequestParameters(luaRequest *LuaRequest, request *lua.LTable) (luaCommand string, nret int) {
	switch luaRequest.Function {
	case global.LuaCommandPassDB:
		luaCommand = global.LuaFnBackendVerifyPassword
		nret = 2

		luaRequest.SetupRequest(request)
	case global.LuaCommandListAccounts:
		luaCommand = global.LuaFnBackendListAccounts
		nret = 2

		request.RawSet(lua.LString(global.LuaRequestDebug), lua.LBool(luaRequest.Debug))
		request.RawSetString(global.LuaRequestSession, lua.LString(luaRequest.Session))
	case global.LuaCommandAddMFAValue:
		luaCommand = global.LuaFnBackendAddTOTPSecret
		nret = 1

		request.RawSetString(global.LuaRequestTOTPSecret, lua.LString(luaRequest.TOTPSecret))
		request.RawSet(lua.LString(global.LuaRequestDebug), lua.LBool(luaRequest.Debug))
		request.RawSetString(global.LuaRequestSession, lua.LString(luaRequest.Session))
	}

	return luaCommand, nret
}

// executeAndHandleError executes the compiled Lua script and handles any errors that occur during execution.
// If an error occurs during the execution of the compiled script or when calling a Lua command, it will be processed using the processError function.
// The compiledScript parameter is a pointer to the compiled Lua script.
// The luaCommand parameter is the name of the Lua command to call.
// The luaRequest parameter represents the LuaRequest object containing the request data.
// The L parameter is the Lua state.
// The request parameter is a Lua table representing the request data.
// The nret parameter specifies the number of return values expected from the Lua command.
// The logs parameter is a pointer to a CustomLogKeyValue object for logging purposes.
// The function returns an error object in case of any errors that occurred during execution.
//
// Example usage:
//
//	err := executeAndHandleError(compiledScript, luaCommand, luaRequest, L, request, nret, logs)
func executeAndHandleError(compiledScript *lua.FunctionProto, luaCommand string, luaRequest *LuaRequest, L *lua.LState, request *lua.LTable, nret int, logs *lualib.CustomLogKeyValue) (err error) {
	if err = lualib.PackagePath(L); err != nil {
		processError(err, luaRequest, logs)
	}

	if err = lualib.DoCompiledFile(L, compiledScript); err != nil {
		processError(err, luaRequest, logs)
	}

	if err = L.CallByParam(lua.P{
		Fn:      L.GetGlobal(luaCommand),
		NRet:    nret,
		Protect: true,
	}, request); err != nil {
		processError(err, luaRequest, logs)
	}

	lualib.CleanupLTable(request)

	return err
}

// handleReturnTypes handles the different return types from Lua scripts.
// The function takes the Lua state, the number of return values, the Lua request,
// and the custom logs as arguments.
//
// If the return value is non-zero, it indicates an error in the Lua script. In this case,
// the function sends an error message with the custom logs to the LuaReplyChan channel
// and returns.
//
// If the Lua request function is LuaCommandPassDB, the function expects the return value
// to be a user data object of type *LuaBackendResult. If it matches the expected type,
// the logs are appended to the LuaBackendResult, and it is sent to the LuaReplyChan channel.
// If the user data object does not match the expected type, an error message is sent
// with the custom logs to the LuaReplyChan channel.
//
// If the Lua request function is LuaCommandListAccounts, the function expects the return value
// to be a Lua table. The function converts the table to a map using the LuaTableToMap function,
// assigns it to the Attributes field of a new LuaBackendResult, and sends it to the LuaReplyChan channel.
//
// For all other Lua request functions, the function sends an empty LuaBackendResult with the custom logs
// to the LuaReplyChan channel.
func handleReturnTypes(L *lua.LState, nret int, luaRequest *LuaRequest, logs *lualib.CustomLogKeyValue) {
	ret := L.ToInt(-nret)
	if ret != 0 {
		luaRequest.LuaReplyChan <- &lualib.LuaBackendResult{
			Err:  errors.ErrBackendLua.WithDetail("Lua script finished with an error"),
			Logs: logs,
		}

		return
	}

	switch luaRequest.Function {
	case global.LuaCommandPassDB:
		userData := L.ToUserData(-1)

		if luaBackendResult, assertOk := userData.Value.(*lualib.LuaBackendResult); assertOk {
			luaBackendResult.Logs = logs

			util.DebugModule(
				global.DbgLua,
				global.LogKeyGUID, luaRequest.Session,
				"result", fmt.Sprintf("%+v", luaBackendResult),
			)

			luaRequest.LuaReplyChan <- luaBackendResult
		} else {
			luaRequest.LuaReplyChan <- &lualib.LuaBackendResult{
				Err:  errors.ErrBackendLuaWrongUserData.WithDetail("Lua script returned a wrong user data object"),
				Logs: logs,
			}
		}

	case global.LuaCommandListAccounts:
		luaRequest.LuaReplyChan <- &lualib.LuaBackendResult{
			Attributes: lualib.LuaTableToMap(L.ToTable(-1)),
			Logs:       logs,
		}

	default:
		luaRequest.LuaReplyChan <- &lualib.LuaBackendResult{
			Logs: logs,
		}
	}
}

// processError logs the error and sends a LuaBackendResult with the error and the logs to the LuaRequest's LuaReplyChan.
// It takes an error, a LuaRequest, and a logs slice of CustomLogKeyValue as parameters.
// The error is logged at the Error level using the DefaultErrLogger.
// The logs contain the session GUID and the path to the Lua script.
// Lastly, the LuaBackendResult is sent to the LuaRequest's LuaReplyChan.
func processError(err error, luaRequest *LuaRequest, logs *lualib.CustomLogKeyValue) {
	level.Error(logging.DefaultErrLogger).Log(
		global.LogKeyGUID, luaRequest.Session,
		"script", config.LoadableConfig.GetLuaScriptPath(),
		global.LogKeyError, err,
	)

	luaRequest.LuaReplyChan <- &lualib.LuaBackendResult{
		Err:  err,
		Logs: logs,
	}
}
