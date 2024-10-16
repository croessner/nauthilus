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

package backend

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/convert"
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

// LoaderModLDAP is a function that returns a LGFunction.
// The returned LGFunction sets up a table with the function name global.LuaFnLDAPSearch
// and its corresponding LuaLDAPSearch function.
// It then pushes the table onto the Lua stack and returns 1.
// The function is intended to be used as a loader for the LDAP module in Lua scripts.
//
// Parameters:
// - ctx: The context.Context object.
//
// Returns: The LGFunction that sets up the LDAP module table.
func LoaderModLDAP(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			global.LuaFnLDAPSearch: LuaLDAPSearch(ctx),
		})

		L.Push(mod)

		return 1
	}
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

// registerDynamicLoader registers a dynamic loader function in the Lua state.
// The dynamic loader function is responsible for registering common Lua libraries
// and modules based on the modName value. It also sets a global variable "dynamic_loader"
// with the dynamic loader function.
//
// Parameters:
// - L: The *lua.LState representing the Lua state.
// - ctx: The context.Context object.
// - luaRequest: The *LuaRequest object containing the request parameters.
//
// Returns: None.
func registerDynamicLoader(L *lua.LState, ctx context.Context, luaRequest *LuaRequest, httpClient *http.Client) {
	dynamicLoader := L.NewFunction(func(L *lua.LState) int {
		modName := L.CheckString(1)

		registry := make(map[string]bool)
		if _, found := registry[modName]; found {
			return 0
		}

		lualib.RegisterCommonLuaLibraries(L, ctx, modName, registry, httpClient)
		registerModule(L, ctx, luaRequest, modName, registry)

		return 0
	})

	L.SetGlobal("dynamic_loader", dynamicLoader)
}

// registerModule registers a module in the Lua state based on the given modName.
// It uses the Lua state L, the context.Context ctx, the *LuaRequest luaRequest, and the map[string]bool registry.
// If modName is global.LuaModHTTPRequest, it preloads the Lua module with the given modName and the lualib.LoaderModHTTPRequest function.
// If modName is global.LuaModLDAP and the LDAP backend is activated, it preloads the Lua module with the given modName and the LoaderModLDAP function.
// If modName is not global.LuaModHTTPRequest or global.LuaModLDAP, it does nothing and returns.
// It marks the modName key in the registry as true.
//
// Parameters:
// - L: The *lua.LState representing the Lua state.
// - ctx: The context.Context object.
// - luaRequest: The *LuaRequest object containing the request parameters.
// - modName: The name of the module to register.
// - registry: A map containing the registered modules.
//
// Returns: None.
func registerModule(L *lua.LState, ctx context.Context, luaRequest *LuaRequest, modName string, registry map[string]bool) {
	switch modName {
	case global.LuaModContext:
		L.PreloadModule(modName, lualib.LoaderModContext(luaRequest.Context))
	case global.LuaModHTTPRequest:
		L.PreloadModule(modName, lualib.LoaderModHTTPRequest(luaRequest.HTTPClientContext.Request))
	case global.LuaModLDAP:
		if config.LoadableConfig.HaveLDAPBackend() {
			L.PreloadModule(modName, LoaderModLDAP(ctx))
		} else {
			L.RaiseError("LDAP backend not activated")
		}
	default:
		return
	}

	registry[modName] = true
}

// handleLuaRequest is a function that handles a Lua request. It takes a context, a LuaRequest object, and a compiled Lua script as parameters.
// It sets up the Lua state, registers libraries, and preloads modules. It sets up global variables and creates a Lua table for the request.
// It sets the Lua request parameters based on the LuaRequest object and the Lua table. Then it executes the Lua script and handles any errors.
// Finally, it handles the specific return types based on the result of the Lua script execution.
//
// Parameters:
// - ctx: The context.Context object.
// - luaRequest: The LuaRequest object containing the request parameters.
// - compiledScript: The compiled Lua script.
//
// Returns: None.
func handleLuaRequest(ctx context.Context, luaRequest *LuaRequest, compiledScript *lua.FunctionProto) {
	var (
		nret       int
		luaCommand string
	)

	logs := new(lualib.CustomLogKeyValue)
	luaCtx, luaCancel := context.WithTimeout(ctx, viper.GetDuration("lua_script_timeout")*time.Second)

	defer luaCancel()

	L := lua.NewState()

	defer L.Close()

	L.SetContext(luaCtx)

	lualib.RegisterBackendResultType(
		L,
		global.LuaBackendResultAuthenticated,
		global.LuaBackendResultUserFound,
		global.LuaBackendResultAccountField,
		global.LuaBackendResultTOTPSecretField,
		global.LuaBackendResultTOTPRecoveryField,
		global.LuaBAckendResultUniqueUserIDField,
		global.LuaBackendResultDisplayNameField,
		global.LuaBackendResultAttributes,
	)

	httpClient, closeHTTPClient := util.NewClosingHTTPClient()

	defer closeHTTPClient()

	registerDynamicLoader(L, ctx, luaRequest, httpClient)

	setupGlobals(luaRequest, L, logs)

	request := L.NewTable()

	luaCommand, nret = setLuaRequestParameters(luaRequest, request)

	err := executeAndHandleError(compiledScript, luaCommand, luaRequest, L, request, nret, logs)

	// Handle the specific return types
	if err == nil {
		handleReturnTypes(L, nret, luaRequest, logs)
	}
}

// setupGlobals sets up global variables for the Lua state. It creates a new Lua table to hold the global variables,
// and assigns values to the predefined global variables. It also registers Lua functions for custom log addition and
// setting the status message. Finally, it sets the global table in the Lua state.
//
// Parameters:
// - luaRequest: The LuaRequest object containing the request parameters.
// - L: The Lua state.
// - logs: The custom log key-value pairs.
//
// Returns: None.
func setupGlobals(luaRequest *LuaRequest, L *lua.LState, logs *lualib.CustomLogKeyValue) {
	globals := L.NewTable()

	globals.RawSet(lua.LString(global.LuaBackendResultOk), lua.LNumber(0))
	globals.RawSet(lua.LString(global.LuaBackendResultFail), lua.LNumber(1))

	globals.RawSetString(global.LuaFnAddCustomLog, L.NewFunction(lualib.AddCustomLog(logs)))
	globals.RawSetString(global.LuaFnSetStatusMessage, L.NewFunction(lualib.SetStatusMessage(&luaRequest.StatusMessage)))

	L.SetGlobal(global.LuaDefaultTable, globals)
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
			Attributes: convert.LuaTableToMap(L.ToTable(-1)),
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
// The error is logged at the Error level using the Logger.
// The logs contain the session GUID and the path to the Lua script.
// Lastly, the LuaBackendResult is sent to the LuaRequest's LuaReplyChan.
func processError(err error, luaRequest *LuaRequest, logs *lualib.CustomLogKeyValue) {
	level.Error(log.Logger).Log(
		global.LogKeyGUID, luaRequest.Session,
		"script", config.LoadableConfig.GetLuaScriptPath(),
		global.LogKeyError, err,
	)

	luaRequest.LuaReplyChan <- &lualib.LuaBackendResult{
		Err:  err,
		Logs: logs,
	}
}
