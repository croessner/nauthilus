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

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/lualib/vmpool"
	"github.com/croessner/nauthilus/server/util"

	"github.com/spf13/viper"
	lua "github.com/yuin/gopher-lua"
)

// httpClient is a pre-configured instance of http.Client with custom timeout and TLS settings for making HTTP requests.
var httpClient *http.Client

// InitHTTPClient initializes the global httpClient variable with a pre-configured instance from util.NewHTTPClient.
func InitHTTPClient() {
	httpClient = util.NewHTTPClient()
}

// LoaderModLDAP initializes and loads the LDAP module into the Lua state with predefined functions for LDAP operations.
func LoaderModLDAP(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnLDAPSearch: LuaLDAPSearch(ctx),
			definitions.LuaFnLDAPModify: LuaLDAPModify(ctx),
		})

		L.Push(mod)

		return 1
	}
}

// LuaMainWorker processes Lua script requests in a loop until the context is canceled.
// It compiles the Lua script and handles requests using a dedicated goroutine for each.
// It now uses a priority queue instead of channels for better request handling.
func LuaMainWorker(ctx context.Context, backendName string) (err error) {
	var (
		numberOfWorkers int
		scriptPath      string
	)

	errMsg := fmt.Sprintf("Lua backend script path not set for backend %s", backendName)

	if backendName == definitions.DefaultBackendName {
		numberOfWorkers = config.GetFile().GetLuaNumberOfWorkers()

		scriptPath = config.GetFile().GetLuaScriptPath()
		if scriptPath == "" {
			panic(errMsg)
		}
	} else {
		optionalBackends := config.GetFile().GetLua().GetOptionalLuaBackends()

		if optionalBackends == nil {
			panic(errMsg)
		}

		if backendConf, found := optionalBackends[backendName]; found {
			numberOfWorkers = backendConf.GetNumberOfWorkers()

			if backendConf.BackendScriptPath != "" {
				scriptPath = backendConf.BackendScriptPath
			} else {
				panic(errMsg)
			}
		} else {
			panic(errMsg)
		}
	}

	compiledScript, err := lualib.CompileLua(scriptPath)
	if err != nil {
		panic(err)
	}

	util.DebugModule(
		definitions.DbgLua,
		definitions.LogKeyMsg, "lua_main_worker_created",
		definitions.LogKeyBackendName, backendName,
		"number_of_workers", numberOfWorkers,
		"script_path", scriptPath,
	)

	// Add the backend name to the queue
	priorityqueue.LuaQueue.AddBackendName(backendName)

	// Configure queue length limit from config (0 = unlimited)
	queueLen := 0
	if backendName == definitions.DefaultBackendName {
		if cfg := config.GetFile().GetLua().GetConfig(); cfg != nil {
			if c, ok := cfg.(*config.LuaConf); ok {
				queueLen = c.GetQueueLength()
			}
		}
	} else {
		optionalBackends := config.GetFile().GetLua().GetOptionalLuaBackends()
		if optionalBackends != nil {
			if bc := optionalBackends[backendName]; bc != nil {
				queueLen = bc.GetQueueLength()
			}
		}
	}

	priorityqueue.LuaQueue.SetMaxQueueLength(backendName, queueLen)

	// Create per-backend VM pool with MaxVMs equal to number of workers
	vmPool := vmpool.GetManager().GetOrCreate(vmpool.PoolKey("backend:"+backendName), vmpool.PoolOptions{MaxVMs: numberOfWorkers})

	for i := 0; i < numberOfWorkers; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				default:
					// Get the next request from the priority queue
					luaRequest := priorityqueue.LuaQueue.Pop(backendName)

					handleLuaRequest(ctx, luaRequest, compiledScript, vmPool)
				}
			}
		}()
	}

	return
}

// registerDynamicLoader registers a dynamic_loader function in the Lua state to dynamically load modules at runtime.
func registerDynamicLoader(L *lua.LState, ctx context.Context, luaRequest *bktype.LuaRequest) {
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

// registerModule loads a specified Lua module into the Lua state and registers it as available in the provided registry.
// It supports modules for context, HTTP requests, and LDAP based on the given module name and configurations.
// If the LDAP backend is not activated, an error is raised for the LDAP module.
func registerModule(L *lua.LState, ctx context.Context, luaRequest *bktype.LuaRequest, modName string, registry map[string]bool) {
	switch modName {
	case definitions.LuaModContext:
		L.PreloadModule(modName, lualib.LoaderModContext(luaRequest.Context))
	case definitions.LuaModHTTPRequest:
		L.PreloadModule(modName, lualib.LoaderModHTTPRequest(luaRequest.HTTPClientContext.Request))
	case definitions.LuaModLDAP:
		if config.GetFile().HaveLDAPBackend() {
			L.PreloadModule(modName, LoaderModLDAP(ctx))
		} else {
			L.RaiseError("LDAP backend not activated")
		}
	default:
		return
	}

	registry[modName] = true
}

// handleLuaRequest processes a Lua script execution request in the given context using the specified compiled script.
// It initializes a Lua state, sets up the environment, runs the script, and handles return values or errors.
// Parameters:
// - ctx: The context for the Lua execution, including cancellation and timeout.
// - luaRequest: The LuaRequest object containing details about the script execution request.
// - compiledScript: The precompiled Lua script to be executed.
func handleLuaRequest(ctx context.Context, luaRequest *bktype.LuaRequest, compiledScript *lua.FunctionProto, vmPool *vmpool.Pool) {
	var (
		nret       int
		luaCommand string
	)

	startTime := time.Now()
	defer func() {
		latency := time.Since(startTime)
		level.Info(log.Logger).Log(
			definitions.LogKeyGUID, luaRequest.Session,
			definitions.LogKeyMsg, "Lua backend handler latency",
			definitions.LogKeyLatency, fmt.Sprintf("%v", latency),
		)
	}()

	logs := new(lualib.CustomLogKeyValue)
	luaCtx, luaCancel := context.WithTimeout(ctx, viper.GetDuration("lua_script_timeout")*time.Second)

	defer luaCancel()

	L, acqErr := vmPool.Acquire(luaCtx)
	if acqErr != nil {
		level.Warn(log.Logger).Log(definitions.LogKeyMsg, "lua_vm_acquire_failed", "err", acqErr)

		return
	}

	replaceVM := false
	defer func() {
		if r := recover(); r != nil {
			replaceVM = true
		}

		if replaceVM {
			vmPool.Replace(L)
		} else {
			vmPool.Release(L)
		}
	}()

	L.SetContext(luaCtx)

	lualib.RegisterBackendResultType(
		L,
		definitions.LuaBackendResultAuthenticated,
		definitions.LuaBackendResultUserFound,
		definitions.LuaBackendResultAccountField,
		definitions.LuaBackendResultTOTPSecretField,
		definitions.LuaBackendResultTOTPRecoveryField,
		definitions.LuaBAckendResultUniqueUserIDField,
		definitions.LuaBackendResultDisplayNameField,
		definitions.LuaBackendResultAttributes,
	)

	registerDynamicLoader(L, ctx, luaRequest)

	setupGlobals(luaRequest, L, logs)

	request := L.NewTable()

	luaCommand, nret = setLuaRequestParameters(luaRequest, request)

	err := executeAndHandleError(compiledScript, luaCommand, luaRequest, L, request, nret, logs)

	// Decide whether to replace VM on hard error/timeout
	if err != nil || luaCtx.Err() != nil {
		replaceVM = true
	}

	// Handle the specific return types
	if err == nil {
		handleReturnTypes(L, nret, luaRequest, logs)
	}
}

// setupGlobals initializes and registers a set of global Lua variables and functions in the provided Lua state.
func setupGlobals(luaRequest *bktype.LuaRequest, L *lua.LState, logs *lualib.CustomLogKeyValue) {
	globals := L.NewTable()

	globals.RawSet(lua.LString(definitions.LuaBackendResultOk), lua.LNumber(0))
	globals.RawSet(lua.LString(definitions.LuaBackendResultFail), lua.LNumber(1))

	globals.RawSetString(definitions.LuaFnAddCustomLog, L.NewFunction(lualib.AddCustomLog(logs)))
	globals.RawSetString(definitions.LuaFnSetStatusMessage, L.NewFunction(lualib.SetStatusMessage(&luaRequest.StatusMessage)))

	L.SetGlobal(definitions.LuaDefaultTable, globals)
}

// setLuaRequestParameters determines the Lua command and number of return values for a LuaRequest and modifies the request.
func setLuaRequestParameters(luaRequest *bktype.LuaRequest, request *lua.LTable) (luaCommand string, nret int) {
	switch luaRequest.Function {
	case definitions.LuaCommandPassDB:
		luaCommand = definitions.LuaFnBackendVerifyPassword
		nret = 2

		luaRequest.SetupRequest(request)
	case definitions.LuaCommandListAccounts:
		luaCommand = definitions.LuaFnBackendListAccounts
		nret = 2

		request.RawSet(lua.LString(definitions.LuaRequestDebug), lua.LBool(luaRequest.Debug))
		request.RawSetString(definitions.LuaRequestSession, lua.LString(luaRequest.Session))
	case definitions.LuaCommandAddMFAValue:
		luaCommand = definitions.LuaFnBackendAddTOTPSecret
		nret = 1

		request.RawSetString(definitions.LuaRequestTOTPSecret, lua.LString(luaRequest.TOTPSecret))
		request.RawSet(lua.LString(definitions.LuaRequestDebug), lua.LBool(luaRequest.Debug))
		request.RawSetString(definitions.LuaRequestSession, lua.LString(luaRequest.Session))
	}

	return luaCommand, nret
}

// executeAndHandleError executes a Lua script, handles errors, and logs details. It runs initialization, execution, and cleanup steps.
func executeAndHandleError(compiledScript *lua.FunctionProto, luaCommand string, luaRequest *bktype.LuaRequest, L *lua.LState, request *lua.LTable, nret int, logs *lualib.CustomLogKeyValue) (err error) {
	startTime := time.Now()
	defer func() {
		latency := time.Since(startTime)
		logs.Set(fmt.Sprintf("backend_execute_%s_latency", luaCommand), fmt.Sprintf("%v", latency))
	}()

	if err = lualib.PackagePath(L); err != nil {
		processError(err, luaRequest, logs)
	}

	if err = lualib.DoCompiledFile(L, compiledScript); err != nil {
		processError(err, luaRequest, logs)
	}

	// Check if the script has a "luaCommand" function
	commandFunc := L.GetGlobal(luaCommand)

	if commandFunc.Type() == lua.LTFunction {
		if err = L.CallByParam(lua.P{
			Fn:      L.GetGlobal(luaCommand),
			NRet:    nret,
			Protect: true,
		}, request); err != nil {
			processError(err, luaRequest, logs)
		}
	}

	return err
}

// handleReturnTypes processes the return values of a Lua script and sends results to the LuaReplyChan of LuaRequest.
// L represents the Lua state machine, nret specifies the number of return values, luaRequest holds request context.
// logs specifies the custom log key-value pairs. Validates the script output and dispatches appropriate Lua results.
// An error is sent if the Lua script fails or returns invalid data for specified commands.
func handleReturnTypes(L *lua.LState, nret int, luaRequest *bktype.LuaRequest, logs *lualib.CustomLogKeyValue) {
	startTime := time.Now()
	defer func() {
		latency := time.Since(startTime)
		logs.Set("process_backend_result_latency", fmt.Sprintf("%v", latency))
	}()

	ret := L.ToInt(-nret)
	if ret != 0 {
		luaRequest.LuaReplyChan <- &lualib.LuaBackendResult{
			Err:  errors.ErrBackendLua.WithDetail("Lua script finished with an error"),
			Logs: logs,
		}

		return
	}

	switch luaRequest.Function {
	case definitions.LuaCommandPassDB:
		userData := L.ToUserData(-1)

		if userData != nil {
			if luaBackendResult, assertOk := userData.Value.(*lualib.LuaBackendResult); assertOk {
				luaBackendResult.Logs = logs

				util.DebugModule(
					definitions.DbgLua,
					definitions.LogKeyGUID, luaRequest.Session,
					"result", fmt.Sprintf("%+v", luaBackendResult),
				)

				luaRequest.LuaReplyChan <- luaBackendResult
			} else {
				luaRequest.LuaReplyChan <- &lualib.LuaBackendResult{
					Err:  errors.ErrBackendLuaWrongUserData.WithDetail("Lua script returned a wrong user data object"),
					Logs: logs,
				}
			}
		} else {
			luaRequest.LuaReplyChan <- &lualib.LuaBackendResult{
				Err:  errors.ErrBackendLuaWrongUserData.WithDetail("Lua script returned nil user data"),
				Logs: logs,
			}
		}

	case definitions.LuaCommandListAccounts:
		// Check if L.ToTable(-1) returns a valid table
		attributes := make(map[any]any)

		table := L.ToTable(-1)
		if table != nil {
			result := convert.LuaValueToGo(table).([]any)
			for k, v := range result {
				attributes[k+1] = v
			}
		}

		luaRequest.LuaReplyChan <- &lualib.LuaBackendResult{
			Attributes: attributes,
			Logs:       logs,
		}

	default:
		luaRequest.LuaReplyChan <- &lualib.LuaBackendResult{
			Logs: logs,
		}
	}
}

// processError handles Lua backend errors by logging the error details and communicating the error and logs via a channel.
func processError(err error, luaRequest *bktype.LuaRequest, logs *lualib.CustomLogKeyValue) {
	level.Error(log.Logger).Log(
		definitions.LogKeyGUID, luaRequest.Session,
		"script", config.GetFile().GetLuaScriptPath(),
		definitions.LogKeyMsg, err,
	)

	luaRequest.LuaReplyChan <- &lualib.LuaBackendResult{
		Err:  err,
		Logs: logs,
	}
}
