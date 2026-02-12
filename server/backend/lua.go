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
	"log/slog"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/lualib/luamod"
	"github.com/croessner/nauthilus/server/lualib/luapool"
	"github.com/croessner/nauthilus/server/lualib/vmpool"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/util"

	lua "github.com/yuin/gopher-lua"
)

// reference stateless LDAP loader to avoid unused warnings and document intent
var _ = LoaderLDAPStateless

// LoaderModLDAP initializes and loads the LDAP module into the Lua state with predefined functions for LDAP operations.
func LoaderModLDAP(ctx context.Context, cfg config.File) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnLDAPSearch:   LDAPSearchWithCtx(ctx),
			definitions.LuaFnLDAPModify:   LDAPModifyWithCtx(ctx),
			definitions.LuaFnLDAPEndpoint: LDAPEndpointWithCtx(cfg),
		})

		L.Push(mod)

		return 1
	}
}

// LoaderLDAPStateless returns an empty, stateless module table for nauthilus_ldap.
// It is intended to be preloaded once per VM (base environment). Per-request bindings will later
// clone this table and inject bound functions via WithCtx factories.
func LoaderLDAPStateless() lua.LGFunction {
	return func(L *lua.LState) int {
		L.Push(L.NewTable())

		return 1
	}
}

// LuaMainWorker processes Lua script requests in a loop until the context is canceled.
// It compiles the Lua script and handles requests using a dedicated goroutine for each.
// It now uses a priority queue instead of channels for better request handling.
func LuaMainWorker(ctx context.Context, cfg config.File, logger *slog.Logger, redisClient rediscli.Client, channel Channel, backendName string) (err error) {
	var (
		numberOfWorkers int
		scriptPath      string
	)

	errMsg := fmt.Sprintf("Lua backend script path not set for backend %s", backendName)

	if backendName == definitions.DefaultBackendName {
		numberOfWorkers = cfg.GetLuaNumberOfWorkers()

		scriptPath = cfg.GetLuaScriptPath()
		if scriptPath == "" {
			panic(errMsg)
		}
	} else {
		optionalBackends := cfg.GetLua().GetOptionalLuaBackends()

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

	util.DebugModuleWithCfg(
		ctx,
		cfg,
		logger,
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
		if c, ok := cfg.GetLua().GetConfig().(*config.LuaConf); ok {
			queueLen = c.GetQueueLength()
		}
	} else {
		optionalBackends := cfg.GetLua().GetOptionalLuaBackends()
		if optionalBackends != nil {
			if bc := optionalBackends[backendName]; bc != nil {
				queueLen = bc.GetQueueLength()
			}
		}
	}

	priorityqueue.LuaQueue.SetMaxQueueLength(backendName, queueLen)

	// Create per-backend VM pool with MaxVMs equal to number of workers
	vmPool := vmpool.GetManager().GetOrCreate(vmpool.PoolKey("backend:"+backendName), vmpool.PoolOptions{
		MaxVMs: numberOfWorkers,
		Config: cfg,
	})

	var wg sync.WaitGroup
	for i := 0; i < numberOfWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Get the next request from the priority queue.
				luaRequest := priorityqueue.LuaQueue.PopWithContext(ctx, backendName)
				if luaRequest == nil {
					return
				}

				handleLuaRequest(ctx, cfg, logger, redisClient, luaRequest, compiledScript, vmPool)
			}
		}()
	}

	go func() {
		wg.Wait()
		TrySignalDone(channel.GetLuaChannel().GetLookupEndChan(backendName))
	}()

	return
}

// handleLuaRequest processes a Lua script execution request in the given context using the specified compiled script.
// It initializes a Lua state, sets up the environment, runs the script, and handles return values or errors.
// Parameters:
// - ctx: The context for the Lua execution, including cancellation and timeout.
// - luaRequest: The LuaRequest object containing details about the script execution request.
// - compiledScript: The precompiled Lua script to be executed.
func handleLuaRequest(ctx context.Context, cfg config.File, logger *slog.Logger, redisClient rediscli.Client, luaRequest *bktype.LuaRequest, compiledScript *lua.FunctionProto, vmPool *vmpool.Pool) {
	var (
		nret       int
		luaCommand string
	)

	startTime := time.Now()
	defer func() {
		latency := time.Since(startTime)
		level.Info(logger).Log(
			definitions.LogKeyGUID, luaRequest.Session,
			definitions.LogKeyMsg, "Lua backend handler latency",
			definitions.LogKeyLatency, util.FormatDurationMs(latency),
		)
	}()

	logs := new(lualib.CustomLogKeyValue)
	luaCtx, luaCancel := context.WithTimeout(ctx, cfg.GetServer().GetTimeouts().GetLuaScript())

	defer luaCancel()

	L, acqErr := vmPool.Acquire(luaCtx)
	if acqErr != nil {
		level.Warn(logger).Log(definitions.LogKeyMsg, "lua_vm_acquire_failed", "err", acqErr)

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

	luapool.PrepareRequestEnv(L)

	// Bind per-request modules into reqEnv so that require() resolves to the bound versions.
	modManager := luamod.NewModuleManager(ctx, cfg, logger, redisClient)

	modManager.BindAllDefault(L, luaRequest.Context, luaRequest.HTTPClientContext, tolerate.GetTolerate())

	if luaRequest.HTTPClientRequest != nil {
		modManager.BindHTTP(L, lualib.NewHTTPMetaFromRequest(luaRequest.HTTPClientRequest))
	}

	modManager.BindLDAP(L, LoaderModLDAP(luaCtx, cfg))

	lualib.LoaderModBackendResult(ctx, cfg, logger)(L)

	if mod, ok := L.Get(-1).(*lua.LTable); ok {
		L.Pop(1)
		L.SetGlobal(definitions.LuaBackendResultTypeName, mod)
		luapool.BindModuleIntoReq(L, definitions.LuaBackendResultTypeName, mod)
	} else {
		L.Pop(1)
	}

	setupGlobals(ctx, cfg, logger, luaRequest, L, logs)

	request := L.NewTable()

	luaCommand, nret = setLuaRequestParameters(cfg, L, luaRequest, request)

	err := executeAndHandleError(cfg, logger, compiledScript, luaCommand, luaRequest, L, request, nret, logs)

	// Decide whether to replace VM on hard error/timeout
	if err != nil || luaCtx.Err() != nil {
		replaceVM = true
	}

	// Handle the specific return types
	if err == nil {
		handleReturnTypes(luaCtx, cfg, logger, L, nret, luaRequest, logs)
	}
}

// setupGlobals initializes and registers a set of global Lua variables and functions in the provided Lua state.
func setupGlobals(ctx context.Context, cfg config.File, logger *slog.Logger, luaRequest *bktype.LuaRequest, L *lua.LState, logs *lualib.CustomLogKeyValue) {
	globals := L.NewTable()

	globals.RawSet(lua.LString(definitions.LuaBackendResultOk), lua.LNumber(0))
	globals.RawSet(lua.LString(definitions.LuaBackendResultFail), lua.LNumber(1))

	globals.RawSetString(definitions.LuaFnAddCustomLog, L.NewFunction(lualib.LoaderModLogging(ctx, cfg, logger, logs)))
	globals.RawSetString(definitions.LuaFnSetStatusMessage, L.NewFunction(lualib.SetStatusMessage(&luaRequest.StatusMessage)))

	L.SetGlobal(definitions.LuaDefaultTable, globals)
}

// setLuaRequestParameters determines the Lua command and number of return values for a LuaRequest and modifies the request.
func setLuaRequestParameters(cfg config.File, L *lua.LState, luaRequest *bktype.LuaRequest, request *lua.LTable) (luaCommand string, nret int) {
	switch luaRequest.Command {
	case definitions.LuaCommandPassDB:
		luaCommand = definitions.LuaFnBackendVerifyPassword
		nret = 2

		luaRequest.SetupRequest(L, cfg, request)
	case definitions.LuaCommandListAccounts:
		luaCommand = definitions.LuaFnBackendListAccounts
		nret = 2

		luaRequest.SetupRequest(L, cfg, request)
	case definitions.LuaCommandAddMFAValue:
		luaCommand = definitions.LuaFnBackendAddTOTPSecret
		nret = 1

		luaRequest.SetupRequest(L, cfg, request)
	case definitions.LuaCommandDeleteMFAValue:
		luaCommand = definitions.LuaFnBackendDeleteTOTPSecret
		nret = 1

		luaRequest.SetupRequest(L, cfg, request)
	case definitions.LuaCommandGetWebAuthnCredentials:
		luaCommand = definitions.LuaFnBackendGetWebAuthnCredentials
		nret = 2

		luaRequest.SetupRequest(L, cfg, request)
	case definitions.LuaCommandSaveWebAuthnCredential:
		luaCommand = definitions.LuaFnBackendSaveWebAuthnCredential
		nret = 1

		luaRequest.SetupRequest(L, cfg, request)
	case definitions.LuaCommandDeleteWebAuthnCredential:
		luaCommand = definitions.LuaFnBackendDeleteWebAuthnCredential
		nret = 1

		luaRequest.SetupRequest(L, cfg, request)
	case definitions.LuaCommandAddTOTPRecoveryCodes:
		luaCommand = definitions.LuaFnBackendAddTOTPRecoveryCodes
		nret = 1

		luaRequest.SetupRequest(L, cfg, request)
	case definitions.LuaCommandDeleteTOTPRecoveryCodes:
		luaCommand = definitions.LuaFnBackendDeleteTOTPRecoveryCodes
		nret = 1

		luaRequest.SetupRequest(L, cfg, request)
	case definitions.LuaCommandUpdateWebAuthnCredential:
		luaCommand = definitions.LuaFnBackendUpdateWebAuthnCredential
		nret = 1

		luaRequest.SetupRequest(L, cfg, request)
	}

	return luaCommand, nret
}

// executeAndHandleError executes a Lua script, handles errors, and logs details. It runs initialization, execution, and cleanup steps.
func executeAndHandleError(cfg config.File, logger *slog.Logger, compiledScript *lua.FunctionProto, luaCommand string, luaRequest *bktype.LuaRequest, L *lua.LState, request *lua.LTable, nret int, logs *lualib.CustomLogKeyValue) (err error) {
	startTime := time.Now()
	defer func() {
		latency := time.Since(startTime)
		logs.Set(fmt.Sprintf("backend_execute_%s_latency", luaCommand), util.FormatDurationMs(latency))
	}()

	if err = lualib.PackagePath(L, cfg); err != nil {
		processError(cfg, logger, err, luaRequest, logs)
	}

	if err = lualib.DoCompiledFile(L, compiledScript); err != nil {
		processError(cfg, logger, err, luaRequest, logs)
	}

	var commandFunc = lua.LNil

	if v := L.GetGlobal("__NAUTH_REQ_ENV"); v != nil && v.Type() == lua.LTTable {
		if fn := L.GetField(v, luaCommand); fn != nil {
			commandFunc = fn
		}
	}

	if commandFunc == lua.LNil {
		commandFunc = L.GetGlobal(luaCommand)
	}

	if commandFunc != nil && commandFunc.Type() == lua.LTFunction {
		if err = L.CallByParam(lua.P{
			Fn:      commandFunc,
			NRet:    nret,
			Protect: true,
		}, request); err != nil {
			processError(cfg, logger, err, luaRequest, logs)
		}
	}

	return err
}

// handleReturnTypes processes the return values of a Lua script and sends results to the LuaReplyChan of LuaRequest.
// L represents the Lua state machine, nret specifies the number of return values, luaRequest holds request context.
// logs specifies the custom log key-value pairs. Validates the script output and dispatches appropriate Lua results.
// An error is sent if the Lua script fails or returns invalid data for specified commands.
func handleReturnTypes(ctx context.Context, cfg config.File, logger *slog.Logger, L *lua.LState, nret int, luaRequest *bktype.LuaRequest, logs *lualib.CustomLogKeyValue) {
	startTime := time.Now()
	defer func() {
		latency := time.Since(startTime)
		logs.Set("process_backend_result_latency", util.FormatDurationMs(latency))
	}()

	ret := L.ToInt(-nret)
	if ret != 0 {
		luaRequest.LuaReplyChan <- &lualib.LuaBackendResult{
			Err:  errors.ErrBackendLua.WithDetail("Lua script finished with an error"),
			Logs: logs,
		}

		return
	}

	switch luaRequest.Command {
	case definitions.LuaCommandPassDB:
		userData := L.ToUserData(-1)

		if userData != nil {
			if luaBackendResult, assertOk := userData.Value.(*lualib.LuaBackendResult); assertOk {
				luaBackendResult.Logs = logs

				util.DebugModule(
					ctx, cfg, logger,
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

	case definitions.LuaCommandGetWebAuthnCredentials:
		var credentials []string

		table := L.ToTable(-1)
		if table != nil {
			result := convert.LuaValueToGo(table).([]any)
			for _, v := range result {
				if str, ok := v.(string); ok {
					credentials = append(credentials, str)
				}
			}
		}

		luaRequest.LuaReplyChan <- &lualib.LuaBackendResult{
			WebAuthnCredentials: credentials,
			Logs:                logs,
		}

	default:
		luaRequest.LuaReplyChan <- &lualib.LuaBackendResult{
			Logs: logs,
		}
	}
}

// processError handles Lua backend errors by logging the error details and communicating the error and logs via a channel.
func processError(cfg config.File, logger *slog.Logger, err error, luaRequest *bktype.LuaRequest, logs *lualib.CustomLogKeyValue) {
	level.Error(logger).Log(
		definitions.LogKeyGUID, luaRequest.Session,
		"script", cfg.GetLuaScriptPath(),
		definitions.LogKeyMsg, "lua_backend_error",
		definitions.LogKeyError, err,
	)

	luaRequest.LuaReplyChan <- &lualib.LuaBackendResult{
		Err:  err,
		Logs: logs,
	}
}
