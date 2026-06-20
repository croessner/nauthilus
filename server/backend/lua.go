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

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/v3/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/errors"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/lualib/convert"
	"github.com/croessner/nauthilus/v3/server/lualib/luamod"
	"github.com/croessner/nauthilus/v3/server/lualib/luapool"
	"github.com/croessner/nauthilus/v3/server/lualib/vmpool"
	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/util"

	lua "github.com/yuin/gopher-lua"
)

// reference stateless LDAP loader to avoid unused warnings and document intent
var _ = LoaderLDAPStateless

type luaBackendRuntimeConfig struct {
	scriptPath      string
	numberOfWorkers int
	queueLength     int
}

type luaRequestCommandSpec struct {
	functionName string
	returns      int
}

var luaRequestCommandSpecs = map[definitions.LuaCommand]luaRequestCommandSpec{
	definitions.LuaCommandPassDB:                   {functionName: definitions.LuaFnBackendVerifyPassword, returns: 2},
	definitions.LuaCommandListAccounts:             {functionName: definitions.LuaFnBackendListAccounts, returns: 2},
	definitions.LuaCommandAddMFAValue:              {functionName: definitions.LuaFnBackendAddTOTPSecret, returns: 1},
	definitions.LuaCommandDeleteMFAValue:           {functionName: definitions.LuaFnBackendDeleteTOTPSecret, returns: 1},
	definitions.LuaCommandGetWebAuthnCredentials:   {functionName: definitions.LuaFnBackendGetWebAuthnCredentials, returns: 2},
	definitions.LuaCommandSaveWebAuthnCredential:   {functionName: definitions.LuaFnBackendSaveWebAuthnCredential, returns: 1},
	definitions.LuaCommandDeleteWebAuthnCredential: {functionName: definitions.LuaFnBackendDeleteWebAuthnCredential, returns: 1},
	definitions.LuaCommandAddTOTPRecoveryCodes:     {functionName: definitions.LuaFnBackendAddTOTPRecoveryCodes, returns: 1},
	definitions.LuaCommandDeleteTOTPRecoveryCodes:  {functionName: definitions.LuaFnBackendDeleteTOTPRecoveryCodes, returns: 1},
	definitions.LuaCommandUpdateWebAuthnCredential: {functionName: definitions.LuaFnBackendUpdateWebAuthnCredential, returns: 1},
}

// LoaderModLDAP initializes and loads the LDAP module into the Lua state with predefined functions for LDAP operations.
func LoaderModLDAP(ctx context.Context, cfg config.File) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnLDAPSearch:   LDAPSearchWithCtx(ctx),
			definitions.LuaFnLDAPModify:   LDAPModifyWithCtx(ctx),
			definitions.LuaFnLDAPEndpoint: LDAPEndpointWithCtx(cfg),
		})

		if ctx != nil {
			lualib.BindRequestRuntimeContext(ctx, L, mod)
		}

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
	runtimeConfig := resolveLuaBackendRuntimeConfig(cfg, backendName)

	compiledScript, err := lualib.CompileLua(runtimeConfig.scriptPath)
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
		"number_of_workers", runtimeConfig.numberOfWorkers,
		"script_path", runtimeConfig.scriptPath,
	)

	priorityqueue.LuaQueue.AddBackendName(backendName)
	priorityqueue.LuaQueue.SetMaxQueueLength(backendName, runtimeConfig.queueLength)

	vmPool := vmpool.GetManager().GetOrCreate(vmpool.PoolKey("backend:"+backendName), vmpool.PoolOptions{
		MaxVMs: runtimeConfig.numberOfWorkers,
		Config: cfg,
	})

	var wg sync.WaitGroup
	startLuaBackendWorkers(ctx, cfg, logger, redisClient, backendName, runtimeConfig.numberOfWorkers, compiledScript, vmPool, &wg)

	go func() {
		wg.Wait()
		TrySignalDone(channel.GetLuaChannel().GetLookupEndChan(backendName))
	}()

	return
}

// resolveLuaBackendRuntimeConfig resolves worker, script, and queue settings for one Lua backend.
func resolveLuaBackendRuntimeConfig(cfg config.File, backendName string) luaBackendRuntimeConfig {
	if backendName == definitions.DefaultBackendName {
		return defaultLuaBackendRuntimeConfig(cfg, backendName)
	}

	return optionalLuaBackendRuntimeConfig(cfg, backendName)
}

// defaultLuaBackendRuntimeConfig resolves the default Lua backend settings.
func defaultLuaBackendRuntimeConfig(cfg config.File, backendName string) luaBackendRuntimeConfig {
	scriptPath := cfg.GetLuaScriptPath()
	if scriptPath == "" {
		panic(luaBackendScriptPathError(backendName))
	}

	queueLength := 0
	if c, ok := cfg.GetLua().GetConfig().(*config.LuaConf); ok {
		queueLength = c.GetQueueLength()
	}

	return luaBackendRuntimeConfig{
		numberOfWorkers: cfg.GetLuaNumberOfWorkers(),
		scriptPath:      scriptPath,
		queueLength:     queueLength,
	}
}

// optionalLuaBackendRuntimeConfig resolves a named optional Lua backend.
func optionalLuaBackendRuntimeConfig(cfg config.File, backendName string) luaBackendRuntimeConfig {
	optionalBackends := cfg.GetLua().GetOptionalLuaBackends()
	if optionalBackends == nil || optionalBackends[backendName] == nil {
		panic(luaBackendScriptPathError(backendName))
	}

	backendConf := optionalBackends[backendName]
	if backendConf.BackendScriptPath == "" {
		panic(luaBackendScriptPathError(backendName))
	}

	return luaBackendRuntimeConfig{
		numberOfWorkers: backendConf.GetNumberOfWorkers(),
		scriptPath:      backendConf.BackendScriptPath,
		queueLength:     backendConf.GetQueueLength(),
	}
}

// luaBackendScriptPathError returns the existing panic message for missing backend scripts.
func luaBackendScriptPathError(backendName string) string {
	return fmt.Sprintf("Lua backend script path not set for backend %s", backendName)
}

// startLuaBackendWorkers starts worker goroutines for one Lua backend.
func startLuaBackendWorkers(
	ctx context.Context,
	cfg config.File,
	logger *slog.Logger,
	redisClient rediscli.Client,
	backendName string,
	numberOfWorkers int,
	compiledScript *lua.FunctionProto,
	vmPool *vmpool.Pool,
	wg *sync.WaitGroup,
) {
	for i := 0; i < numberOfWorkers; i++ {
		wg.Go(func() {
			luaBackendWorkerLoop(ctx, cfg, logger, redisClient, backendName, compiledScript, vmPool)
		})
	}
}

// luaBackendWorkerLoop consumes backend requests until the context or queue is closed.
func luaBackendWorkerLoop(
	ctx context.Context,
	cfg config.File,
	logger *slog.Logger,
	redisClient rediscli.Client,
	backendName string,
	compiledScript *lua.FunctionProto,
	vmPool *vmpool.Pool,
) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		luaRequest := priorityqueue.LuaQueue.PopWithContext(ctx, backendName)
		if luaRequest == nil {
			return
		}

		handleLuaRequest(ctx, cfg, logger, redisClient, luaRequest, compiledScript, vmPool)
	}
}

// handleLuaRequest processes a Lua script execution request in the given context using the specified compiled script.
// It initializes a Lua state, sets up the environment, runs the script, and handles return values or errors.
// Parameters:
// - ctx: The context for the Lua execution, including cancellation and timeout.
// - luaRequest: The LuaRequest object containing details about the script execution request.
// - compiledScript: The precompiled Lua script to be executed.
func handleLuaRequest(ctx context.Context, cfg config.File, logger *slog.Logger, redisClient rediscli.Client, luaRequest *bktype.LuaRequest, compiledScript *lua.FunctionProto, vmPool *vmpool.Pool) {
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

	lease, acqErr := vmPool.AcquireLease(luaCtx)
	if acqErr != nil {
		level.Warn(logger).Log(definitions.LogKeyMsg, "lua_vm_acquire_failed", "err", acqErr)

		return
	}

	L := lease.State()

	var leaseErr error

	defer lease.ReleaseRecoveringOnError(&leaseErr)

	L.SetContext(luaCtx)
	luapool.PrepareRequestEnv(L)

	bindLuaRequestModules(ctx, luaCtx, cfg, logger, redisClient, L, luaRequest)
	setupGlobals(ctx, cfg, logger, luaRequest, L, logs)

	request := L.NewTable()
	luaCommand, nret := setLuaRequestParameters(cfg, L, luaRequest, request)

	err := executeAndHandleError(cfg, logger, compiledScript, luaCommand, luaRequest, L, request, nret, logs)
	if err != nil {
		leaseErr = err
	}

	if luaCtx.Err() != nil {
		leaseErr = luaCtx.Err()
	}

	// Handle the specific return types
	if err == nil {
		handleReturnTypes(luaCtx, cfg, logger, L, nret, luaRequest, logs)
	}
}

// bindLuaRequestModules binds request-scoped modules into the Lua request environment.
func bindLuaRequestModules(
	ctx context.Context,
	luaCtx context.Context,
	cfg config.File,
	logger *slog.Logger,
	redisClient rediscli.Client,
	L *lua.LState,
	luaRequest *bktype.LuaRequest,
) {
	modManager := luamod.NewModuleManager(ctx, cfg, logger, redisClient)

	modManager.BindAllDefault(luaRequest.HTTPClientContext, L, luaRequest.Context, tolerate.GetTolerate())

	if luaRequest.HTTPClientRequest != nil {
		modManager.BindHTTP(L, lualib.NewHTTPMetaFromRequest(luaRequest.HTTPClientRequest))
	}

	modManager.BindLDAP(L, LoaderModLDAP(luaCtx, cfg))
	modManager.BindModule(L, definitions.LuaModPolicy, lualib.LoaderModPolicy(luaRequest.PolicyContext, policy.StageAuthBackend))
	bindBackendResultModule(ctx, cfg, logger, L)
}

// bindBackendResultModule exposes backend-result userdata helpers in globals and request env.
func bindBackendResultModule(ctx context.Context, cfg config.File, logger *slog.Logger, L *lua.LState) {
	lualib.LoaderModBackendResult(ctx, cfg, logger)(L)

	if mod, ok := L.Get(-1).(*lua.LTable); ok {
		L.Pop(1)
		L.SetGlobal(definitions.LuaBackendResultTypeName, mod)
		luapool.BindModuleIntoReq(L, definitions.LuaBackendResultTypeName, mod)

		return
	}

	L.Pop(1)
}

// setupGlobals initializes and registers a set of global Lua variables and functions in the provided Lua state.
func setupGlobals(ctx context.Context, cfg config.File, logger *slog.Logger, luaRequest *bktype.LuaRequest, L *lua.LState, logs *lualib.CustomLogKeyValue) {
	lualib.SetBuiltinTableForBackend(
		L,
		lualib.LoaderModLogging(ctx, cfg, logger, logs),
		&luaRequest.StatusMessage,
	)
}

// setLuaRequestParameters determines the Lua command and number of return values for a LuaRequest and modifies the request.
func setLuaRequestParameters(cfg config.File, L *lua.LState, luaRequest *bktype.LuaRequest, request *lua.LTable) (luaCommand string, nret int) {
	spec, ok := luaRequestCommandSpecs[luaRequest.Command]
	if !ok {
		return "", 0
	}

	luaRequest.SetupRequest(L, cfg, request)

	return spec.functionName, spec.returns
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

		return err
	}

	if err = lualib.DoCompiledFile(L, compiledScript); err != nil {
		processError(cfg, logger, err, luaRequest, logs)

		return err
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

			return err
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
		handlePassDBReturn(ctx, cfg, logger, L, luaRequest, logs)
	case definitions.LuaCommandListAccounts:
		handleListAccountsReturn(L, luaRequest, logs)
	case definitions.LuaCommandGetWebAuthnCredentials:
		handleWebAuthnCredentialsReturn(L, luaRequest, logs)
	default:
		luaRequest.LuaReplyChan <- &lualib.LuaBackendResult{
			Logs: logs,
		}
	}
}

// handlePassDBReturn validates and forwards LuaBackendResult userdata.
func handlePassDBReturn(ctx context.Context, cfg config.File, logger *slog.Logger, L *lua.LState, luaRequest *bktype.LuaRequest, logs *lualib.CustomLogKeyValue) {
	userData := L.ToUserData(-1)
	if userData == nil {
		sendLuaBackendUserDataError(luaRequest, logs, "Lua script returned nil user data")

		return
	}

	luaBackendResult, ok := userData.Value.(*lualib.LuaBackendResult)
	if !ok {
		sendLuaBackendUserDataError(luaRequest, logs, "Lua script returned a wrong user data object")

		return
	}

	luaBackendResult.Logs = logs

	util.DebugModule(
		ctx, cfg, logger,
		definitions.DbgLua,
		definitions.LogKeyGUID, luaRequest.Session,
		"result", fmt.Sprintf("%+v", luaBackendResult),
	)

	luaRequest.LuaReplyChan <- luaBackendResult
}

// sendLuaBackendUserDataError sends a typed userdata validation error.
func sendLuaBackendUserDataError(luaRequest *bktype.LuaRequest, logs *lualib.CustomLogKeyValue, detail string) {
	luaRequest.LuaReplyChan <- &lualib.LuaBackendResult{
		Err:  errors.ErrBackendLuaWrongUserData.WithDetail(detail),
		Logs: logs,
	}
}

// handleListAccountsReturn converts a Lua array table into backend account attributes.
func handleListAccountsReturn(L *lua.LState, luaRequest *bktype.LuaRequest, logs *lualib.CustomLogKeyValue) {
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
}

// handleWebAuthnCredentialsReturn converts a Lua array table into credential IDs.
func handleWebAuthnCredentialsReturn(L *lua.LState, luaRequest *bktype.LuaRequest, logs *lualib.CustomLogKeyValue) {
	luaRequest.LuaReplyChan <- &lualib.LuaBackendResult{
		WebAuthnCredentials: luaStringTableToSlice(L.ToTable(-1)),
		Logs:                logs,
	}
}

// luaStringTableToSlice converts a Lua array table to a string slice.
func luaStringTableToSlice(table *lua.LTable) []string {
	var values []string

	if table == nil {
		return values
	}

	result := convert.LuaValueToGo(table).([]any)
	for _, value := range result {
		if str, ok := value.(string); ok {
			values = append(values, str)
		}
	}

	return values
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
