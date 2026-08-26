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
	"crypto/sha256"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/errors"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/lualib/convert"
	"github.com/croessner/nauthilus/v3/server/lualib/luamod"
	"github.com/croessner/nauthilus/v3/server/lualib/luapool"
	"github.com/croessner/nauthilus/v3/server/lualib/luaseal"
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

type preparedLuaBackendProgram struct {
	prototype *lua.FunctionProto
	modules   *luaseal.Modules
	snapshot  *config.ArtifactSnapshot
	path      string
	digest    [sha256.Size]byte
}

var preparedLuaBackendPrograms sync.Map

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

	program, err := preparedLuaBackendScript(cfg, backendName, runtimeConfig.scriptPath, nil)
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
	startLuaBackendWorkers(ctx, cfg, logger, redisClient, backendName, runtimeConfig.numberOfWorkers, program, vmPool, &wg)

	go func() {
		wg.Wait()
		TrySignalDone(channel.GetLuaChannel().GetLookupEndChan(backendName))
	}()

	return
}

// PrepareLuaBackendScripts compiles every restart-bound backend before workers start.
func PrepareLuaBackendScripts(cfg config.File) error {
	modules, err := luaseal.CaptureConfigured(cfg)
	if err != nil {
		return err
	}

	return PrepareLuaBackendScriptsWithModules(cfg, modules)
}

// PrepareLuaBackendScriptsWithModules binds every restart-bound backend to one boot-owned module snapshot.
func PrepareLuaBackendScriptsWithModules(cfg config.File, modules *luaseal.Modules) error {
	if cfg == nil {
		return fmt.Errorf("lua backend configuration is nil")
	}

	if modules == nil {
		return fmt.Errorf("lua backend module snapshot is nil")
	}

	programs := make(map[string]string)
	if path := cfg.GetLuaScriptPath(); path != "" {
		programs[definitions.DefaultBackendName] = path
	}

	for name, optional := range cfg.GetLuaOptionalBackends() {
		if optional != nil && optional.BackendScriptPath != "" {
			programs[name] = optional.BackendScriptPath
		}
	}

	names := make([]string, 0, len(programs))
	for name := range programs {
		names = append(names, name)
	}

	sort.Strings(names)

	for _, name := range names {
		if _, err := preparedLuaBackendScript(cfg, name, programs[name], modules); err != nil {
			return fmt.Errorf("prepare Lua backend %q: %w", name, err)
		}
	}

	return nil
}

// preparedLuaBackendScript returns the prototype cached for one sealed source identity.
func preparedLuaBackendScript(
	cfg config.File,
	backendName string,
	scriptPath string,
	modules *luaseal.Modules,
) (*preparedLuaBackendProgram, error) {
	snapshot, err := config.ArtifactSnapshotFor(cfg)
	if err != nil {
		return nil, fmt.Errorf("load sealed Lua backend source %q: %w", scriptPath, err)
	}

	digest, err := snapshot.Digest(scriptPath)
	if err != nil {
		return nil, fmt.Errorf("load sealed Lua backend source %q: %w", scriptPath, err)
	}

	if cached, ok := preparedLuaBackendPrograms.Load(backendName); ok {
		program := cached.(*preparedLuaBackendProgram)
		if program.path == scriptPath && program.digest == digest && program.snapshot == snapshot {
			return program, nil
		}
	}

	if modules == nil {
		modules, err = luaseal.CaptureConfigured(cfg)
		if err != nil {
			return nil, err
		}
	}

	prototype, err := compileLuaBackendScript(cfg, scriptPath)
	if err != nil {
		return nil, err
	}

	program := &preparedLuaBackendProgram{
		prototype: prototype,
		modules:   modules,
		snapshot:  snapshot,
		path:      scriptPath,
		digest:    digest,
	}
	preparedLuaBackendPrograms.Store(backendName, program)

	return program, nil
}

// compileLuaBackendScript compiles the exact backend bytes sealed with the active config.
func compileLuaBackendScript(cfg config.File, scriptPath string) (*lua.FunctionProto, error) {
	snapshot, err := config.ArtifactSnapshotFor(cfg)
	if err != nil {
		return nil, fmt.Errorf("load sealed Lua backend source %q: %w", scriptPath, err)
	}

	source, err := snapshot.ReadFile(scriptPath)
	if err != nil {
		return nil, fmt.Errorf("load sealed Lua backend source %q: %w", scriptPath, err)
	}
	defer clear(source)

	return lualib.CompileLuaSource(scriptPath, source)
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
	program *preparedLuaBackendProgram,
	vmPool *vmpool.Pool,
	wg *sync.WaitGroup,
) {
	for i := 0; i < numberOfWorkers; i++ {
		wg.Go(func() {
			luaBackendWorkerLoop(ctx, cfg, logger, redisClient, backendName, program, vmPool)
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
	program *preparedLuaBackendProgram,
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

		handleLuaRequest(ctx, cfg, logger, redisClient, luaRequest, program, vmPool)
	}
}

// handleLuaRequest processes a Lua script execution request in the given context using the specified compiled script.
// It initializes a Lua state, sets up the environment, runs the script, and handles return values or errors.
// Parameters:
// - ctx: The context for the Lua execution, including cancellation and timeout.
// - luaRequest: The LuaRequest object containing details about the script execution request.
// - compiledScript: The precompiled Lua script to be executed.
func handleLuaRequest(ctx context.Context, cfg config.File, logger *slog.Logger, redisClient rediscli.Client, luaRequest *bktype.LuaRequest, program *preparedLuaBackendProgram, vmPool *vmpool.Pool) {
	startTime := time.Now()
	defer logLuaBackendLatency(logger, luaRequest.Session, startTime)

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

	if program == nil || program.modules == nil {
		leaseErr = fmt.Errorf("prepared Lua backend program is incomplete")
		processError(cfg, logger, leaseErr, luaRequest, logs)

		return
	}

	if leaseErr = luaseal.PrepareProcess(L, program.modules); leaseErr != nil {
		processError(cfg, logger, leaseErr, luaRequest, logs)

		return
	}
	luapool.PrepareRequestEnv(L)

	bindLuaRequestModules(ctx, luaCtx, cfg, logger, redisClient, L, luaRequest)
	setupGlobals(ctx, cfg, logger, luaRequest, L, logs)

	request := L.NewTable()
	luaCommand, nret := setLuaRequestParameters(cfg, L, luaRequest, request)

	err := executeAndHandleError(cfg, logger, program, luaCommand, luaRequest, L, request, nret, logs)
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

// logLuaBackendLatency records one completed backend request duration.
func logLuaBackendLatency(logger *slog.Logger, session string, startTime time.Time) {
	level.Info(logger).Log(
		definitions.LogKeyGUID, session,
		definitions.LogKeyMsg, "Lua backend handler latency",
		definitions.LogKeyLatency, util.FormatDurationMs(time.Since(startTime)),
	)
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

	modManager.BindAllDefault(luaRequest.HTTPClientContext, L, luaRequest.Context, luaRequest.Tolerate)

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
func executeAndHandleError(cfg config.File, logger *slog.Logger, program *preparedLuaBackendProgram, luaCommand string, luaRequest *bktype.LuaRequest, L *lua.LState, request *lua.LTable, nret int, logs *lualib.CustomLogKeyValue) (err error) {
	startTime := time.Now()
	defer func() {
		latency := time.Since(startTime)
		logs.Set(fmt.Sprintf("backend_execute_%s_latency", luaCommand), util.FormatDurationMs(latency))
	}()

	if program == nil || program.prototype == nil || program.modules == nil {
		err = fmt.Errorf("prepared Lua backend program is incomplete")
		processError(cfg, logger, err, luaRequest, logs)

		return err
	}

	if err = luaseal.InstallProcess(L, program.modules); err != nil {
		processError(cfg, logger, err, luaRequest, logs)

		return err
	}

	if err = lualib.DoCompiledFile(L, program.prototype); err != nil {
		processError(cfg, logger, err, luaRequest, logs)

		return err
	}

	if err = callLuaBackendCommand(L, luaCommand, request, nret); err != nil {
		processError(cfg, logger, err, luaRequest, logs)

		return err
	}

	return err
}

// callLuaBackendCommand resolves and invokes one request-scoped backend function.
func callLuaBackendCommand(L *lua.LState, luaCommand string, request *lua.LTable, nret int) error {
	commandFunc := luaBackendCommand(L, luaCommand)
	if commandFunc == nil || commandFunc.Type() != lua.LTFunction {
		return nil
	}

	return L.CallByParam(lua.P{
		Fn:      commandFunc,
		NRet:    nret,
		Protect: true,
	}, request)
}

// luaBackendCommand prefers the request environment and falls back to the process global.
func luaBackendCommand(L *lua.LState, luaCommand string) lua.LValue {
	if environment := L.GetGlobal("__NAUTH_REQ_ENV"); environment != nil && environment.Type() == lua.LTTable {
		if command := L.GetField(environment, luaCommand); command != nil && command != lua.LNil {
			return command
		}
	}

	return L.GetGlobal(luaCommand)
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
