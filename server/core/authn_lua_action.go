// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/lualib"
	"github.com/croessner/nauthilus/v4/server/lualib/luamod"
	"github.com/croessner/nauthilus/v4/server/lualib/luapool"
	"github.com/croessner/nauthilus/v4/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v4/server/lualib/vmpool"
	"github.com/croessner/nauthilus/v4/server/policy/decision/service"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"

	"github.com/gin-gonic/gin"
	lua "github.com/yuin/gopher-lua"
)

const (
	authnLuaActionFailureClass  = "authn_lua_action_failed"
	authnLuaActionSuccessResult = lua.LNumber(0)
)

type compiledAuthnLuaAction interface {
	OpenCompiledLuaAction() (string, *lua.FunctionProto, error)
	LuaPoolKey() string
	LuaPoolManager() *vmpool.Manager
	SealedLuaModules() *luaseal.Modules
}

type authnLuaActionInvocation struct {
	auth          *AuthState
	response      *gin.Context
	httpRequest   *http.Request
	request       lualib.CommonRequest
	requestCtx    *lualib.Context
	i18n          *lualib.I18NRuntime
	modules       *luaseal.Modules
	prototype     *lua.FunctionProto
	pools         *vmpool.Manager
	name          string
	poolKey       vmpool.PoolKey
	cleanupOnce   sync.Once
	allowResponse bool
}

type authnLuaPostActionWork struct {
	invocation *authnLuaActionInvocation
}

type openedAuthnLuaAction struct {
	modules   *luaseal.Modules
	prototype *lua.FunctionProto
	pools     *vmpool.Manager
	name      string
	poolKey   vmpool.PoolKey
}

// ExecuteAuthnLuaAction executes one exact generation-owned synchronous action in request-local state.
func (e *authnCandidateExecution) ExecuteAuthnLuaAction(
	ctx context.Context,
	program policyruntime.AuthnLuaActionProgram,
	execution policyruntime.EffectExecution,
) effectsupervisor.Result {
	invocation, err := e.newAuthnLuaActionInvocation(ctx, program, execution, false)
	if err != nil {
		return effectsupervisor.Failed(authnLuaActionFailureClass)
	}
	defer invocation.cleanup()

	return invocation.execute(ctx)
}

// PrepareAuthnLuaPostAction captures one exact action without retaining live response state.
func (e *authnCandidateExecution) PrepareAuthnLuaPostAction(
	ctx context.Context,
	program policyruntime.AuthnLuaActionProgram,
	execution policyruntime.EffectExecution,
) (effectsupervisor.Work, error) {
	invocation, err := e.newAuthnLuaActionInvocation(ctx, program, execution, true)
	if err != nil {
		return nil, err
	}

	return &authnLuaPostActionWork{invocation: invocation}, nil
}

// newAuthnLuaActionInvocation captures all mutable request inputs before execution ownership changes.
func (e *authnCandidateExecution) newAuthnLuaActionInvocation(
	ctx context.Context,
	program policyruntime.AuthnLuaActionProgram,
	execution policyruntime.EffectExecution,
	postAction bool,
) (*authnLuaActionInvocation, error) {
	if e == nil || e.auth == nil || e.ginCtx == nil || program == nil || program.ID() != execution.EffectID() {
		return nil, fmt.Errorf("authn Lua action owner is unavailable")
	}

	opened, err := openAuthnLuaAction(program)
	if err != nil {
		return nil, err
	}

	ownedRequest, requestCtx := e.captureAuthnLuaActionRequest(postAction)
	resolver, _ := service.CapturedMessageResolverFromContext(ctx)
	i18n := lualib.NewI18NRuntime(lualib.I18NRuntimeOptions{Resolver: resolver})
	invocation := &authnLuaActionInvocation{
		auth: e.auth, request: ownedRequest, requestCtx: requestCtx, i18n: i18n,
		modules: opened.modules, prototype: opened.prototype, name: opened.name,
		pools: opened.pools, poolKey: opened.poolKey, allowResponse: !postAction,
	}

	if e.ginCtx.Request != nil {
		invocation.httpRequest = e.ginCtx.Request.Clone(context.Background())
	}

	if !postAction {
		invocation.response = e.ginCtx
	}

	return invocation, nil
}

// openAuthnLuaAction validates and opens one exact generation-owned compiled action.
func openAuthnLuaAction(program policyruntime.AuthnLuaActionProgram) (openedAuthnLuaAction, error) {
	compiled, ok := program.(compiledAuthnLuaAction)
	if !ok {
		return openedAuthnLuaAction{}, fmt.Errorf("authn Lua action program is unavailable")
	}

	name, prototype, err := compiled.OpenCompiledLuaAction()
	if err != nil {
		return openedAuthnLuaAction{}, fmt.Errorf("open authn Lua action %q: %w", program.ID(), err)
	}

	opened := openedAuthnLuaAction{
		modules: compiled.SealedLuaModules(), prototype: prototype, name: name,
		pools: compiled.LuaPoolManager(), poolKey: vmpool.PoolKey(compiled.LuaPoolKey()),
	}
	if opened.name == "" || opened.prototype == nil {
		return openedAuthnLuaAction{}, fmt.Errorf("authn Lua action %q is incomplete", program.ID())
	}

	if opened.poolKey == "" || opened.pools == nil {
		return openedAuthnLuaAction{}, fmt.Errorf("authn Lua action pool is unavailable")
	}

	return opened, nil
}

// captureAuthnLuaActionRequest detaches request state before synchronous or post-action execution.
func (e *authnCandidateExecution) captureAuthnLuaActionRequest(
	postAction bool,
) (lualib.CommonRequest, *lualib.Context) {
	common := lualib.GetCommonRequest()
	e.auth.FillCommonRequest(common)
	e.applyAuthnLuaActionFlags(common)
	ownedRequest := common.CloneForPostAction()
	lualib.PutCommonRequest(common)

	requestCtx := e.auth.Runtime.Context
	if requestCtx == nil {
		requestCtx = lualib.NewContext()
	}

	if postAction {
		requestCtx = requestCtx.Clone()
	}

	return ownedRequest, requestCtx
}

// applyAuthnLuaActionFlags copies request-observed stage state into the Lua request.
func (e *authnCandidateExecution) applyAuthnLuaActionFlags(request *lualib.CommonRequest) {
	if e == nil || e.auth == nil || request == nil {
		return
	}

	flags := e.auth.AuthnRequestStageFlags()
	request.EnvironmentRejected = flags.EnvironmentRejected
	request.EnvironmentStageExpected = flags.EnvironmentStageExpected
	request.SubjectStageExpected = flags.SubjectStageExpected
}

// execute runs the captured prototype once in its exact generation-specific pool.
func (i *authnLuaActionInvocation) execute(ctx context.Context) (result effectsupervisor.Result) {
	if err := i.validate(); err != nil {
		return effectsupervisor.Failed(authnLuaActionFailureClass)
	}

	pool := i.pools.GetOrCreate(i.poolKey, vmpool.PoolOptions{
		MaxVMs: i.auth.Cfg().GetLuaActionNumberOfWorkers(), Config: i.auth.Cfg(),
	})

	lease, err := pool.AcquireLease(ctx)
	if err != nil {
		return effectsupervisor.Failed(authnLuaActionFailureClass)
	}

	var runErr error
	defer lease.ReleaseRecoveringOnError(&runErr)

	runErr = i.executeWithState(ctx, lease.State())
	if runErr != nil {
		return effectsupervisor.Failed(authnLuaActionFailureClass)
	}

	return effectsupervisor.Succeeded()
}

// validate rejects incomplete or response-retaining post-action captures.
func (i *authnLuaActionInvocation) validate() error {
	if i == nil || i.auth == nil || i.prototype == nil || i.pools == nil || i.poolKey == "" || i.name == "" || i.requestCtx == nil || i.i18n == nil {
		return fmt.Errorf("authn Lua action invocation is incomplete")
	}

	if !i.allowResponse && i.response != nil {
		return fmt.Errorf("authn Lua post-action retained response state")
	}

	return nil
}

// executeWithState binds captured request modules and calls the configured action entrypoint exactly once.
func (i *authnLuaActionInvocation) executeWithState(ctx context.Context, state *lua.LState) error {
	if state == nil {
		return fmt.Errorf("authn Lua action state is unavailable")
	}

	deadlineCtx, cancel := context.WithTimeout(ctx, i.auth.Cfg().GetServer().GetTimeouts().GetLuaScript())
	defer cancel()

	state.SetContext(deadlineCtx)

	profile := i.policyProfile()

	if err := luaseal.PreparePolicyProfile(state, i.modules, profile); err != nil {
		return err
	}

	luapool.PrepareRequestEnv(state)
	i.bindLuaActionModules(deadlineCtx, state)

	logs := new(lualib.CustomLogKeyValue)
	lualib.SetBuiltinTableForAction(
		state,
		lualib.NewLoggingManager(deadlineCtx, i.auth.Cfg(), i.auth.Logger(), logs).AddCustomLog,
	)

	request := state.NewTable()
	i.request.SetupRequest(state, i.auth.Cfg(), request)

	if err := luaseal.InstallPolicyProfile(state, i.modules, profile); err != nil {
		return err
	}

	if err := lualib.DoCompiledFile(state, i.prototype); err != nil {
		return err
	}

	return executeAuthnLuaActionCallback(state, request)
}

// policyProfile selects the sealed capability profile for sync or post-action execution.
func (i *authnLuaActionInvocation) policyProfile() luaseal.PolicyProfile {
	if i.allowResponse {
		return luaseal.PolicyProfileResponseAction
	}

	return luaseal.PolicyProfileAction
}

// bindLuaActionModules installs request-local host modules into one leased state.
func (i *authnLuaActionInvocation) bindLuaActionModules(ctx context.Context, state *lua.LState) {
	manager := luamod.NewModuleManager(ctx, i.auth.Cfg(), i.auth.Logger(), i.auth.Redis())
	manager.BindAllPolicyRequest(ctx, state, i.requestCtx, i.auth.deps.Tolerate)
	manager.BindI18NRuntime(state, i.i18n, lualib.I18NModeRequest)

	if i.httpRequest != nil {
		manager.BindHTTP(state, lualib.NewHTTPMetaFromRequest(i.httpRequest))
	}

	if i.allowResponse {
		manager.BindHTTPResponse(state, i.response)
	}
}

// executeAuthnLuaActionCallback calls and validates the configured action entrypoint exactly once.
func executeAuthnLuaActionCallback(state *lua.LState, request *lua.LTable) error {
	callback := authnLuaActionCallback(state)
	if callback.Type() != lua.LTFunction {
		return fmt.Errorf("authn Lua action callback is unavailable")
	}

	if err := state.CallByParam(lua.P{Fn: callback, NRet: 1, Protect: true}, request); err != nil {
		return err
	}

	value := state.Get(-1)
	state.Pop(1)

	result, ok := value.(lua.LNumber)
	if !ok || result != authnLuaActionSuccessResult {
		return fmt.Errorf("authn Lua action returned failure")
	}

	return nil
}

// authnLuaActionCallback resolves the action only from the current request environment or exact chunk.
func authnLuaActionCallback(state *lua.LState) lua.LValue {
	if requestEnvironment := state.GetGlobal("__NAUTH_REQ_ENV"); requestEnvironment.Type() == lua.LTTable {
		if callback := state.GetField(requestEnvironment, definitions.LuaFnCallAction); callback.Type() == lua.LTFunction {
			return callback
		}
	}

	return state.GetGlobal(definitions.LuaFnCallAction)
}

// cleanup removes secret-bearing captured inputs after sync execution or supervisor release.
func (i *authnLuaActionInvocation) cleanup() {
	if i == nil {
		return
	}

	i.cleanupOnce.Do(func() {
		i.request.Reset()
		i.prototype = nil
		i.requestCtx = nil
		i.httpRequest = nil
		i.response = nil
		i.auth = nil
	})
}

// Validate confirms the post-action capture owns no live response state.
func (w *authnLuaPostActionWork) Validate() error {
	if w == nil || w.invocation == nil {
		return fmt.Errorf("authn Lua post-action work is unavailable")
	}

	return w.invocation.validate()
}

// Execute runs one already accepted post-action with supervisor-owned cancellation.
func (w *authnLuaPostActionWork) Execute(ctx context.Context) effectsupervisor.Result {
	if err := w.Validate(); err != nil {
		return effectsupervisor.Failed(authnLuaActionFailureClass)
	}

	return w.invocation.execute(ctx)
}

// Cleanup releases secret-bearing post-action capture state exactly once.
func (w *authnLuaPostActionWork) Cleanup() {
	if w == nil || w.invocation == nil {
		return
	}

	w.invocation.cleanup()
	w.invocation = nil
}

var _ policyruntime.AuthnLuaActionHost = (*authnCandidateExecution)(nil)
var _ effectsupervisor.ExecutableWork = (*authnLuaPostActionWork)(nil)
