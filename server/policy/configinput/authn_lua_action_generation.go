// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"context"
	"fmt"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/lualib"
	"github.com/croessner/nauthilus/v4/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v4/server/lualib/vmpool"
	policy "github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"

	lua "github.com/yuin/gopher-lua"
)

const (
	authnLuaActionSyncProvider = registry.AuthnLuaActionProviderID
	authnLuaActionPostProvider = registry.AuthnPostActionProviderID
)

// ConfiguredAuthnLuaActionInput carries one exact candidate action configuration.
type ConfiguredAuthnLuaActionInput struct {
	PostActionAcceptance effectsupervisor.Acceptor
	Artifacts            LuaArtifactReader
	Modules              *luaseal.Modules
	Pools                *vmpool.Manager
	Policy               policyconfig.PolicyConfig
	Generation           uint64
}

type preparedAuthnLuaAction struct {
	pools      *vmpool.Manager
	modules    *luaseal.Modules
	source     []byte
	id         string
	name       string
	path       string
	poolKey    string
	generation uint64
}

type configuredAuthnLuaSyncDispatcher struct {
	actions map[string]*preparedAuthnLuaAction
}

type configuredAuthnLuaPostDispatcher struct {
	actions map[string]*preparedAuthnLuaAction
}

// PrepareConfiguredAuthnLuaActions compiles every authored authn Lua action before candidate publication.
func PrepareConfiguredAuthnLuaActions(
	ctx context.Context,
	input ConfiguredAuthnLuaActionInput,
) (policyruntime.ExtensionPreparation, error) {
	ctx = normalizeConfiguredPreparationContext(ctx)

	document, err := validateConfiguredAuthnLuaActionInput(ctx, input)
	if err != nil {
		return policyruntime.ExtensionPreparation{}, err
	}

	return prepareConfiguredAuthnLuaActionBindings(ctx, input, document.Policy.Namespaces[policy.AuthnNamespace])
}

// validateConfiguredAuthnLuaActionInput validates the complete candidate envelope before reading scripts.
func validateConfiguredAuthnLuaActionInput(
	ctx context.Context,
	input ConfiguredAuthnLuaActionInput,
) (policyconfig.Document, error) {
	if err := ctx.Err(); err != nil {
		return policyconfig.Document{}, err
	}

	if input.Generation == 0 || input.Pools == nil || nilConfiguredPreparationDependency(input.PostActionAcceptance) {
		return policyconfig.Document{}, invalidGenerationRegistration(
			"authn Lua action generation or acceptance is unavailable",
		)
	}

	document := policyconfig.Normalize(policyconfig.Document{Policy: input.Policy})
	if err := policyconfig.Validate(document); err != nil {
		return policyconfig.Document{}, configuredPreparationError(
			ctx,
			"authn Lua action configuration was rejected",
		)
	}

	return document, nil
}

// prepareConfiguredAuthnLuaActionBindings compiles and groups exact action owners into one binding set.
func prepareConfiguredAuthnLuaActionBindings(
	ctx context.Context,
	input ConfiguredAuthnLuaActionInput,
	authn policyconfig.NamespaceConfig,
) (policyruntime.ExtensionPreparation, error) {
	syncActions := make(map[string]*preparedAuthnLuaAction)
	postActions := make(map[string]*preparedAuthnLuaAction)
	resources := make([]policyruntime.CandidateResource, 0)

	for _, name := range sortedConfiguredKeys(authn.Effects) {
		configured := authn.Effects[name]
		if configured.Kind != effectKindLuaAction {
			continue
		}

		action, err := prepareConfiguredAuthnLuaAction(
			input.Generation, name, configured, input.Artifacts, input.Modules, input.Pools,
		)
		if err != nil {
			return policyruntime.ExtensionPreparation{Resources: resources}, configuredPreparationError(
				ctx,
				"configured authn Lua action was rejected",
			)
		}

		resources = append(resources, action)
		if err = addPreparedAuthnLuaAction(syncActions, postActions, configured, action); err != nil {
			return policyruntime.ExtensionPreparation{Resources: resources}, err
		}
	}

	bindings, err := newConfiguredAuthnLuaActionBindingSet(input.PostActionAcceptance, syncActions, postActions)
	if err != nil {
		return policyruntime.ExtensionPreparation{Resources: resources}, err
	}

	return policyruntime.ExtensionPreparation{Bindings: bindings, Resources: resources}, nil
}

// addPreparedAuthnLuaAction assigns one exact action to its closed execution class.
func addPreparedAuthnLuaAction(
	syncActions map[string]*preparedAuthnLuaAction,
	postActions map[string]*preparedAuthnLuaAction,
	configured policyconfig.EffectConfig,
	action *preparedAuthnLuaAction,
) error {
	switch registry.ExecutionClass(configured.Execution) {
	case registry.ExecutionHostSync:
		syncActions[action.ID()] = action
	case registry.ExecutionHostPostAction:
		postActions[action.ID()] = action
	default:
		return invalidGenerationRegistration("configured authn Lua action execution is invalid")
	}

	return nil
}

// newConfiguredAuthnLuaActionBindingSet publishes only non-empty exact action dispatchers.
func newConfiguredAuthnLuaActionBindingSet(
	acceptance effectsupervisor.Acceptor,
	syncActions map[string]*preparedAuthnLuaAction,
	postActions map[string]*preparedAuthnLuaAction,
) (*policyruntime.BindingSet, error) {
	syncBindings := make(map[string]policyruntime.SyncEffectProvider)
	if len(syncActions) > 0 {
		syncBindings[authnLuaActionSyncProvider] = configuredAuthnLuaSyncDispatcher{actions: syncActions}
	}

	postBindings := make(map[string]policyruntime.PostActionProvider)
	if len(postActions) > 0 {
		postBindings[authnLuaActionPostProvider] = configuredAuthnLuaPostDispatcher{actions: postActions}
	}

	return policyruntime.NewBindingSet(policyruntime.BindingSetInput{
		SyncEffects: syncBindings, PostActions: postBindings, PostActionAcceptance: acceptance,
	})
}

// prepareConfiguredAuthnLuaAction captures bytes and validates the exact callback and return vocabulary.
func prepareConfiguredAuthnLuaAction(
	generation uint64,
	name string,
	configured policyconfig.EffectConfig,
	artifacts LuaArtifactReader,
	modules *luaseal.Modules,
	pools *vmpool.Manager,
) (*preparedAuthnLuaAction, error) {
	source, err := readCapturedLuaArtifact(artifacts, configured.ScriptPath, maximumAuthnLuaSourceSize)
	if err != nil {
		return nil, fmt.Errorf("read configured action: %w", err)
	}
	defer clear(source)

	prototype, err := compileCapturedAuthnLuaSource(configured.ScriptPath, source)
	if err != nil {
		return nil, err
	}

	if err = validateConfiguredAuthnLuaActionSource(configured, source, prototype, modules); err != nil {
		return nil, err
	}

	id := policy.AuthnNamespace + "/" + name

	return &preparedAuthnLuaAction{
		pools: pools, modules: modules, source: append([]byte(nil), source...),
		id: id, name: name, path: configured.ScriptPath,
		poolKey:    fmt.Sprintf("policy-authn:%d:lua_action:%s", generation, id),
		generation: generation,
	}, nil
}

// validateConfiguredAuthnLuaActionSource executes the callback once in its exact sealed capability profile.
func validateConfiguredAuthnLuaActionSource(
	configured policyconfig.EffectConfig,
	source []byte,
	prototype *lua.FunctionProto,
	modules *luaseal.Modules,
) error {
	profile := luaseal.PolicyProfileResponseAction
	if configured.Execution == string(registry.ExecutionHostPostAction) {
		profile = luaseal.PolicyProfileAction
	}

	if err := modules.ValidateSource(configured.ScriptPath, source, profile); err != nil {
		return err
	}

	state, err := newAuthnLuaSourceValidationState(modules, profile)
	if err != nil {
		return err
	}
	defer state.Close()

	lualib.SetBuiltinTableForAction(state, func(*lua.LState) int { return 0 })

	if err = lualib.DoCompiledFile(state, prototype); err != nil {
		return err
	}

	callback := state.GetGlobal(definitions.LuaFnCallAction)
	if callback.Type() != lua.LTFunction {
		return fmt.Errorf("required callback %s is unavailable", definitions.LuaFnCallAction)
	}

	if err = state.CallByParam(lua.P{Fn: callback, NRet: 1, Protect: true}, state.NewTable()); err != nil {
		return err
	}

	result := state.Get(-1)
	state.Pop(1)

	number, ok := result.(lua.LNumber)
	if !ok || (number != 0 && number != 1) {
		return fmt.Errorf("configured action returned an unsupported result")
	}

	return nil
}

// ID returns the exact configured effect identity.
func (a *preparedAuthnLuaAction) ID() string {
	if a == nil {
		return ""
	}

	return a.id
}

// OpenCompiledLuaAction returns one fresh prototype from candidate-owned bytes.
func (a *preparedAuthnLuaAction) OpenCompiledLuaAction() (string, *lua.FunctionProto, error) {
	if a == nil {
		return "", nil, fmt.Errorf("configured authn Lua action is unavailable")
	}

	prototype, err := compileCapturedAuthnLuaSource(a.path, a.source)

	return a.name, prototype, err
}

// LuaPoolKey returns the exact generation-specific action VM pool identity.
func (a *preparedAuthnLuaAction) LuaPoolKey() string {
	if a == nil {
		return ""
	}

	return a.poolKey
}

// LuaPoolManager returns the generation-captured VM pool owner used for execution and retirement.
func (a *preparedAuthnLuaAction) LuaPoolManager() *vmpool.Manager {
	if a == nil {
		return nil
	}

	return a.pools
}

// SealedLuaModules returns the immutable external module snapshot owned by the generation.
func (a *preparedAuthnLuaAction) SealedLuaModules() *luaseal.Modules {
	if a == nil {
		return nil
	}

	return a.modules
}

// Dispose retires one exact action pool after generation leases drain.
func (a *preparedAuthnLuaAction) Dispose(_ context.Context) error {
	if a == nil || a.pools == nil || a.poolKey == "" {
		return nil
	}

	return a.pools.Delete(vmpool.PoolKey(a.poolKey))
}

// Execute selects only the exact configured action owned by this generation.
func (d configuredAuthnLuaSyncDispatcher) Execute(
	ctx context.Context,
	execution policyruntime.EffectExecution,
) effectsupervisor.Result {
	action, exists := d.actions[execution.EffectID()]
	if !exists {
		return effectsupervisor.Failed("authn_lua_action_unavailable")
	}

	if execution.Provider() != authnLuaActionSyncProvider || execution.Generation() != action.generation {
		return effectsupervisor.Failed("authn_lua_action_mismatch")
	}

	host, ok := policyruntime.AuthnLuaActionHostFromContext(ctx)
	if !ok {
		return effectsupervisor.Failed("authn_lua_action_host_unavailable")
	}

	return host.ExecuteAuthnLuaAction(ctx, action, execution)
}

// Prepare captures only the exact configured post-action owned by this generation.
func (d configuredAuthnLuaPostDispatcher) Prepare(
	ctx context.Context,
	execution policyruntime.EffectExecution,
) (effectsupervisor.Work, error) {
	action, exists := d.actions[execution.EffectID()]
	if !exists {
		return nil, fmt.Errorf("authn Lua post action is unavailable")
	}

	if execution.Provider() != authnLuaActionPostProvider || execution.Generation() != action.generation {
		return nil, fmt.Errorf("authn Lua post action binding mismatch")
	}

	host, ok := policyruntime.AuthnLuaActionHostFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("authn Lua post-action host is unavailable")
	}

	return host.PrepareAuthnLuaPostAction(ctx, action, execution)
}

var _ policyruntime.AuthnLuaActionProgram = (*preparedAuthnLuaAction)(nil)
var _ policyruntime.CandidateResource = (*preparedAuthnLuaAction)(nil)
var _ policyruntime.SyncEffectProvider = configuredAuthnLuaSyncDispatcher{}
var _ policyruntime.PostActionProvider = configuredAuthnLuaPostDispatcher{}
