// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/lualib"
	"github.com/croessner/nauthilus/v4/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v4/server/lualib/vmpool"
	policy "github.com/croessner/nauthilus/v4/server/policy"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
	lua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/parse"
)

const (
	authnLuaEnvironmentPrefix = "lua_environment_"
	authnLuaSubjectPrefix     = "lua_subject_"
	maximumAuthnLuaSourceSize = 4 << 20
)

type preparedAuthnLuaSource struct {
	pools   *vmpool.Manager
	modules *luaseal.Modules
	source  []byte
	id      string
	kind    string
	name    string
	path    string
	poolKey string
}

// PrepareConfiguredAuthnLuaSources compiles only activated exact authn source owners off-side.
func PrepareConfiguredAuthnLuaSources(
	ctx context.Context,
	generation uint64,
	configured policyconfig.PolicyConfig,
	artifacts LuaArtifactReader,
	modules *luaseal.Modules,
	pools *vmpool.Manager,
) (map[string]policyruntime.AuthnHostProvider, error) {
	ctx = normalizeConfiguredPreparationContext(ctx)

	document, err := validateConfiguredAuthnLuaSourceInput(ctx, generation, configured, pools)
	if err != nil {
		return nil, err
	}

	authn, exists := document.Policy.Namespaces[policy.AuthnNamespace]
	if !exists {
		return map[string]policyruntime.AuthnHostProvider{}, nil
	}

	activated := activatedAuthnHostProviderIDs(document.Policy, authn)
	prepared := make(map[string]policyruntime.AuthnHostProvider, len(activated))

	for _, localName := range sortedConfiguredKeys(authn.Providers) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		provider := authn.Providers[localName]
		if !isConfiguredAuthnLuaSource(provider) {
			continue
		}

		id := CanonicalProviderID(policy.AuthnNamespace, localName, provider)
		if _, selected := activated[id]; !selected {
			continue
		}

		source, err := prepareAuthnLuaSource(generation, id, localName, provider, artifacts, modules, pools)
		if err != nil {
			return nil, configuredPreparationError(ctx, "configured authn Lua source was rejected")
		}

		prepared[id] = source
	}

	return prepared, nil
}

// validateConfiguredAuthnLuaSourceInput validates the candidate envelope before scripts are prepared.
func validateConfiguredAuthnLuaSourceInput(
	ctx context.Context,
	generation uint64,
	configured policyconfig.PolicyConfig,
	pools *vmpool.Manager,
) (policyconfig.Document, error) {
	if err := ctx.Err(); err != nil {
		return policyconfig.Document{}, err
	}

	if generation == 0 || pools == nil {
		return policyconfig.Document{}, fmt.Errorf("generation identity and Lua VM pool manager are required")
	}

	document := policyconfig.Normalize(policyconfig.Document{Policy: configured})
	if err := policyconfig.Validate(document); err != nil {
		return policyconfig.Document{}, configuredPreparationError(
			ctx,
			"authn Lua source configuration was rejected",
		)
	}

	return document, nil
}

// isConfiguredAuthnLuaSource recognizes the closed host-source kind set.
func isConfiguredAuthnLuaSource(provider policyconfig.ProviderConfig) bool {
	return provider.Kind == policyconfig.ProviderKindLuaEnvironment ||
		provider.Kind == policyconfig.ProviderKindLuaSubject
}

// activatedAuthnHostProviderIDs selects exact provider uses from activated authn plans.
func activatedAuthnHostProviderIDs(
	configured policyconfig.PolicyConfig,
	authn policyconfig.NamespaceConfig,
) map[string]struct{} {
	result := make(map[string]struct{})

	for _, target := range configured.Targets {
		if target.Namespace != policy.AuthnNamespace || target.DomainPlan == "" {
			continue
		}

		_, localPlan, qualified := strings.Cut(target.DomainPlan, "/")
		if !qualified {
			continue
		}

		plan, exists := authn.DomainPlans[localPlan]
		if !exists {
			continue
		}

		for _, checkpoint := range plan.Checkpoints {
			for _, instance := range checkpoint.Providers {
				if len(instance.Actions) == 0 || slices.Contains(instance.Actions, target.Action) {
					result[instance.Use] = struct{}{}
				}
			}
		}
	}

	return result
}

// prepareAuthnLuaSource compiles and validates one exact callback without publishing it.
func prepareAuthnLuaSource(
	generation uint64,
	id string,
	localName string,
	configured policyconfig.ProviderConfig,
	artifacts LuaArtifactReader,
	modules *luaseal.Modules,
	pools *vmpool.Manager,
) (*preparedAuthnLuaSource, error) {
	source, err := readCapturedLuaArtifact(artifacts, configured.ScriptPath, maximumAuthnLuaSourceSize)
	if err != nil {
		return nil, err
	}
	defer clear(source)

	prototype, err := compileCapturedAuthnLuaSource(configured.ScriptPath, source)
	if err != nil {
		return nil, err
	}

	callback := definitions.LuaFnCallSubject
	prefix := authnLuaSubjectPrefix

	if configured.Kind == policyconfig.ProviderKindLuaEnvironment {
		callback = definitions.LuaFnCallEnvironment
		prefix = authnLuaEnvironmentPrefix
	}

	profile := luaseal.PolicyProfileSubject
	if configured.Kind == policyconfig.ProviderKindLuaEnvironment {
		profile = luaseal.PolicyProfileEnvironment
	}

	if err = modules.ValidateSource(configured.ScriptPath, source, profile); err != nil {
		return nil, err
	}

	state, err := newAuthnLuaSourceValidationState(modules, profile)
	if err != nil {
		return nil, err
	}
	defer state.Close()

	if err = lualib.DoCompiledFile(state, prototype); err != nil {
		return nil, err
	}

	if state.GetGlobal(callback).Type() != lua.LTFunction {
		return nil, fmt.Errorf("required callback %s is unavailable", callback)
	}

	name := strings.TrimPrefix(localName, prefix)
	if name == "" {
		return nil, fmt.Errorf("authn Lua source name is unavailable")
	}

	return &preparedAuthnLuaSource{
		pools: pools, modules: modules, source: append([]byte(nil), source...),
		id: id, kind: configured.Kind, name: name, path: configured.ScriptPath,
		poolKey: fmt.Sprintf("policy-authn:%d:%s:%s", generation, configured.Kind, id),
	}, nil
}

// compileCapturedAuthnLuaSource returns one fresh prototype from candidate-owned immutable bytes.
func compileCapturedAuthnLuaSource(name string, source []byte) (*lua.FunctionProto, error) {
	chunk, err := parse.Parse(bytes.NewReader(source), name)
	if err != nil {
		return nil, err
	}

	return lua.Compile(chunk, name)
}

// newAuthnLuaSourceValidationState applies the request VM loader policy without host side effects.
func newAuthnLuaSourceValidationState(modules *luaseal.Modules, profile luaseal.PolicyProfile) (*lua.LState, error) {
	state := lua.NewState(lua.Options{SkipOpenLibs: true})
	for _, open := range []lua.LGFunction{lua.OpenBase, lua.OpenPackage, lua.OpenTable, lua.OpenString, lua.OpenMath} {
		open(state)
		state.Pop(1)
	}

	for _, name := range []string{lua.TabLibName, lua.StringLibName, lua.MathLibName} {
		moduleName := name
		state.PreloadModule(moduleName, func(current *lua.LState) int {
			current.Push(current.GetGlobal(moduleName))

			return 1
		})
	}

	for _, name := range authnLuaValidationModuleNames() {
		state.PreloadModule(name, authnLuaValidationModule)
	}

	state.PreloadModule(definitions.LuaModHTTPResponse, lualib.LoaderHTTPResponseValidation())
	state.PreloadModule("time", lualib.LoaderModPolicyTime())

	if err := luaseal.PreparePolicyProfile(state, modules, profile); err != nil {
		state.Close()

		return nil, err
	}

	if err := luaseal.InstallPolicyProfile(state, modules, profile); err != nil {
		state.Close()

		return nil, err
	}

	return state, nil
}

// authnLuaValidationModuleNames returns code-owned runtime modules with inert candidate bindings.
func authnLuaValidationModuleNames() []string {
	return []string{
		definitions.LuaModPassword,
		definitions.LuaModRedis,
		definitions.LuaModMisc,
		definitions.LuaModContext,
		definitions.LuaModBackend,
		definitions.LuaBackendResultTypeName,
		definitions.LuaModHTTPRequest,
		definitions.LuaModCBOR,
		definitions.LuaModPrometheus,
		definitions.LuaModBruteForce,
		definitions.LuaModCache,
		definitions.LuaModPsnet,
		definitions.LuaModOpenTelemetry,
		definitions.LuaModPolicy,
		definitions.LuaModI18N,
		"json",
		"glua_crypto",
	}
}

// authnLuaValidationModule exposes an inert table during off-side callback validation.
func authnLuaValidationModule(state *lua.LState) int {
	module := state.NewTable()
	meta := state.NewTable()
	meta.RawSetString("__index", state.NewFunction(func(current *lua.LState) int {
		current.Push(current.NewFunction(func(call *lua.LState) int {
			call.Push(lua.LNil)

			return 1
		}))

		return 1
	}))
	state.SetMetatable(module, meta)
	state.Push(module)

	return 1
}

// ID returns the exact catalog provider identity.
func (s *preparedAuthnLuaSource) ID() string {
	if s == nil {
		return ""
	}

	return s.id
}

// Kind returns the closed authn host source kind.
func (s *preparedAuthnLuaSource) Kind() string {
	if s == nil {
		return ""
	}

	return s.kind
}

// OpenCompiledLuaSource returns a fresh prototype compiled from candidate-owned immutable bytes.
func (s *preparedAuthnLuaSource) OpenCompiledLuaSource() (string, *lua.FunctionProto, error) {
	if s == nil {
		return "", nil, fmt.Errorf("authn Lua source is unavailable")
	}

	prototype, err := compileCapturedAuthnLuaSource(s.path, s.source)

	return s.name, prototype, err
}

// LuaPoolKey returns the generation-and-provider-specific VM pool identity.
func (s *preparedAuthnLuaSource) LuaPoolKey() string {
	if s == nil {
		return ""
	}

	return s.poolKey
}

// LuaPoolManager returns the generation-captured VM pool owner used for execution and retirement.
func (s *preparedAuthnLuaSource) LuaPoolManager() *vmpool.Manager {
	if s == nil {
		return nil
	}

	return s.pools
}

// SealedLuaModules returns the immutable external module snapshot owned by the generation.
func (s *preparedAuthnLuaSource) SealedLuaModules() *luaseal.Modules {
	if s == nil {
		return nil
	}

	return s.modules
}

// Dispose retires the exact idle pool after the owning generation lease drains.
func (s *preparedAuthnLuaSource) Dispose(_ context.Context) error {
	if s == nil || s.pools == nil || s.poolKey == "" {
		return nil
	}

	return s.pools.Delete(vmpool.PoolKey(s.poolKey))
}

// AuthnLuaSourceResources returns deterministic generation-retirement resources for prepared sources.
func AuthnLuaSourceResources(
	providers map[string]policyruntime.AuthnHostProvider,
) []policyruntime.CandidateResource {
	ids := make([]string, 0, len(providers))
	for id := range providers {
		ids = append(ids, id)
	}

	sort.Strings(ids)

	resources := make([]policyruntime.CandidateResource, 0, len(ids))
	for _, id := range ids {
		resource, ok := providers[id].(policyruntime.CandidateResource)
		if ok {
			resources = append(resources, resource)
		}
	}

	return resources
}

var _ policyruntime.AuthnHostProvider = (*preparedAuthnLuaSource)(nil)
var _ policyruntime.CandidateResource = (*preparedAuthnLuaSource)(nil)
