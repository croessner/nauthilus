// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v3/server/lualib/vmpool"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
	lua "github.com/yuin/gopher-lua"
)

const configuredAuthnLuaSourcesFixture = `policy:
  namespaces:
    authn:
      providers:
        lua_environment_risk:
          kind: lua_environment
          script_path: environment.lua
          targets: [{action: authenticate}]
          executions: [host_sync]
        lua_subject_risk:
          kind: lua_subject
          script_path: subject.lua
          targets: [{action: authenticate}]
          executions: [host_sync]
      domain_plans:
        configured:
          checkpoints:
            pre_auth:
              providers:
                - {name: environment_risk, use: authn/lua_environment_risk}
            subject_analysis:
              providers:
                - {name: subject_risk, use: authn/lua_subject_risk}
            auth_decision: {providers: []}
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/configured
`

// TestPrepareConfiguredAuthnLuaSourcesBuildsExactCompiledOwners proves the hard-cut source binding.
func TestPrepareConfiguredAuthnLuaSourcesBuildsExactCompiledOwners(t *testing.T) {
	configured := configuredAuthnLuaSourcePolicy(t)

	artifacts := capturePolicyLuaTestArtifacts(t, configured)
	mutateConfiguredAuthnLuaSources(t, configured, "function broken(")

	prepared, err := PrepareConfiguredAuthnLuaSources(t.Context(), 17, configured, artifacts, nil, vmpool.NewManager())
	if err != nil {
		t.Fatalf("PrepareConfiguredAuthnLuaSources() error = %v", err)
	}

	if len(prepared) != 2 {
		t.Fatalf("prepared authn Lua sources = %d, want two", len(prepared))
	}

	assertPreparedAuthnLuaSourceOwners(t, prepared)

	bindings, err := policyruntime.NewBindingSet(policyruntime.BindingSetInput{
		AuthnHostProviders:   prepared,
		PostActionAcceptance: testAcceptanceCapability{},
	})
	if err != nil {
		t.Fatalf("NewBindingSet() error = %v", err)
	}

	if _, found := bindings.AuthnHostProvider("authn/lua_environment_risk"); !found {
		t.Fatal("binding set lost generation-owned Lua environment provider")
	}
}

// mutateConfiguredAuthnLuaSources replaces every live source after candidate capture.
func mutateConfiguredAuthnLuaSources(t *testing.T, configured policyconfig.PolicyConfig, source string) {
	t.Helper()

	for _, provider := range configured.Namespaces["authn"].Providers {
		if err := os.WriteFile(provider.ScriptPath, []byte(source), 0o600); err != nil {
			t.Fatalf("mutate source script: %v", err)
		}
	}
}

// assertPreparedAuthnLuaSourceOwners checks exact compiled identities and retirement ownership.
func assertPreparedAuthnLuaSourceOwners(
	t *testing.T,
	prepared map[string]policyruntime.AuthnHostProvider,
) {
	t.Helper()

	cases := map[string]struct {
		kind string
		name string
	}{
		"authn/lua_environment_risk": {kind: policyconfig.ProviderKindLuaEnvironment, name: "risk"},
		"authn/lua_subject_risk":     {kind: policyconfig.ProviderKindLuaSubject, name: "risk"},
	}

	for id, expected := range cases {
		assertPreparedAuthnLuaSourceOwner(t, prepared, id, expected.kind, expected.name)
	}
}

// assertPreparedAuthnLuaSourceOwner checks one exact compiled source and its pool retirement.
func assertPreparedAuthnLuaSourceOwner(
	t *testing.T,
	prepared map[string]policyruntime.AuthnHostProvider,
	id string,
	wantKind string,
	wantName string,
) {
	t.Helper()

	provider, found := prepared[id]
	if !found || provider.ID() != id || provider.Kind() != wantKind {
		t.Fatalf("prepared provider %q = %#v", id, provider)
	}

	compiled, ok := provider.(interface {
		OpenCompiledLuaSource() (string, *lua.FunctionProto, error)
		LuaPoolKey() string
		LuaPoolManager() *vmpool.Manager
	})
	if !ok {
		t.Fatalf("prepared provider %q has no compiled Lua capability", id)
	}

	name, prototype, err := compiled.OpenCompiledLuaSource()
	if err != nil || name != wantName || prototype == nil {
		t.Fatalf("prepared provider %q source = %q/%p", id, name, prototype)
	}

	_, secondPrototype, err := compiled.OpenCompiledLuaSource()
	if err != nil || secondPrototype == nil || secondPrototype == prototype {
		t.Fatalf("prepared provider %q returned mutable/shared prototype", id)
	}

	assertPreparedAuthnLuaSourceRetirement(t, provider, compiled.LuaPoolKey(), compiled.LuaPoolManager())
}

// assertPreparedAuthnLuaSourceRetirement checks that disposal deletes only the generation-owned pool.
func assertPreparedAuthnLuaSourceRetirement(
	t *testing.T,
	provider policyruntime.AuthnHostProvider,
	poolIdentity string,
	manager *vmpool.Manager,
) {
	t.Helper()

	if poolIdentity == "" || manager == nil {
		t.Fatal("prepared provider has incomplete generation-owned pool authority")
	}

	poolKey := vmpool.PoolKey(poolIdentity)
	before := manager.GetOrCreate(poolKey, vmpool.PoolOptions{MaxVMs: 1, Config: &config.FileSettings{}})

	resource, ok := provider.(policyruntime.CandidateResource)
	if !ok {
		t.Fatalf("prepared provider %q has no retirement owner", provider.ID())
	}

	if err := resource.Dispose(t.Context()); err != nil {
		t.Fatalf("Dispose(%q) error = %v", provider.ID(), err)
	}

	after := manager.GetOrCreate(poolKey, vmpool.PoolOptions{MaxVMs: 1, Config: &config.FileSettings{}})
	if before == after {
		t.Fatalf("Dispose(%q) retained the generation-owned pool", provider.ID())
	}

	if err := manager.Delete(poolKey); err != nil {
		t.Fatalf("Delete(%q) error = %v", provider.ID(), err)
	}
}

func TestPreparedAuthnLuaSourcesKeepCapturedModuleBytes(t *testing.T) {
	configured := configuredAuthnLuaSourcePolicy(t)
	directory := t.TempDir()

	modulePath := filepath.Join(directory, "shared.lua")
	if err := os.WriteFile(modulePath, []byte(`return { value = "captured" }`), 0o600); err != nil {
		t.Fatalf("write captured module: %v", err)
	}

	writeAuthnLuaSourceModuleFixtures(t, configured)

	pattern := filepath.Join(directory, "?.lua")

	artifacts := capturePolicyLuaTestArtifacts(t, configured, pattern)
	if err := os.WriteFile(modulePath, []byte(`return { value = "mutated" }`), 0o600); err != nil {
		t.Fatalf("mutate captured module: %v", err)
	}

	modules, err := luaseal.CaptureSnapshot([]string{pattern}, artifacts)
	if err != nil {
		t.Fatalf("CaptureSnapshot() error = %v", err)
	}

	prepared, err := PrepareConfiguredAuthnLuaSources(t.Context(), 18, configured, artifacts, modules, vmpool.NewManager())
	if err != nil {
		t.Fatalf("PrepareConfiguredAuthnLuaSources() error = %v", err)
	}

	assertPreparedAuthnLuaSourcesCapturedModules(t, prepared)
}

// writeAuthnLuaSourceModuleFixtures installs callbacks that import one shared module.
func writeAuthnLuaSourceModuleFixtures(t *testing.T, configured policyconfig.PolicyConfig) {
	t.Helper()

	for name, provider := range configured.Namespaces["authn"].Providers {
		source := "local shared = require(\"shared\")\ncaptured_module_value = shared.value\n"
		if provider.Kind == policyconfig.ProviderKindLuaEnvironment {
			source += "function nauthilus_call_environment(_request) return 0, 0, 0 end\n"
		} else {
			source += "function nauthilus_call_subject(_request) return 0, 0 end\n"
		}

		if err := os.WriteFile(provider.ScriptPath, []byte(source), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

// assertPreparedAuthnLuaSourcesCapturedModules executes every source against sealed module bytes.
func assertPreparedAuthnLuaSourcesCapturedModules(
	t *testing.T,
	prepared map[string]policyruntime.AuthnHostProvider,
) {
	t.Helper()

	for id, provider := range prepared {
		compiled, ok := provider.(interface {
			OpenCompiledLuaSource() (string, *lua.FunctionProto, error)
			SealedLuaModules() *luaseal.Modules
		})
		if !ok {
			t.Fatalf("prepared provider %q has no sealed Lua capability", id)
		}

		_, prototype, openErr := compiled.OpenCompiledLuaSource()
		if openErr != nil {
			t.Fatalf("open provider %q: %v", id, openErr)
		}

		for index := 0; index < 2; index++ {
			state, stateErr := newAuthnLuaSourceValidationState(
				compiled.SealedLuaModules(),
				luaseal.PolicyProfileSubject,
			)
			if stateErr != nil {
				t.Fatalf("validation state %q: %v", id, stateErr)
			}

			if stateErr = lualib.DoCompiledFile(state, prototype); stateErr != nil {
				state.Close()
				t.Fatalf("execute provider %q state %d: %v", id, index, stateErr)
			}

			if got := state.GetGlobal("captured_module_value").String(); got != "captured" {
				state.Close()
				t.Fatalf("provider %q state %d module = %q, want captured", id, index, got)
			}

			state.Close()
		}
	}
}

func TestPrepareConfiguredAuthnLuaSourcesRejectsDeferredMutableCapability(t *testing.T) {
	configured := configuredAuthnLuaSourcePolicy(t)
	authn := configured.Namespaces["authn"]

	environment := authn.Providers["lua_environment_risk"]
	if err := os.WriteFile(environment.ScriptPath, []byte(`
local redis = require("nauthilus_redis")
function nauthilus_call_environment(_request)
    redis.redis_set("mutable", "forbidden")
    return 0, 0, 0
end
`), 0o600); err != nil {
		t.Fatalf("write mutable environment callback: %v", err)
	}

	_, err := PrepareConfiguredAuthnLuaSources(
		t.Context(),
		19,
		configured,
		capturePolicyLuaTestArtifacts(t, configured),
		nil,
		vmpool.NewManager(),
	)
	if err == nil {
		t.Fatal("PrepareConfiguredAuthnLuaSources() accepted a deferred Redis mutation")
	}
}

// configuredAuthnLuaSourcePolicy resolves isolated valid source paths into one test policy.
func configuredAuthnLuaSourcePolicy(t *testing.T) policyconfig.PolicyConfig {
	t.Helper()

	document := decodePolicy(t, configuredAuthnLuaSourcesFixture)
	directory := t.TempDir()
	scripts := map[string]string{
		"lua_environment_risk": "function nauthilus_call_environment(_request) return 0, 0, 0 end\n",
		"lua_subject_risk":     "function nauthilus_call_subject(_request) return 0, 0 end\n",
	}

	authn := document.Policy.Namespaces["authn"]

	for providerName, source := range scripts {
		path := filepath.Join(directory, providerName+".lua")
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatalf("write %s: %v", providerName, err)
		}

		provider := authn.Providers[providerName]
		provider.ScriptPath = path
		authn.Providers[providerName] = provider
	}

	document.Policy.Namespaces["authn"] = authn

	return document.Policy
}
