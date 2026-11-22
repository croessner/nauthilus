// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/lualib"
	"github.com/croessner/nauthilus/v4/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v4/server/lualib/vmpool"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
	"github.com/croessner/nauthilus/v4/server/testing/luaapiprobe"
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

	// The prototype is compiled once per generation and shared by every request VM; gopher-lua never writes it
	// after compiling, and the sealed-module test executes the same prototype in several states.
	_, secondPrototype, err := compiled.OpenCompiledLuaSource()
	if err != nil || secondPrototype != prototype {
		t.Fatalf("prepared provider %q recompiled its prototype per open", id)
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

		// Several request VMs execute the one shared prototype concurrently; the race detector covers the sharing.
		const states = 4

		failures := make(chan error, states)
		wait := sync.WaitGroup{}

		for index := range states {
			wait.Go(func() {
				failures <- runCapturedModulePrototype(compiled.SealedLuaModules(), prototype, index)
			})
		}

		wait.Wait()
		close(failures)

		for failure := range failures {
			if failure != nil {
				t.Fatalf("provider %q: %v", id, failure)
			}
		}
	}
}

// newSealedLuaTestState builds a plain VM whose require resolves only the captured module snapshot.
func newSealedLuaTestState(modules *luaseal.Modules) (*lua.LState, error) {
	state := lua.NewState()

	if err := luaseal.Prepare(state, modules); err != nil {
		state.Close()

		return nil, err
	}

	if err := luaseal.Install(state, modules); err != nil {
		state.Close()

		return nil, err
	}

	return state, nil
}

// runCapturedModulePrototype executes one shared prototype in its own sealed state.
func runCapturedModulePrototype(modules *luaseal.Modules, prototype *lua.FunctionProto, index int) error {
	state, err := newSealedLuaTestState(modules)
	if err != nil {
		return fmt.Errorf("sealed state %d: %w", index, err)
	}
	defer state.Close()

	if err = lualib.DoCompiledFile(state, prototype); err != nil {
		return fmt.Errorf("execute state %d: %w", index, err)
	}

	if got := state.GetGlobal("captured_module_value").String(); got != "captured" {
		return fmt.Errorf("state %d module = %q, want captured", index, got)
	}

	return nil
}

// unexecutableModuleLevelCode fails when it runs outside a request: it uses the legacy dynamic_loader call, a host
// module as a bare global, and finally raises an error. Candidate preparation must accept it because it never
// executes a callback script.
const unexecutableModuleLevelCode = `
dynamic_loader("nauthilus_redis")

local module_level_context_get = nauthilus_context.context_get
local module_level_country = "x-" .. require("nauthilus_misc").get_country_name("DE")

error("candidate preparation must not execute callback scripts")
`

// TestPrepareConfiguredAuthnLuaSourcesAcceptFullHostAPI proves candidate preparation never rejects a source for
// the host API it uses and never executes it. The probe names every mutating and registering function.
func TestPrepareConfiguredAuthnLuaSourcesAcceptFullHostAPI(t *testing.T) {
	configured := configuredAuthnLuaSourcePolicy(t)
	entryPoints := map[string]string{
		policyconfig.ProviderKindLuaEnvironment: `
function nauthilus_call_environment(_request)
    probe.run()

    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`,
		policyconfig.ProviderKindLuaSubject: `
function nauthilus_call_subject(_request)
    probe.run()
    probe.backend_selection()
    require("nauthilus_backend").select_backend_server("192.0.2.77", 993)

    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`,
	}

	for name, provider := range configured.Namespaces["authn"].Providers {
		source := luaapiprobe.Script(t, unexecutableModuleLevelCode+entryPoints[provider.Kind])
		if err := os.WriteFile(provider.ScriptPath, []byte(source), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	prepared, err := PrepareConfiguredAuthnLuaSources(
		t.Context(),
		19,
		configured,
		capturePolicyLuaTestArtifacts(t, configured),
		nil,
		vmpool.NewManager(),
	)
	if err != nil {
		t.Fatalf("PrepareConfiguredAuthnLuaSources() error = %v", err)
	}

	if len(prepared) != len(configured.Namespaces["authn"].Providers) {
		t.Fatalf("prepared sources = %d, want every configured provider", len(prepared))
	}
}

// TestPrepareConfiguredAuthnLuaSourcesAcceptEntryPointFromCapturedModule proves a callback may live in a shared
// module that the configured script only requires.
func TestPrepareConfiguredAuthnLuaSourcesAcceptEntryPointFromCapturedModule(t *testing.T) {
	configured := configuredAuthnLuaSourcePolicy(t)
	directory := t.TempDir()
	module := `
function nauthilus_call_environment(_request) return 0, 0, 0 end
function nauthilus_call_subject(_request) return 0, 0 end
`

	if err := os.WriteFile(filepath.Join(directory, "callbacks.lua"), []byte(module), 0o600); err != nil {
		t.Fatalf("write shared callbacks: %v", err)
	}

	for name, provider := range configured.Namespaces["authn"].Providers {
		if err := os.WriteFile(provider.ScriptPath, []byte(`require("callbacks")`+"\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	pattern := filepath.Join(directory, "?.lua")
	artifacts := capturePolicyLuaTestArtifacts(t, configured, pattern)

	modules, err := luaseal.CaptureSnapshot([]string{pattern}, artifacts)
	if err != nil {
		t.Fatalf("CaptureSnapshot() error = %v", err)
	}

	if _, err = PrepareConfiguredAuthnLuaSources(t.Context(), 21, configured, artifacts, modules, vmpool.NewManager()); err != nil {
		t.Fatalf("PrepareConfiguredAuthnLuaSources() error = %v", err)
	}
}

// TestPrepareConfiguredAuthnLuaSourcesRejectsMissingEntryPoint keeps the one remaining load-time check.
func TestPrepareConfiguredAuthnLuaSourcesRejectsMissingEntryPoint(t *testing.T) {
	configured := configuredAuthnLuaSourcePolicy(t)

	environment := configured.Namespaces["authn"].Providers["lua_environment_risk"]
	if err := os.WriteFile(environment.ScriptPath, []byte("return true\n"), 0o600); err != nil {
		t.Fatalf("write environment callback: %v", err)
	}

	_, err := PrepareConfiguredAuthnLuaSources(
		t.Context(),
		20,
		configured,
		capturePolicyLuaTestArtifacts(t, configured),
		nil,
		vmpool.NewManager(),
	)
	if err == nil {
		t.Fatal("PrepareConfiguredAuthnLuaSources() accepted a source without its entry point")
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
