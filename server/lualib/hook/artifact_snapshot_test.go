// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package hook

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/lualib/luaseal"

	lua "github.com/yuin/gopher-lua"
)

func TestPreCompileLuaHooksUsesSealedEntryAndModulesAcrossFreshVMs(t *testing.T) {
	withIsolatedHookRoles(t)

	directory := t.TempDir()
	scriptPath := filepath.Join(directory, "hook.lua")
	modulePath := filepath.Join(directory, "shared.lua")

	if err := os.WriteFile(scriptPath, []byte(`
assert(dofile == nil)
assert(loadfile == nil)
local shared = require("shared")
function nauthilus_run_hook(request)
  return {module = shared.value}
end
`), 0o600); err != nil {
		t.Fatalf("write captured hook script: %v", err)
	}

	if err := os.WriteFile(modulePath, []byte(`return { value = "sealed-hook-module" }`), 0o600); err != nil {
		t.Fatalf("write captured hook module: %v", err)
	}

	configured := &config.FileSettings{
		Server: &config.ServerSection{},
		Lua: &config.LuaSection{
			Config: &config.LuaConf{PackagePath: filepath.Join(directory, "?.lua")},
			Hooks: []config.LuaHooks{{
				Location:   "captured-hook",
				Method:     http.MethodGet,
				ScriptPath: scriptPath,
			}},
		},
	}
	if _, err := config.EnsureArtifactSnapshot(configured); err != nil {
		t.Fatalf("EnsureArtifactSnapshot() error = %v", err)
	}

	if err := os.WriteFile(scriptPath, []byte("this is not valid Lua !!!\n"), 0o600); err != nil {
		t.Fatalf("mutate hook script: %v", err)
	}

	if err := os.WriteFile(modulePath, []byte(`return { value = "mutated-hook-module" }`), 0o600); err != nil {
		t.Fatalf("mutate hook module: %v", err)
	}

	if err := PreCompileLuaHooks(configured); err != nil {
		t.Fatalf("PreCompileLuaHooks() error = %v", err)
	}

	script := mustCapturedHookScript(t)
	prototype, modules := script.prepared()

	for index := 0; index < 2; index++ {
		requireSealedHookResult(t, index, prototype, modules)
	}
}

// mustCapturedHookScript returns the precompiled hook registered by the isolated test candidate.
func mustCapturedHookScript(t *testing.T) *PrecompiledLuaScript {
	t.Helper()

	mu.RLock()

	script := customLocation.GetScript("captured-hook", http.MethodGet)

	mu.RUnlock()

	if script == nil || script.GetPrecompiledScript() == nil {
		t.Fatal("captured hook prototype was not registered")
	}

	return script
}

// requireSealedHookResult executes one fresh VM against the captured hook program.
func requireSealedHookResult(
	t *testing.T,
	index int,
	prototype *lua.FunctionProto,
	modules *luaseal.Modules,
) {
	t.Helper()

	state := lua.NewState()
	defer state.Close()

	if err := luaseal.PrepareProcess(state, modules); err != nil {
		t.Fatalf("fresh hook VM %d preparation error = %v", index, err)
	}

	result, err := executeAndHandleError(
		nil,
		prototype,
		modules,
		state,
		"captured-hook",
		state.NewTable(),
	)
	if err != nil {
		t.Fatalf("fresh hook VM %d execution error = %v", index, err)
	}

	if got := result["module"]; got != "sealed-hook-module" {
		t.Fatalf("fresh hook VM %d module result = %#v, want sealed-hook-module", index, got)
	}
}
