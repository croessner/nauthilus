// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package backend

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/lualib/luaseal"

	lua "github.com/yuin/gopher-lua"
)

func TestPreparedLuaBackendUsesSealedEntryAndModulesAcrossFreshVMs(t *testing.T) {
	configured, program := prepareCapturedLuaBackend(t)

	for index := 0; index < 2; index++ {
		assertCapturedLuaBackendVM(t, configured, program, index)
	}
}

// prepareCapturedLuaBackend captures a valid program before mutating its live source files.
func prepareCapturedLuaBackend(t *testing.T) (*config.FileSettings, *preparedLuaBackendProgram) {
	t.Helper()

	directory := t.TempDir()
	scriptPath := filepath.Join(directory, "backend.lua")
	modulePath := filepath.Join(directory, "shared.lua")

	if err := os.WriteFile(scriptPath, []byte(`
assert(dofile == nil)
assert(loadfile == nil)
local shared = require("shared")
captured_backend = shared.value
`), 0o600); err != nil {
		t.Fatalf("write captured backend script: %v", err)
	}

	if err := os.WriteFile(modulePath, []byte(`return { value = "sealed-module" }`), 0o600); err != nil {
		t.Fatalf("write captured backend module: %v", err)
	}

	configured := &config.FileSettings{
		Server: &config.ServerSection{},
		Lua: &config.LuaSection{Config: &config.LuaConf{
			BackendScriptPath: scriptPath,
			PackagePath:       filepath.Join(directory, "?.lua"),
		}},
	}
	if _, err := config.EnsureArtifactSnapshot(configured); err != nil {
		t.Fatalf("EnsureArtifactSnapshot() error = %v", err)
	}

	if err := os.WriteFile(scriptPath, []byte("this is not valid Lua !!!\n"), 0o600); err != nil {
		t.Fatalf("mutate backend script: %v", err)
	}

	if err := os.WriteFile(modulePath, []byte(`return { value = "mutated-module" }`), 0o600); err != nil {
		t.Fatalf("mutate backend module: %v", err)
	}

	modules, err := luaseal.CaptureConfigured(configured)
	if err != nil {
		t.Fatalf("CaptureConfigured() error = %v", err)
	}

	if err = PrepareLuaBackendScriptsWithModules(configured, modules); err != nil {
		t.Fatalf("PrepareLuaBackendScriptsWithModules() error = %v", err)
	}

	program, err := preparedLuaBackendScript(configured, definitions.DefaultBackendName, scriptPath, nil)
	if err != nil {
		t.Fatalf("preparedLuaBackendScript() error = %v", err)
	}

	return configured, program
}

// assertCapturedLuaBackendVM verifies that one fresh VM observes only the sealed bytes.
func assertCapturedLuaBackendVM(
	t *testing.T,
	configured config.File,
	program *preparedLuaBackendProgram,
	index int,
) {
	t.Helper()

	state := lua.NewState()
	defer state.Close()

	if err := luaseal.PrepareProcess(state, program.modules); err != nil {
		t.Fatalf("fresh backend VM %d preparation error = %v", index, err)
	}

	err := executeAndHandleError(
		configured,
		nil,
		program,
		"",
		&bktype.LuaRequest{},
		state,
		state.NewTable(),
		0,
		new(lualib.CustomLogKeyValue),
	)
	if err != nil {
		t.Fatalf("fresh backend VM %d execution error = %v", index, err)
	}

	if got := state.GetGlobal("captured_backend").String(); got != "sealed-module" {
		t.Fatalf("fresh backend VM %d captured_backend = %q, want sealed-module", index, got)
	}
}
