// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package cacheflush

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v4/server/rediscli"

	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestRunCacheFlushScriptUsesSealedSourceAfterLiveMutation(t *testing.T) {
	resetCompiledScriptForTest(t)

	scriptPath := filepath.Join(t.TempDir(), "cache_flush.lua")
	if err := os.WriteFile(scriptPath, []byte(`
function nauthilus_cache_flush(request)
  return {"captured:key"}, "captured-account"
end
`), 0o600); err != nil {
		t.Fatalf("write captured cache-flush script: %v", err)
	}

	configured := &config.FileSettings{
		Server: &config.ServerSection{},
		Lua: &config.LuaSection{Config: &config.LuaConf{
			CacheFlushScriptPath: scriptPath,
		}},
	}
	if _, err := config.EnsureArtifactSnapshot(configured); err != nil {
		t.Fatalf("EnsureArtifactSnapshot() error = %v", err)
	}

	if err := os.WriteFile(scriptPath, []byte("this is not valid Lua !!!\n"), 0o600); err != nil {
		t.Fatalf("mutate cache-flush script: %v", err)
	}

	db, _ := redismock.NewClientMock()

	result, err := RunCacheFlushScript(
		context.Background(),
		configured,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		rediscli.NewTestClient(db),
		"user@example.test",
		"guid-captured",
	)
	if err != nil {
		t.Fatalf("RunCacheFlushScript() error = %v", err)
	}

	if result == nil || result.AccountName != "captured-account" {
		t.Fatalf("RunCacheFlushScript() result = %#v, want captured script result", result)
	}

	if len(result.AdditionalKeys) != 1 || result.AdditionalKeys[0] != "captured:key" {
		t.Fatalf("RunCacheFlushScript() keys = %#v, want captured:key", result.AdditionalKeys)
	}
}

func TestPreparedCacheFlushUsesSealedModulesAcrossFreshVMs(t *testing.T) {
	resetCompiledScriptForTest(t)

	directory := t.TempDir()
	scriptPath := filepath.Join(directory, "cache_flush.lua")
	modulePath := filepath.Join(directory, "shared.lua")

	if err := os.WriteFile(scriptPath, []byte(`
assert(dofile == nil)
assert(loadfile == nil)
local shared = require("shared")
function nauthilus_cache_flush(request)
  return {shared.value}, shared.value
end
`), 0o600); err != nil {
		t.Fatalf("write captured cache-flush script: %v", err)
	}

	if err := os.WriteFile(modulePath, []byte(`return { value = "sealed-cache-module" }`), 0o600); err != nil {
		t.Fatalf("write captured cache-flush module: %v", err)
	}

	configured := &config.FileSettings{
		Server: &config.ServerSection{},
		Lua: &config.LuaSection{Config: &config.LuaConf{
			CacheFlushScriptPath: scriptPath,
			PackagePath:          filepath.Join(directory, "?.lua"),
		}},
	}
	if _, err := config.EnsureArtifactSnapshot(configured); err != nil {
		t.Fatalf("EnsureArtifactSnapshot() error = %v", err)
	}

	if err := os.WriteFile(modulePath, []byte(`return { value = "mutated-cache-module" }`), 0o600); err != nil {
		t.Fatalf("mutate cache-flush module: %v", err)
	}

	modules, err := luaseal.CaptureConfigured(configured)
	if err != nil {
		t.Fatalf("CaptureConfigured() error = %v", err)
	}

	if err = PrepareConfiguredScriptWithModules(configured, modules); err != nil {
		t.Fatalf("PrepareConfiguredScriptWithModules() error = %v", err)
	}

	program, err := compileScript(configured, scriptPath, nil)
	if err != nil {
		t.Fatalf("compileScript() error = %v", err)
	}

	for index := 0; index < 2; index++ {
		requireSealedCacheFlushResult(t, index, program, scriptPath)
	}
}

// requireSealedCacheFlushResult executes one fresh VM against the captured cache-flush program.
func requireSealedCacheFlushResult(
	t *testing.T,
	index int,
	program *compiledCacheFlushScript,
	scriptPath string,
) {
	t.Helper()

	state := lua.NewState()
	defer state.Close()

	if err := luaseal.PrepareProcess(state, program.modules); err != nil {
		t.Fatalf("fresh cache-flush VM %d preparation error = %v", index, err)
	}

	if err := executeCacheFlushScript(state, program, state.NewTable(), scriptPath); err != nil {
		t.Fatalf("fresh cache-flush VM %d execution error = %v", index, err)
	}

	result := parseReturnValues(state)
	if result.AccountName != "sealed-cache-module" || len(result.AdditionalKeys) != 1 ||
		result.AdditionalKeys[0] != "sealed-cache-module" {
		t.Fatalf("fresh cache-flush VM %d result = %#v, want sealed module values", index, result)
	}
}
