// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package bootfx

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
)

func TestSetupLuaScriptsUsesOneSealedProcessArtifactSnapshot(t *testing.T) {
	directory := t.TempDir()
	backendPath := filepath.Join(directory, "backend.lua")
	cacheFlushPath := filepath.Join(directory, "cache_flush.lua")
	hookPath := filepath.Join(directory, "hook.lua")

	modulePath := filepath.Join(directory, "shared.lua")
	for path, source := range map[string]string{
		backendPath:    "local shared = require('shared'); captured_backend = shared.value\n",
		cacheFlushPath: "local shared = require('shared'); function nauthilus_cache_flush(request) return {shared.value}, nil end\n",
		hookPath:       "local shared = require('shared'); captured_hook = shared.value\n",
		modulePath:     "return {value = 'captured-module'}\n",
	} {
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatalf("write process Lua artifact %q: %v", path, err)
		}
	}

	configured := &config.FileSettings{
		Server: &config.ServerSection{},
		Lua: &config.LuaSection{
			Config: &config.LuaConf{
				BackendScriptPath:    backendPath,
				CacheFlushScriptPath: cacheFlushPath,
				PackagePath:          filepath.Join(directory, "?.lua"),
			},
			Hooks: []config.LuaHooks{{
				Location:   "sealed-hook",
				Method:     http.MethodPost,
				ScriptPath: hookPath,
			}},
		},
	}
	if _, err := config.EnsureArtifactSnapshot(configured); err != nil {
		t.Fatalf("EnsureArtifactSnapshot() error = %v", err)
	}

	for _, path := range []string{backendPath, cacheFlushPath, hookPath, modulePath} {
		if err := os.WriteFile(path, []byte("this is not valid Lua !!!\n"), 0o600); err != nil {
			t.Fatalf("mutate process Lua artifact %q: %v", path, err)
		}
	}

	if err := SetupLuaScripts(configured, nil); err != nil {
		t.Fatalf("SetupLuaScripts() error = %v", err)
	}
}

func TestSetupLuaScriptsRejectsInvalidSealedProcessArtifact(t *testing.T) {
	cacheFlushPath := filepath.Join(t.TempDir(), "cache_flush.lua")
	if err := os.WriteFile(cacheFlushPath, []byte("this is not valid Lua !!!\n"), 0o600); err != nil {
		t.Fatalf("write invalid cache-flush artifact: %v", err)
	}

	configured := &config.FileSettings{
		Server: &config.ServerSection{},
		Lua: &config.LuaSection{Config: &config.LuaConf{
			CacheFlushScriptPath: cacheFlushPath,
		}},
	}
	if _, err := config.EnsureArtifactSnapshot(configured); err != nil {
		t.Fatalf("EnsureArtifactSnapshot() error = %v", err)
	}

	if err := SetupLuaScripts(configured, nil); err == nil {
		t.Fatal("SetupLuaScripts() error = nil, want invalid sealed artifact rejection")
	}
}
