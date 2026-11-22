// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package environment

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/lualib"
	"github.com/croessner/nauthilus/v4/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v4/server/lualib/pipeline"
	"github.com/croessner/nauthilus/v4/server/lualib/vmpool"
)

// BenchmarkCallEnvironmentLuaSourceWithSharedModules measures one complete environment source request whose script
// loads the bundled shared modules, as the bundled plugins do.
func BenchmarkCallEnvironmentLuaSourceWithSharedModules(b *testing.B) {
	pattern := filepath.Join("..", "..", "lua-plugins.d", "share", "?.lua")

	snapshot, err := config.CaptureArtifactSnapshot(config.ArtifactSnapshotSpec{LuaPackagePatterns: []string{pattern}})
	if err != nil {
		b.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	b.Cleanup(snapshot.Release)

	modules, err := luaseal.CaptureSnapshot([]string{pattern}, snapshot)
	if err != nil {
		b.Fatalf("CaptureSnapshot() error = %v", err)
	}

	scriptPath := filepath.Join(b.TempDir(), "shared.lua")

	prototype, err := lualib.CompileLuaSource(scriptPath, []byte(`
local nauthilus_util = require("nauthilus_util")
local nauthilus_keys = require("nauthilus_keys")
local nauthilus_redis_pool = require("nauthilus_redis_pool")
local nauthilus_policy_facts = require("nauthilus_policy_facts")

function nauthilus_call_environment(_request)
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`))
	if err != nil {
		b.Fatalf("compile benchmark source: %v", err)
	}

	source := &LuaEnvironmentSource{
		Name: "shared", CompiledScript: prototype, Modules: modules,
		Modes: pipeline.ModeAuthenticated | pipeline.ModeUnauthenticated | pipeline.ModeNoAuth,
	}
	manager := vmpool.NewManager()
	key := vmpool.PoolKey("bench:environment:shared")

	b.Cleanup(func() { _ = manager.Delete(key) })

	cfg := newEnvironmentTestConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ginCtx := newEnvironmentTestContext()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if _, _, err = newEnvironmentTestRequest().CallEnvironmentLuaSource(ginCtx, cfg, logger, nil, source, manager, key); err != nil {
			b.Fatalf("CallEnvironmentLuaSource() error = %v", err)
		}
	}
}
