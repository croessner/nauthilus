// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package bruteforce

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/croessner/nauthilus/v4/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/rediscli"

	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestBruteForceModuleUsesInjectedTolerateWithoutGlobal(t *testing.T) {
	cfg := &config.FileSettings{
		Server:     &config.ServerSection{},
		BruteForce: &config.BruteForceSection{},
	}
	database, _ := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(database)
	injected := tolerate.NewTolerateWithDeps(
		cfg,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		redisClient,
		0,
	)
	previous := tolerate.GetTolerate()

	tolerate.SetTolerate(nil)
	t.Cleanup(func() { tolerate.SetTolerate(previous) })

	state := lua.NewState()
	t.Cleanup(state.Close)
	state.PreloadModule(
		definitions.LuaModBruteForce,
		LoaderModBruteForce(context.Background(), cfg, slog.Default(), redisClient, injected),
	)

	err := state.DoString(`
local bf = require("nauthilus_brute_force")
local result, set_error = bf.set_custom_toleration({
  ip_address = "192.0.2.44",
  tolerate_percent = 25,
  tolerate_ttl = "1m",
})
assert(result == "OK" and set_error == nil)
local entries, get_error = bf.get_custom_tolerations()
assert(get_error == nil)
assert(#entries == 1)
assert(entries[1].ip_address == "192.0.2.44")
`)
	if err != nil {
		t.Fatalf("injected tolerate Lua flow failed: %v", err)
	}
}
