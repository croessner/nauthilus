// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package backend

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/lualib"
	"github.com/croessner/nauthilus/v4/server/lualib/luapool"

	lua "github.com/yuin/gopher-lua"
)

func TestBindLuaRequestModulesUsesRequestTolerateWithoutGlobal(t *testing.T) {
	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	injected := tolerate.NewTolerateWithDeps(cfg, logger, nil, 0)
	injected.SetCustomToleration("192.0.2.53", 35, time.Minute)

	previous := tolerate.GetTolerate()

	tolerate.SetTolerate(nil)
	t.Cleanup(func() { tolerate.SetTolerate(previous) })

	state := lua.NewState()
	t.Cleanup(state.Close)
	luapool.PrepareRequestEnv(state)
	bindLuaRequestModules(
		context.Background(),
		context.Background(),
		cfg,
		logger,
		nil,
		state,
		&bktype.LuaRequest{Context: lualib.NewContext(), Tolerate: injected},
	)

	err := state.DoString(`
local brute_force = require("nauthilus_brute_force")
local entries, get_error = brute_force.get_custom_tolerations()
assert(get_error == nil)
assert(#entries == 1)
assert(entries[1].ip_address == "192.0.2.53")
`)
	if err != nil {
		t.Fatalf("Lua backend request did not use injected tolerate: %v", err)
	}
}
