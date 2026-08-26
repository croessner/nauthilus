// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package connmgr

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	lua "github.com/yuin/gopher-lua"
)

// TestLoaderModPsnetRequestHidesTargetRegistration proves Policy request VMs cannot mutate process targets.
func TestLoaderModPsnetRequestHidesTargetRegistration(t *testing.T) {
	manager = NewConnectionManager()
	manager.targets["sealed-target"] = TargetInfo{Direction: "local", Description: "test"}

	state := lua.NewState()
	defer state.Close()

	state.PreloadModule(
		definitions.LuaModPsnet,
		LoaderModPsnetRequest(context.Background(), &config.FileSettings{}, nil),
	)

	if err := state.DoString(`
		local psnet = require("nauthilus_psnet")
		assert(psnet.register_connection_target == nil)
		assert(type(psnet.get_connection_target) == "function")
		assert(psnet.get_connection_target("sealed-target") == 0)
	`); err != nil {
		t.Fatalf("restricted psnet module: %v", err)
	}
}
