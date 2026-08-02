// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib"
)

func TestUpdateLuaContextAcceptsPluginNormalizedBuiltinControls(t *testing.T) {
	auth := &AuthState{Runtime: AuthRuntime{Context: lualib.NewContext()}}
	auth.Runtime.Context.Set(definitions.LuaCtxBuiltin, []any{definitions.ControlBruteForce})

	auth.updateLuaContext(definitions.ControlRBL)

	controls := auth.Runtime.Context.Get(definitions.LuaCtxBuiltin)
	assertEnvironmentControls(t, controls, definitions.ControlBruteForce, definitions.ControlRBL)
}

// assertEnvironmentControls verifies the internal set representation and its members.
func assertEnvironmentControls(t *testing.T, value any, expected ...string) {
	t.Helper()

	controls, ok := value.(config.StringSet)
	if !ok {
		t.Fatalf("builtin controls type = %T, want string set", value)
	}

	for _, control := range expected {
		if _, exists := controls[control]; !exists {
			t.Fatalf("builtin controls = %#v, missing %q", value, control)
		}
	}
}
