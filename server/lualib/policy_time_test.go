// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package lualib

import (
	"context"
	"testing"
	"time"

	lua "github.com/yuin/gopher-lua"
)

func TestPolicyTimeUsesUTCWithoutLoadingLocations(t *testing.T) {
	state := lua.NewState()
	defer state.Close()

	state.PreloadModule("time", LoaderModPolicyTime())

	if err := state.DoString(`
		local policy_time = require("time")
		formatted, format_err = policy_time.format(0, "2006-01-02 15:04:05 MST", "UTC")
		parsed, parse_err = policy_time.parse("1970-01-01 00:00:00", "2006-01-02 15:04:05", "UTC")
		_, forbidden_err = policy_time.format(0, "2006", "Europe/Berlin")
	`); err != nil {
		t.Fatalf("execute Policy time module: %v", err)
	}

	if got := state.GetGlobal("formatted").String(); got != "1970-01-01 00:00:00 UTC" {
		t.Fatalf("unexpected UTC timestamp: %q", got)
	}

	if state.GetGlobal("format_err") != lua.LNil || state.GetGlobal("parse_err") != lua.LNil {
		t.Fatal("expected UTC conversion without an error")
	}

	if got := state.GetGlobal("parsed"); got != lua.LNumber(0) {
		t.Fatalf("unexpected parsed timestamp: %v", got)
	}

	if state.GetGlobal("forbidden_err") == lua.LNil {
		t.Fatal("expected non-UTC location to be rejected")
	}
}

func TestPolicyTimeSleepIsBoundByRuntimeContext(t *testing.T) {
	state := lua.NewState()
	defer state.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()

	state.SetContext(ctx)
	state.PreloadModule("time", LoaderModPolicyTime())

	started := time.Now()

	err := state.DoString(`require("time").sleep(60)`)
	if err == nil {
		t.Fatal("expected the request deadline to interrupt sleep")
	}

	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Policy sleep ignored the runtime deadline: %s", elapsed)
	}
}
