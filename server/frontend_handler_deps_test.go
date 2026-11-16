// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"log/slog"
	"testing"

	"github.com/croessner/nauthilus/v4/server/pluginruntime"
)

// TestFrontendHandlerDepsCarryPluginRunner reproduces the missing step-event path found by the browser smoke: the IdP
// frontend handlers emit second-factor events through the native plugin runner, so their deps must carry it.
func TestFrontendHandlerDepsCarryPluginRunner(t *testing.T) {
	runner := pluginruntime.NewRunner(nil)
	runtime := httpServerRuntime{store: &contextStore{pluginRunner: runner}, logger: slog.Default()}

	if deps := frontendHandlerDeps(runtime); deps.PluginRunner != runner {
		t.Fatalf("frontend deps PluginRunner = %p, want process runner %p", deps.PluginRunner, runner)
	}
}
