// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package luaseal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"

	lua "github.com/yuin/gopher-lua"
)

func TestCapturedModulesIgnoreFilesystemMutationAcrossFreshStates(t *testing.T) {
	directory := t.TempDir()
	modulePath := filepath.Join(directory, "shared.lua")
	writeModule(t, modulePath, `return { value = "captured" }`)

	pattern := filepath.Join(directory, "?.lua")
	snapshot := captureLuaModuleSnapshot(t, pattern)

	writeModule(t, modulePath, `return { value = "mutated" }`)

	modules, err := CaptureSnapshot([]string{pattern}, snapshot)
	if err != nil {
		t.Fatalf("CaptureSnapshot() error = %v", err)
	}

	for index := range 2 {
		state := lua.NewState()

		if err = prepareAndInstall(state, modules); err != nil {
			state.Close()
			t.Fatalf("seal fresh state %d: %v", index, err)
		}

		err = state.DoString(`
assert(package.path == "")
assert(package.cpath == "")
local shared = require("shared")
assert(shared.value == "captured")
`)
		state.Close()

		if err != nil {
			t.Fatalf("fresh state %d observed mutable module authority: %v", index, err)
		}
	}
}

func TestInstalledModulesRejectUncapturedFilesystemRequire(t *testing.T) {
	directory := t.TempDir()
	writeModule(t, filepath.Join(directory, "late.lua"), `return { value = "late" }`)

	state := lua.NewState()
	defer state.Close()

	snapshot := captureLuaModuleSnapshot(t)

	modules, err := CaptureSnapshot(nil, snapshot)
	if err != nil {
		t.Fatalf("CaptureSnapshot() error = %v", err)
	}

	if err = prepareAndInstall(state, modules); err != nil {
		t.Fatalf("seal state: %v", err)
	}

	err = state.DoString(`require("late")`)
	if err == nil {
		t.Fatal("uncaptured filesystem module was loaded")
	}
}

// TestInstallKeepsTheCompleteLuaLibrary proves the seal owns module resolution only: no library, base function,
// or host preload is removed, and a script may still load code by absolute path or select modules dynamically.
func TestInstallKeepsTheCompleteLuaLibrary(t *testing.T) {
	directory := t.TempDir()
	chunkPath := filepath.Join(directory, "chunk.lua")

	writeModule(t, chunkPath, `return "loaded from file"`)

	state := lua.NewState()
	defer state.Close()

	state.PreloadModule("host_module", hostModuleLoader("host"))
	state.SetGlobal("chunk_path", lua.LString(chunkPath))

	if err := prepareAndInstall(state, nil); err != nil {
		t.Fatalf("seal state: %v", err)
	}

	if err := state.DoString(`
for _, name in ipairs({ "os", "io", "debug", "coroutine", "channel", "string", "table", "math", "package" }) do
    assert(type(_G[name]) == "table", "library " .. name .. " was removed")
end

for _, name in ipairs({
    "print", "load", "loadstring", "dofile", "loadfile", "collectgarbage",
    "getfenv", "setfenv", "module", "newproxy", "require",
}) do
    assert(type(_G[name]) == "function", "base function " .. name .. " was removed")
end

assert(type(package.seeall) == "function", "package.seeall was removed")
assert(dofile(chunk_path) == "loaded from file")
assert(loadfile(chunk_path)() == "loaded from file")
assert(loadstring("return 7")() == 7)

local selected = "host_" .. "module"
assert(require(selected).value == "host")
`); err != nil {
		t.Fatalf("sealed state lost part of the Lua library: %v", err)
	}
}

// TestInstallRequiresPreparedState keeps the two-step lease protocol explicit.
func TestInstallRequiresPreparedState(t *testing.T) {
	state := lua.NewState()
	defer state.Close()

	if err := Install(state, nil); err == nil {
		t.Fatal("Install() accepted a state that was not prepared")
	}
}

func TestInstallRestoresHostPreloadsAndClearsRemovedModules(t *testing.T) {
	directory := t.TempDir()
	modulePath := filepath.Join(directory, "removed.lua")
	pattern := filepath.Join(directory, "?.lua")

	writeModule(t, modulePath, `return { value = "captured" }`)
	firstSnapshot := captureLuaModuleSnapshot(t, pattern)

	firstModules, err := CaptureSnapshot([]string{pattern}, firstSnapshot)
	if err != nil {
		t.Fatalf("CaptureSnapshot(first) error = %v", err)
	}

	emptySnapshot := captureLuaModuleSnapshot(t)

	emptyModules, err := CaptureSnapshot(nil, emptySnapshot)
	if err != nil {
		t.Fatalf("CaptureSnapshot(empty) error = %v", err)
	}

	state := lua.NewState()
	defer state.Close()

	state.PreloadModule("dynamic_host", hostModuleLoader("host"))

	if err = Prepare(state, firstModules); err != nil {
		t.Fatalf("Prepare(first) error = %v", err)
	}

	if err = Install(state, firstModules); err != nil {
		t.Fatalf("Install(first) error = %v", err)
	}

	if err = state.DoString(`
assert(require("dynamic_host").value == "host")
assert(require("removed").value == "captured")
package.preload.dynamic_host = function() return { value = "mutated" } end
package.loaded.dynamic_host = nil
package.loaded.removed = { value = "stale" }
`); err != nil {
		t.Fatalf("mutate package state: %v", err)
	}

	if err = Prepare(state, emptyModules); err != nil {
		t.Fatalf("Prepare(second) error = %v", err)
	}

	if err = Install(state, emptyModules); err != nil {
		t.Fatalf("Install(second) error = %v", err)
	}

	if err = state.DoString(`
assert(require("dynamic_host").value == "host")
local ok = pcall(require, "removed")
assert(ok == false)
`); err != nil {
		t.Fatalf("restored module authority error = %v", err)
	}
}

func TestInstallRefreshesTrustedHostBindingsAfterReset(t *testing.T) {
	state := lua.NewState()
	defer state.Close()

	state.PreloadModule("dynamic_host", hostModuleLoader("request"))

	if err := Prepare(state, nil); err != nil {
		t.Fatalf("Prepare(first) error = %v", err)
	}

	if err := Install(state, nil); err != nil {
		t.Fatalf("Install(first) error = %v", err)
	}

	if err := state.DoString(`
assert(require("dynamic_host").value == "request")
package.preload.dynamic_host = function() return { value = "script" } end
package.preload.script_only = function() return { value = "script" } end
package.loaded.dynamic_host = nil
`); err != nil {
		t.Fatalf("mutate first lease: %v", err)
	}

	if err := Prepare(state, nil); err != nil {
		t.Fatalf("Prepare(second) error = %v", err)
	}

	state.PreloadModule("dynamic_host", hostModuleLoader("startup"))

	if err := Install(state, nil); err != nil {
		t.Fatalf("Install(second) error = %v", err)
	}

	if err := state.DoString(`
assert(require("dynamic_host").value == "startup")
local script_only_ok = pcall(require, "script_only")
assert(script_only_ok == false)
`); err != nil {
		t.Fatalf("second lease retained stale authority: %v", err)
	}
}

// prepareAndInstall seals one state without host bindings between the two lease steps.
func prepareAndInstall(state *lua.LState, modules *Modules) error {
	if err := Prepare(state, modules); err != nil {
		return err
	}

	return Install(state, modules)
}

// hostModuleLoader returns a host preload with one observable generation value.
func hostModuleLoader(value string) lua.LGFunction {
	return func(state *lua.LState) int {
		module := state.NewTable()
		module.RawSetString("value", lua.LString(value))
		state.Push(module)

		return 1
	}
}

// captureLuaModuleSnapshot captures only the test's declared package patterns.
func captureLuaModuleSnapshot(t *testing.T, patterns ...string) *config.ArtifactSnapshot {
	t.Helper()

	snapshot, err := config.CaptureArtifactSnapshot(config.ArtifactSnapshotSpec{LuaPackagePatterns: patterns})
	if err != nil {
		t.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	t.Cleanup(snapshot.Release)

	return snapshot
}

// writeModule replaces one module source used by the immutable-capture reproducer.
func writeModule(t *testing.T, path string, source string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatalf("write module: %v", err)
	}
}

// TestModulesMentionsSearchesCapturedSources covers the entry-point lookup used by candidate preparation.
func TestModulesMentionsSearchesCapturedSources(t *testing.T) {
	directory := t.TempDir()
	writeModule(t, filepath.Join(directory, "callbacks.lua"), `function nauthilus_call_subject() return 0, 0 end`)

	pattern := filepath.Join(directory, "?.lua")

	modules, err := CaptureSnapshot([]string{pattern}, captureLuaModuleSnapshot(t, pattern))
	if err != nil {
		t.Fatalf("CaptureSnapshot() error = %v", err)
	}

	for _, test := range []struct {
		modules *Modules
		text    string
		want    bool
	}{
		{modules: modules, text: "nauthilus_call_subject", want: true},
		{modules: modules, text: "nauthilus_call_action"},
		{modules: modules, text: ""},
		{modules: nil, text: "nauthilus_call_subject"},
	} {
		if got := test.modules.Mentions(test.text); got != test.want {
			t.Errorf("Mentions(%q) = %t, want %t", test.text, got, test.want)
		}
	}
}
