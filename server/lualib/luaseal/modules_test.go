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

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"

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

	for index := 0; index < 2; index++ {
		state := lua.NewState()
		state.PreloadModule("ambient_loader", func(current *lua.LState) int {
			current.Push(current.NewTable())

			return 1
		})

		if err = PreparePolicy(state, modules); err != nil {
			state.Close()
			t.Fatalf("PreparePolicy() error = %v", err)
		}

		if err = InstallPolicy(state, modules); err != nil {
			state.Close()
			t.Fatalf("Install() error = %v", err)
		}

		err = state.DoString(`
assert(dofile == nil)
assert(loadfile == nil)
assert(load == nil)
assert(loadstring == nil)
assert(os == nil)
assert(io == nil)
assert(debug == nil)
assert(channel == nil)
assert(coroutine == nil)
assert(package.path == "")
assert(package.cpath == "")
assert(package.loadlib == nil)
local ok = pcall(require, "ambient_loader")
assert(ok == false)
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

	if err = PreparePolicy(state, modules); err != nil {
		t.Fatalf("PreparePolicy() error = %v", err)
	}

	if err = InstallPolicy(state, modules); err != nil {
		t.Fatalf("Install() error = %v", err)
	}

	err = state.DoString(`require("late")`)
	if err == nil {
		t.Fatal("uncaptured filesystem module was loaded")
	}
}

func TestPreparePolicyRebuildsPoisonedGlobalsAndModuleCachesAcrossLeases(t *testing.T) {
	state := lua.NewState()
	defer state.Close()

	state.PreloadModule("json", func(current *lua.LState) int {
		module := current.NewTable()
		module.RawSetString("value", lua.LString("clean"))
		current.Push(module)

		return 1
	})
	state.PreloadModule("forbidden_host", func(current *lua.LState) int {
		current.Push(current.NewTable())

		return 1
	})

	if err := PreparePolicy(state, nil); err != nil {
		t.Fatalf("PreparePolicy(first) error = %v", err)
	}

	state.SetGlobal("__NAUTH_REQ_ENV", state.NewTable())

	if err := InstallPolicy(state, nil); err != nil {
		t.Fatalf("InstallPolicy(first) error = %v", err)
	}

	if err := state.DoString(`
		local json = require("json")
		json.poisoned = true
		package.loaded.json = json
		package.preload.forbidden_host = function() return { escaped = true } end
		require = function() return { escaped = true } end
		_G.cross_lease_value = "poisoned"
	`); err != nil {
		t.Fatalf("poison first lease: %v", err)
	}

	if err := PreparePolicy(state, nil); err != nil {
		t.Fatalf("PreparePolicy(second) error = %v", err)
	}

	state.SetGlobal("__NAUTH_REQ_ENV", state.NewTable())

	if err := InstallPolicy(state, nil); err != nil {
		t.Fatalf("InstallPolicy(second) error = %v", err)
	}

	if err := state.DoString(`
		assert(cross_lease_value == nil)
		assert(type(require) == "function")
		local json = require("json")
		assert(json.value == "clean")
		assert(json.poisoned == nil)
		local forbidden_ok = pcall(require, "forbidden_host")
		assert(forbidden_ok == false)
	`); err != nil {
		t.Fatalf("second lease retained poisoned authority: %v", err)
	}
}

func TestInstallPolicyRemovesForbiddenDirectRequestModuleBindings(t *testing.T) {
	state := lua.NewState()
	defer state.Close()

	if err := PreparePolicy(state, nil); err != nil {
		t.Fatalf("PreparePolicy() error = %v", err)
	}

	requestEnv := state.NewTable()
	requestEnv.RawSetString("nauthilus_ldap", state.NewTable())
	requestEnv.RawSetString("glua_http", state.NewTable())
	requestEnv.RawSetString("__NAUTH_REQ_CONTEXT", state.NewUserData())
	state.SetGlobal("__NAUTH_REQ_ENV", requestEnv)

	if err := InstallPolicy(state, nil); err != nil {
		t.Fatalf("InstallPolicy() error = %v", err)
	}

	if err := state.DoString(`
		assert(rawget(__NAUTH_REQ_ENV, "nauthilus_ldap") == nil)
		assert(rawget(__NAUTH_REQ_ENV, "glua_http") == nil)
		assert(rawget(__NAUTH_REQ_ENV, "__NAUTH_REQ_CONTEXT") ~= nil)
	`); err != nil {
		t.Fatalf("forbidden direct request binding remained visible: %v", err)
	}
}

func TestPolicyProfilesExposeOnlySelectedStageCapabilities(t *testing.T) {
	tests := []struct {
		name         string
		profile      PolicyProfile
		wantResponse bool
		wantBackend  bool
	}{
		{name: "environment", profile: PolicyProfileEnvironment},
		{name: "subject", profile: PolicyProfileSubject, wantBackend: true},
		{name: "post action", profile: PolicyProfileAction},
		{name: "synchronous action", profile: PolicyProfileResponseAction, wantResponse: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := lua.NewState()
			defer state.Close()

			for _, name := range []string{
				definitions.LuaModHTTPResponse,
				definitions.LuaModBackend,
				definitions.LuaBackendResultTypeName,
			} {
				moduleName := name
				state.PreloadModule(moduleName, func(current *lua.LState) int {
					current.Push(current.NewTable())

					return 1
				})
			}

			if err := PreparePolicyProfile(state, nil, test.profile); err != nil {
				t.Fatalf("PreparePolicyProfile() error = %v", err)
			}

			requestEnv := state.NewTable()
			requestEnv.RawSetString(definitions.LuaModHTTPResponse, state.NewTable())
			requestEnv.RawSetString(definitions.LuaModBackend, state.NewTable())
			requestEnv.RawSetString(definitions.LuaBackendResultTypeName, state.NewTable())
			state.SetGlobal("__NAUTH_REQ_ENV", requestEnv)

			if err := InstallPolicyProfile(state, nil, test.profile); err != nil {
				t.Fatalf("InstallPolicyProfile() error = %v", err)
			}

			gotResponse := requestEnv.RawGetString(definitions.LuaModHTTPResponse) != lua.LNil

			gotBackend := requestEnv.RawGetString(definitions.LuaModBackend) != lua.LNil &&
				requestEnv.RawGetString(definitions.LuaBackendResultTypeName) != lua.LNil
			if gotResponse != test.wantResponse || gotBackend != test.wantBackend {
				t.Fatalf(
					"stage capabilities response/backend = %t/%t, want %t/%t",
					gotResponse,
					gotBackend,
					test.wantResponse,
					test.wantBackend,
				)
			}
		})
	}
}

func TestValidateSourceRejectsNestedMutableCapabilitiesBeforeExecution(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		profile PolicyProfile
	}{
		{
			name: "post action response",
			source: `function callback()
				local response = require("nauthilus_http_response")
				response.add_http_response_header("X-Test", "forbidden")
			end`,
			profile: PolicyProfileAction,
		},
		{
			name: "Redis mutation",
			source: `function callback(redis)
				redis.redis_set("key", "value")
			end`,
			profile: PolicyProfileEnvironment,
		},
		{
			name: "backend target selection",
			source: `function callback(backend)
				backend.select_backend_server("mutable.example", 1234)
			end`,
			profile: PolicyProfileSubject,
		},
		{
			name: "deferred in-memory compiler",
			source: `function callback(source)
				return load(source)
			end`,
			profile: PolicyProfileEnvironment,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := (*Modules)(nil).ValidateSource(
				"@candidate.lua",
				[]byte(test.source),
				test.profile,
			); err == nil {
				t.Fatal("ValidateSource() accepted a mutable nested capability")
			}
		})
	}
}

func TestValidateSourceRecursesIntoCapturedDependencies(t *testing.T) {
	modules := &Modules{entries: map[string]capturedModule{
		"helper": {name: "helper", source: []byte(`return { run = dynamic_loader }`)},
	}}

	if err := modules.ValidateSource(
		"@candidate.lua",
		[]byte(`local helper = require("helper")`),
		PolicyProfileEnvironment,
	); err == nil {
		t.Fatal("ValidateSource() accepted mutable authority in a captured dependency")
	}
}

func TestValidateSourceRejectsUnavailableAndDynamicDependencies(t *testing.T) {
	modules := &Modules{entries: make(map[string]capturedModule)}
	tests := map[string]string{
		"unavailable": `local helper = require("helper")`,
		"dynamic":     `local name = "json"; local helper = require(name)`,
		"aliased":     `local load_module = require; local helper = load_module("json")`,
	}

	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			if err := modules.ValidateSource("@candidate.lua", []byte(source), PolicyProfileEnvironment); err == nil {
				t.Fatal("ValidateSource() accepted non-static module authority")
			}
		})
	}
}

func TestInstallProcessSealsFilesystemLoadersButKeepsInMemoryCompilation(t *testing.T) {
	directory := t.TempDir()
	modulePath := filepath.Join(directory, "process.lua")
	pattern := filepath.Join(directory, "?.lua")

	writeModule(t, modulePath, `return { value = "captured" }`)
	snapshot := captureLuaModuleSnapshot(t, pattern)
	writeModule(t, modulePath, `return { value = "mutated" }`)

	modules, err := CaptureSnapshot([]string{pattern}, snapshot)
	if err != nil {
		t.Fatalf("CaptureSnapshot() error = %v", err)
	}

	state := lua.NewState()
	defer state.Close()

	if err = PrepareProcess(state, modules); err != nil {
		t.Fatalf("PrepareProcess() error = %v", err)
	}

	if err = InstallProcess(state, modules); err != nil {
		t.Fatalf("InstallProcess() error = %v", err)
	}

	if err = state.DoString(`
assert(dofile == nil)
assert(loadfile == nil)
assert(package.path == "")
assert(package.cpath == "")
assert(package.loadlib == nil)
assert(type(load) == "function")
assert(type(loadstring) == "function")
local process = require("process")
assert(process.value == "captured")
`); err != nil {
		t.Fatalf("sealed process module authority: %v", err)
	}
}

func TestInstallProcessRestoresHostPreloadsAndClearsRemovedModules(t *testing.T) {
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

	state.PreloadModule("dynamic_host", processModuleLoader("host"))

	if err = PrepareProcess(state, firstModules); err != nil {
		t.Fatalf("PrepareProcess(first) error = %v", err)
	}

	if err = InstallProcess(state, firstModules); err != nil {
		t.Fatalf("InstallProcess(first) error = %v", err)
	}

	if err = state.DoString(`
assert(require("dynamic_host").value == "host")
assert(require("removed").value == "captured")
package.preload.dynamic_host = function() return { value = "mutated" } end
package.loaded.dynamic_host = nil
package.loaded.removed = { value = "stale" }
`); err != nil {
		t.Fatalf("mutate process package state: %v", err)
	}

	if err = PrepareProcess(state, emptyModules); err != nil {
		t.Fatalf("PrepareProcess(second) error = %v", err)
	}

	if err = InstallProcess(state, emptyModules); err != nil {
		t.Fatalf("InstallProcess(second) error = %v", err)
	}

	if err = state.DoString(`
assert(require("dynamic_host").value == "host")
local ok = pcall(require, "removed")
assert(ok == false)
`); err != nil {
		t.Fatalf("restored process module authority error = %v", err)
	}
}

func TestInstallProcessRefreshesTrustedHostBindingsAfterReset(t *testing.T) {
	state := lua.NewState()
	defer state.Close()

	state.PreloadModule("dynamic_host", processModuleLoader("request"))

	if err := PrepareProcess(state, nil); err != nil {
		t.Fatalf("PrepareProcess(first) error = %v", err)
	}

	if err := InstallProcess(state, nil); err != nil {
		t.Fatalf("InstallProcess(first) error = %v", err)
	}

	if err := state.DoString(`
assert(require("dynamic_host").value == "request")
package.preload.dynamic_host = function() return { value = "script" } end
package.preload.script_only = function() return { value = "script" } end
package.loaded.dynamic_host = nil
`); err != nil {
		t.Fatalf("mutate first process lease: %v", err)
	}

	if err := PrepareProcess(state, nil); err != nil {
		t.Fatalf("PrepareProcess(second) error = %v", err)
	}

	state.PreloadModule("dynamic_host", processModuleLoader("startup"))

	if err := InstallProcess(state, nil); err != nil {
		t.Fatalf("InstallProcess(second) error = %v", err)
	}

	if err := state.DoString(`
assert(require("dynamic_host").value == "startup")
local script_only_ok = pcall(require, "script_only")
assert(script_only_ok == false)
`); err != nil {
		t.Fatalf("second process lease retained stale authority: %v", err)
	}
}

// processModuleLoader returns a host preload with one observable generation value.
func processModuleLoader(value string) lua.LGFunction {
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
