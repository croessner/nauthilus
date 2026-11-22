// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package luaseal captures external Lua modules and installs immutable loaders.
//
// The package owns module identity only: every runtime resolves require() from host preloads and from the
// module bytes captured with its configuration candidate. It does not restrict the Lua API of any runtime.
package luaseal

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/croessner/nauthilus/v4/server/config"

	lua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/parse"
)

const (
	maximumModuleCount         = 1024
	maximumModuleSize          = 4 << 20
	maximumTotalSize           = 32 << 20
	preloadBaselineRegistryKey = "_NAUTHILUS_SEALED_PRELOADS"
	preparedRegistryKey        = "_NAUTHILUS_SEALED_PREPARED"
	luaGlobalName              = "_G"
)

var standardLoadedNames = map[string]struct{}{
	luaGlobalName:        {},
	lua.LoadLibName:      {},
	lua.TabLibName:       {},
	lua.StringLibName:    {},
	lua.MathLibName:      {},
	lua.CoroutineLibName: {},
	lua.IoLibName:        {},
	lua.OsLibName:        {},
	lua.DebugLibName:     {},
	lua.ChannelLibName:   {},
}

type capturedModule struct {
	source []byte
	name   string
}

// Modules is an immutable snapshot of external Lua package membership and bytes.
type Modules struct {
	entries map[string]capturedModule
}

// Mentions reports whether any captured module source contains the given text.
func (m *Modules) Mentions(text string) bool {
	if m == nil || text == "" {
		return false
	}

	needle := []byte(text)

	for _, module := range m.entries {
		if bytes.Contains(module.source, needle) {
			return true
		}
	}

	return false
}

// CaptureSnapshot compiles every module from the candidate's single immutable artifact snapshot.
func CaptureSnapshot(patterns []string, snapshot *config.ArtifactSnapshot) (*Modules, error) {
	modules := &Modules{entries: make(map[string]capturedModule)}

	if snapshot == nil {
		return nil, fmt.Errorf("capture Lua modules: artifact snapshot is unavailable")
	}

	totalSize := 0

	for _, rawPattern := range patterns {
		pattern := strings.TrimSpace(rawPattern)
		if pattern == "" {
			continue
		}

		files, err := snapshot.FilesForLuaPackagePattern(pattern)
		if err != nil {
			return nil, fmt.Errorf("open captured Lua module pattern %q: %w", pattern, err)
		}

		if err = capturePattern(modules, filepath.Clean(pattern), files, &totalSize); err != nil {
			return nil, err
		}
	}

	return modules, nil
}

// capturePattern adds first-match module entries from one captured deterministic path pattern.
func capturePattern(
	modules *Modules,
	pattern string,
	files []config.ArtifactFile,
	totalSize *int,
) error {
	defer clearArtifactFiles(files)

	if strings.Count(pattern, "?") != 1 {
		return fmt.Errorf("lua module pattern %q must contain exactly one placeholder", pattern)
	}

	marker := strings.IndexByte(pattern, '?')
	prefix := pattern[:marker]
	suffix := pattern[marker+1:]

	for _, file := range files {
		path := filepath.Clean(file.Path)
		if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
			return fmt.Errorf("captured Lua module %q does not match pattern %q", path, pattern)
		}

		middle := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)

		moduleName := moduleNameFromPath(middle)
		if moduleName == "" {
			continue
		}

		if _, exists := modules.entries[moduleName]; exists {
			continue
		}

		if len(modules.entries) >= maximumModuleCount {
			return fmt.Errorf("lua module snapshot exceeds %d entries", maximumModuleCount)
		}

		source := file.Content
		if len(source) == 0 || len(source) > maximumModuleSize || *totalSize+len(source) > maximumTotalSize {
			return fmt.Errorf("lua module %q has an invalid snapshot size", path)
		}

		if _, err := compileModule(path, source); err != nil {
			return fmt.Errorf("compile Lua module %q: %w", path, err)
		}

		*totalSize += len(source)
		modules.entries[moduleName] = capturedModule{
			name: moduleName, source: append([]byte(nil), source...),
		}
	}

	return nil
}

// clearArtifactFiles erases detached snapshot clones after module compilation.
func clearArtifactFiles(files []config.ArtifactFile) {
	for index := range files {
		clear(files[index].Content)
		files[index].Content = nil
	}
}

// moduleNameFromPath converts the package placeholder portion into require vocabulary.
func moduleNameFromPath(value string) string {
	value = strings.Trim(filepath.ToSlash(value), "/")
	if value == "" {
		return ""
	}

	return strings.ReplaceAll(value, "/", ".")
}

// Prepare restores the previous trusted host preload set before current host bindings are installed.
//
// Every Lua runtime calls it on a leased VM before binding request modules: custom hooks, Lua backends, the
// cache-flush script, environment sources, subject sources, and actions.
func Prepare(state *lua.LState, modules *Modules) error {
	packageTable, loaded, err := installSealedSearchers(state, modules)
	if err != nil {
		return err
	}

	if err = restorePreloads(state, packageTable); err != nil {
		return err
	}

	clearStaleModules(loaded)
	state.SetField(state.Get(lua.RegistryIndex), preparedRegistryKey, lua.LTrue)

	return nil
}

// Install captures current host bindings and seals module authority for script execution.
func Install(state *lua.LState, modules *Modules) error {
	if state == nil {
		return fmt.Errorf("lua state is unavailable")
	}

	registry := state.Get(lua.RegistryIndex)
	if state.GetField(registry, preparedRegistryKey) != lua.LTrue {
		return fmt.Errorf("lua state was not prepared before host binding")
	}

	packageTable, _, err := installSealedSearchers(state, modules)
	if err != nil {
		return err
	}

	preloads, ok := state.GetField(packageTable, "preload").(*lua.LTable)
	if !ok {
		return fmt.Errorf("lua package preload table is unavailable")
	}

	state.SetField(registry, preloadBaselineRegistryKey, cloneLuaTable(state, preloads))
	state.SetField(registry, "_PRELOAD", preloads)
	state.SetField(registry, preparedRegistryKey, lua.LNil)

	return nil
}

// restorePreloads resets script mutations while retaining the VM's host-installed preload surface.
func restorePreloads(state *lua.LState, packageTable *lua.LTable) error {
	registry := state.Get(lua.RegistryIndex)

	baseline, hasBaseline := state.GetField(registry, preloadBaselineRegistryKey).(*lua.LTable)
	if !hasBaseline {
		current, ok := state.GetField(packageTable, "preload").(*lua.LTable)
		if !ok {
			return fmt.Errorf("lua package preload table is unavailable")
		}

		state.SetField(registry, preloadBaselineRegistryKey, cloneLuaTable(state, current))

		return nil
	}

	restored := cloneLuaTable(state, baseline)
	state.SetField(packageTable, "preload", restored)
	state.SetField(registry, "_PRELOAD", restored)

	return nil
}

// cloneLuaTable copies one flat host-owned loader table into a detached Lua table.
func cloneLuaTable(state *lua.LState, source *lua.LTable) *lua.LTable {
	cloned := state.NewTable()

	source.ForEach(func(key lua.LValue, value lua.LValue) {
		cloned.RawSet(key, value)
	})

	return cloned
}

// clearStaleModules drops every loaded module except the standard libraries.
//
// Host modules and captured modules load again through the preload table and the snapshot searcher of the current
// lease, so no module table of an earlier request stays reachable through require.
func clearStaleModules(loaded *lua.LTable) {
	if loaded == nil {
		return
	}

	stale := make([]lua.LValue, 0)

	loaded.ForEach(func(key lua.LValue, _ lua.LValue) {
		if name, ok := key.(lua.LString); ok {
			if _, standard := standardLoadedNames[string(name)]; standard {
				return
			}
		}

		stale = append(stale, key)
	})

	for _, key := range stale {
		loaded.RawSet(key, lua.LNil)
	}
}

// installSealedSearchers replaces every filesystem searcher with preload and snapshot owners.
//
// Only module resolution is sealed. The package search paths stay empty because require() never reads the
// filesystem; dofile, loadfile, and every other library function remain available to the script.
func installSealedSearchers(
	state *lua.LState,
	modules *Modules,
) (*lua.LTable, *lua.LTable, error) {
	if state == nil {
		return nil, nil, fmt.Errorf("lua state is unavailable")
	}

	if modules == nil {
		modules = &Modules{entries: make(map[string]capturedModule)}
	}

	packageTable, ok := state.GetGlobal(lua.LoadLibName).(*lua.LTable)
	if !ok {
		return nil, nil, fmt.Errorf("lua package table is unavailable")
	}

	loaders, ok := state.GetField(state.Get(lua.RegistryIndex), "_LOADERS").(*lua.LTable)
	if !ok {
		return nil, nil, fmt.Errorf("lua package loaders are unavailable")
	}

	preload := loaders.RawGetInt(1)
	if preload.Type() != lua.LTFunction {
		return nil, nil, fmt.Errorf("lua preload searcher is unavailable")
	}

	sealedLoaders := state.NewTable()
	sealedLoaders.RawSetInt(1, preload)
	sealedLoaders.RawSetInt(2, state.NewFunction(modules.searcher))
	state.SetField(packageTable, "loaders", sealedLoaders)
	state.SetField(packageTable, "searchers", sealedLoaders)
	state.SetField(state.Get(lua.RegistryIndex), "_LOADERS", sealedLoaders)
	state.SetField(packageTable, "path", lua.LString(""))
	state.SetField(packageTable, "cpath", lua.LString(""))

	loaded, _ := state.GetField(state.Get(lua.RegistryIndex), "_LOADED").(*lua.LTable)
	if loaded != nil {
		for name := range modules.entries {
			state.SetField(loaded, name, lua.LNil)
		}
	}

	return packageTable, loaded, nil
}

// searcher returns a loader compiled only from candidate-captured module bytes.
func (m *Modules) searcher(state *lua.LState) int {
	name := state.CheckString(1)

	module, exists := m.entries[name]
	if !exists {
		state.Push(lua.LString(fmt.Sprintf("no captured Lua module %q", name)))

		return 1
	}

	prototype, err := compileModule("@captured-module/"+module.name, module.source)
	if err != nil {
		state.RaiseError("captured Lua module %q is invalid: %v", name, err)

		return 0
	}

	state.Push(state.NewFunctionFromProto(prototype))

	return 1
}

// compileModule compiles one detached module copy without accessing the filesystem.
func compileModule(name string, source []byte) (*lua.FunctionProto, error) {
	chunk, err := parse.Parse(bytes.NewReader(source), name)
	if err != nil {
		return nil, err
	}

	return lua.Compile(chunk, name)
}
