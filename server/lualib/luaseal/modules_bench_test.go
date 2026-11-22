// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package luaseal

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"

	lua "github.com/yuin/gopher-lua"
)

// BenchmarkSearcherResolvesBundledShareModules measures what one request pays to resolve the bundled shared modules
// through the sealed searcher, without executing them.
func BenchmarkSearcherResolvesBundledShareModules(b *testing.B) {
	pattern := filepath.Join("..", "..", "lua-plugins.d", "share", "?.lua")

	snapshot, err := config.CaptureArtifactSnapshot(config.ArtifactSnapshotSpec{LuaPackagePatterns: []string{pattern}})
	if err != nil {
		b.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	b.Cleanup(snapshot.Release)

	modules, err := CaptureSnapshot([]string{pattern}, snapshot)
	if err != nil {
		b.Fatalf("CaptureSnapshot() error = %v", err)
	}

	names := make([]string, 0, len(modules.entries))
	for name := range modules.entries {
		names = append(names, name)
	}

	sort.Strings(names)

	if len(names) == 0 {
		b.Fatal("no bundled shared modules were captured")
	}

	state := lua.NewState()
	defer state.Close()

	searcher := state.NewFunction(modules.searcher)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		for _, name := range names {
			if err = state.CallByParam(lua.P{Fn: searcher, NRet: 1, Protect: true}, lua.LString(name)); err != nil {
				b.Fatalf("resolve %q: %v", name, err)
			}

			if state.Get(-1).Type() != lua.LTFunction {
				b.Fatalf("resolve %q returned %s", name, state.Get(-1).Type())
			}

			state.Pop(1)
		}
	}
}
