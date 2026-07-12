// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package lualib

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v3/server/definitions"

	lua "github.com/yuin/gopher-lua"
)

func TestPolicyFactsEmitManyPrefersBatchWithLegacyFallback(t *testing.T) {
	tests := []struct {
		name        string
		batchAPI    bool
		wantBatch   int
		wantSingles int
	}{
		{name: "BatchAPI", batchAPI: true, wantBatch: 1},
		{name: "LegacyFallback", wantSingles: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			L := lua.NewState()
			defer L.Close()

			batchCalls := 0
			singleCalls := 0

			preloadPolicyFactsContext(L)
			preloadPolicyFactsEmitter(L, tt.batchAPI, &batchCalls, &singleCalls)

			helperPath := filepath.Join("..", "lua-plugins.d", "share", "nauthilus_policy_facts.lua")
			if err := L.DoString(fmt.Sprintf("policy_facts = dofile(%q)", helperPath)); err != nil {
				t.Fatalf("loading policy facts helper failed: %v", err)
			}

			if err := L.DoString(`policy_facts.emit_many("batch", { triggered = true, count = 12 })`); err != nil {
				t.Fatalf("emit_many failed: %v", err)
			}

			if batchCalls != tt.wantBatch || singleCalls != tt.wantSingles {
				t.Fatalf("emitter calls = batch:%d single:%d, want batch:%d single:%d", batchCalls, singleCalls, tt.wantBatch, tt.wantSingles)
			}
		})
	}
}

// preloadPolicyFactsContext installs the minimum context API used by the shared helper.
func preloadPolicyFactsContext(L *lua.LState) {
	L.PreloadModule(definitions.LuaModContext, func(L *lua.LState) int {
		mod := L.NewTable()
		mod.RawSetString("context_get", L.NewFunction(func(L *lua.LState) int {
			L.Push(lua.LNil)

			return 1
		}))
		mod.RawSetString("context_set", L.NewFunction(func(_ *lua.LState) int {
			return 0
		}))
		L.Push(mod)

		return 1
	})
}

// preloadPolicyFactsEmitter installs either the batch API or its legacy single-emission surface.
func preloadPolicyFactsEmitter(L *lua.LState, batchAPI bool, batchCalls *int, singleCalls *int) {
	L.PreloadModule(definitions.LuaModPolicy, func(L *lua.LState) int {
		mod := L.NewTable()
		mod.RawSetString(definitions.LuaFnPolicyEmitAttribute, L.NewFunction(func(_ *lua.LState) int {
			*singleCalls++

			return 0
		}))

		if batchAPI {
			mod.RawSetString(definitions.LuaFnPolicyEmitAttributes, L.NewFunction(func(_ *lua.LState) int {
				*batchCalls++

				return 0
			}))
		}

		L.Push(mod)

		return 1
	})
}
