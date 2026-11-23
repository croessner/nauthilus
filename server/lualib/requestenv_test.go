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
	"strings"
	"testing"

	lua "github.com/yuin/gopher-lua"
)

// newRequestBindingTestModule creates a module table with the given number of functions.
func newRequestBindingTestModule(L *lua.LState, functions int) *lua.LTable {
	mod := L.NewTable()

	for index := range functions {
		mod.RawSetString(fmt.Sprintf("function_%d", index), L.NewFunction(func(*lua.LState) int { return 0 }))
	}

	return mod
}

// requestBindingFields returns the hidden request fields that a table holds.
func requestBindingFields(tbl *lua.LTable) []string {
	fields := make([]string, 0)

	tbl.ForEach(func(key lua.LValue, _ lua.LValue) {
		if name, ok := key.(lua.LString); ok && strings.HasPrefix(string(name), luaRequestBindingPrefix) {
			fields = append(fields, string(name))
		}
	})

	return fields
}

func TestRequestBindingsReachEnvironmentAndAreScrubbed(t *testing.T) {
	if len(requestBindingKeys) == 0 {
		t.Fatal("expected registered request-binding keys")
	}

	L := lua.NewState()
	defer L.Close()

	req := L.NewTable()
	modules := make([]*lua.LTable, 0, len(requestBindingKeys))

	for index, key := range requestBindingKeys {
		if !strings.HasPrefix(key, luaRequestBindingPrefix) {
			t.Fatalf("binding key %q lacks the request prefix", key)
		}

		mod := newRequestBindingTestModule(L, 3)

		bindRequestValue(L, mod, key, index)
		BindRequestValuesToEnv(L, req, mod)

		bound, ok := req.RawGetString(key).(*lua.LUserData)
		if !ok || bound.Value != index {
			t.Fatalf("expected %q to reach the request environment, got %v", key, req.RawGetString(key))
		}

		modules = append(modules, mod)
	}

	if req.RawGetString(luaRequestModulesKey) == lua.LNil {
		t.Fatal("expected the request environment to track the bound modules")
	}

	ScrubRequestBindings(L, req)

	for _, tbl := range append(modules, req) {
		if left := requestBindingFields(tbl); len(left) != 0 {
			t.Fatalf("expected no request fields after scrubbing, got %v", left)
		}
	}

	for _, mod := range modules {
		if mod.RawGetString("function_0").Type() != lua.LTFunction {
			t.Fatal("expected scrubbing to keep the module functions")
		}
	}
}

func TestRequestBindingCostDoesNotDependOnModuleSize(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	measure := func(functions int) float64 {
		return testing.AllocsPerRun(50, func() {
			req := L.NewTable()
			mod := newRequestBindingTestModule(L, 0)

			for index := range functions {
				mod.RawSetString(requestBindingTestNames[index], lua.LTrue)
			}

			BindRequestRuntimeContext(t.Context(), L, mod)
			BindRequestValuesToEnv(L, req, mod)
			ScrubRequestBindings(L, req)
		})
	}

	small, large := measure(2), measure(len(requestBindingTestNames))

	// Only the field storage of the larger module may add allocations; a scan would add one per field.
	if large-small > 8 {
		t.Fatalf("binding a module with %d fields costs %v allocations, with 2 fields %v", len(requestBindingTestNames), large, small)
	}
}

// requestBindingTestNames holds field names for the allocation test so that building them does not count.
var requestBindingTestNames = func() []string {
	names := make([]string, 64)

	for index := range names {
		names[index] = fmt.Sprintf("field_%d", index)
	}

	return names
}()
