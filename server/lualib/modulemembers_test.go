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
	"testing"

	lua "github.com/yuin/gopher-lua"
)

const moduleMembersTestKey = "module_members_test"

// moduleMembersTestOwner is a comparable collaborator for the member cache tests.
type moduleMembersTestOwner struct {
	name string
}

// countingModuleBuilder returns a builder that reports how often it ran and decorates each built table.
func countingModuleBuilder(L *lua.LState, builds *int, decorate func(*lua.LTable)) ModuleBuilder {
	return func() *lua.LTable {
		*builds++

		built := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			"first":  func(*lua.LState) int { return 0 },
			"second": func(*lua.LState) int { return 0 },
		})
		built.RawSetString("answer", lua.LNumber(42))

		if decorate != nil {
			decorate(built)
		}

		return built
	}
}

func TestRequestModuleTablesShareMembersButNotState(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	builds := 0
	build := countingModuleBuilder(L, &builds, nil)

	first := NewRequestModule(L, moduleMembersTestKey, 1, build)
	second := NewRequestModule(L, moduleMembersTestKey, 1, build)

	if builds != 1 {
		t.Fatalf("expected the members to be built once, got %d builds", builds)
	}

	if first == second {
		t.Fatal("expected every request to receive its own module table")
	}

	if first.RawGetString("first") != second.RawGetString("first") {
		t.Fatal("expected both tables to hold the same function")
	}

	// What one request does to its table must not reach the table of another request.
	first.RawSetString("first", lua.LNil)
	first.RawSetString("leak", lua.LString("request data"))
	first.RawSetString("answer", lua.LNumber(1))

	third := NewRequestModule(L, moduleMembersTestKey, 1, build)

	for _, table := range []*lua.LTable{second, third} {
		if table.RawGetString("first").Type() != lua.LTFunction {
			t.Fatal("expected the function removed by another request to be present")
		}

		if table.RawGetString("leak") != lua.LNil {
			t.Fatal("expected a field added by another request to be absent")
		}

		if table.RawGetString("answer") != lua.LNumber(42) {
			t.Fatalf("expected the original constant, got %v", table.RawGetString("answer"))
		}
	}
}

func TestRequestModuleRebuildsForOtherOwners(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	builds := 0
	build := countingModuleBuilder(L, &builds, nil)
	firstOwner := &moduleMembersTestOwner{name: "first"}
	secondOwner := &moduleMembersTestOwner{name: "second"}

	NewRequestModule(L, moduleMembersTestKey, 0, build, firstOwner, nil)
	NewRequestModule(L, moduleMembersTestKey, 0, build, firstOwner, nil)

	if builds != 1 {
		t.Fatalf("expected one build for the same owners, got %d", builds)
	}

	NewRequestModule(L, moduleMembersTestKey, 0, build, secondOwner, nil)
	NewRequestModule(L, moduleMembersTestKey, 0, build, secondOwner)

	if builds != 3 {
		t.Fatalf("expected a build for every other owner set, got %d", builds)
	}

	// An owner that cannot be compared never matches: the module is built again instead of being reused.
	NewRequestModule(L, moduleMembersTestKey, 0, build, []string{"uncomparable"})
	NewRequestModule(L, moduleMembersTestKey, 0, build, []string{"uncomparable"})

	if builds != 5 {
		t.Fatalf("expected a build for every uncomparable owner, got %d", builds)
	}
}

func TestRequestModuleWithMutableMemberIsBuiltPerRequest(t *testing.T) {
	cases := map[string]func(*lua.LState, *lua.LTable){
		"nested table": func(L *lua.LState, built *lua.LTable) {
			built.RawSetString("nested", L.NewTable())
		},
		"lua function": func(L *lua.LState, built *lua.LTable) {
			fn, err := L.LoadString("return 1")
			if err != nil {
				panic(err)
			}

			built.RawSetString("chunk", fn)
		},
		"go closure with upvalue": func(L *lua.LState, built *lua.LTable) {
			built.RawSetString("closure", L.NewClosure(func(*lua.LState) int { return 0 }, lua.LNumber(1)))
		},
		"userdata with metatable": func(L *lua.LState, built *lua.LTable) {
			object := L.NewUserData()
			object.Metatable = L.NewTable()

			built.RawSetString("object", object)
		},
		"metatable": func(L *lua.LState, built *lua.LTable) {
			L.SetMetatable(built, L.NewTable())
		},
		"numeric key": func(_ *lua.LState, built *lua.LTable) {
			built.RawSetInt(1, lua.LTrue)
		},
	}

	for name, decorate := range cases {
		t.Run(name, func(t *testing.T) {
			L := lua.NewState()
			defer L.Close()

			builds := 0
			build := countingModuleBuilder(L, &builds, func(built *lua.LTable) { decorate(L, built) })

			first := NewRequestModule(L, moduleMembersTestKey, 0, build)
			second := NewRequestModule(L, moduleMembersTestKey, 0, build)

			if builds != 2 {
				t.Fatalf("expected a build per request, got %d", builds)
			}

			if first == second {
				t.Fatal("expected separate module tables")
			}
		})
	}
}

func TestRequestModuleKeepsOpaqueSentinel(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	_ = LoaderModCBOR()(L)
	first := L.Get(-1).(*lua.LTable)
	_ = LoaderModCBOR()(L)
	second := L.Get(-1).(*lua.LTable)

	L.Pop(2)

	if first == second {
		t.Fatal("expected separate module tables")
	}

	if _, ok := first.RawGetString("null").(*lua.LUserData); !ok {
		t.Fatalf("expected the null sentinel, got %T", first.RawGetString("null"))
	}

	if first.RawGetString("null") != second.RawGetString("null") {
		t.Fatal("expected one null sentinel per VM")
	}
}

func TestRequestModuleCostDoesNotDependOnMemberCount(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	builds := 0
	build := countingModuleBuilder(L, &builds, nil)

	NewRequestModule(L, moduleMembersTestKey, 1, build)

	allocations := testing.AllocsPerRun(100, func() {
		NewRequestModule(L, moduleMembersTestKey, 1, build)
	})

	// One table and its field storage: no function objects and no intermediate maps.
	if allocations > 2 {
		t.Fatalf("expected at most 2 allocations per request module, got %v", allocations)
	}
}
