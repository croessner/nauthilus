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

package luapool

import (
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	lua "github.com/yuin/gopher-lua"
)

func bindTestModule(L *lua.LState, moduleName, marker string) {
	mod := L.NewTable()
	L.SetField(mod, "marker", lua.LString(marker))

	BindModuleIntoReq(L, moduleName, mod)
}

func TestResetLuaStateClearsRequestBoundLoadedModules(t *testing.T) {
	L := NewLuaState(nil)
	defer L.Close()

	PrepareRequestEnv(L)
	bindTestModule(L, definitions.LuaModContext, "first-request")

	if err := L.DoString(`
		local ctx = require("nauthilus_context")
		if ctx.marker ~= "first-request" then
			error("unexpected initial module marker: " .. tostring(ctx.marker))
		end
	`); err != nil {
		t.Fatalf("initial request setup failed: %v", err)
	}

	ResetLuaState(L)
	PrepareRequestEnv(L)
	bindTestModule(L, definitions.LuaModContext, "second-request")

	pkg := L.GetGlobal("package")
	pkgTable, ok := pkg.(*lua.LTable)
	if !ok {
		t.Fatalf("expected package table, got %T", pkg)
	}

	loaded := L.GetField(pkgTable, "loaded")
	loadedTable, ok := loaded.(*lua.LTable)
	if !ok {
		t.Fatalf("expected package.loaded table, got %T", loaded)
	}

	ctxMod := L.GetField(loadedTable, definitions.LuaModContext)
	ctxTable, ok := ctxMod.(*lua.LTable)
	if !ok {
		t.Fatalf("expected bound context module table, got %T", ctxMod)
	}

	if got := L.GetField(ctxTable, "marker"); got.String() != "second-request" {
		t.Fatalf("stale module marker leaked across reset: %s", got.String())
	}
}
