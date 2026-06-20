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
	"github.com/croessner/nauthilus/v3/server/lualib/luastack"
	lua "github.com/yuin/gopher-lua"
)

// newLuaModuleTable creates a Lua module table from one or more function groups.
func newLuaModuleTable(L *lua.LState, groups ...map[string]lua.LGFunction) *lua.LTable {
	mod := L.NewTable()

	for _, funcs := range groups {
		L.SetFuncs(mod, funcs)
	}

	return mod
}

// pushLuaModuleTable pushes a Lua module table as the loader result.
func pushLuaModuleTable(L *lua.LState, mod *lua.LTable) int {
	stack := luastack.NewManager(L)

	return stack.PushResult(mod)
}

// pushLuaModule builds and pushes a Lua module table in one step.
func pushLuaModule(L *lua.LState, groups ...map[string]lua.LGFunction) int {
	return pushLuaModuleTable(L, newLuaModuleTable(L, groups...))
}
