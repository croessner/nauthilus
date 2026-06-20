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

import lua "github.com/yuin/gopher-lua"

// preloadInMemoryContextModule installs a small request-context module for Lua tests.
func preloadInMemoryContextModule(L *lua.LState) {
	L.PreloadModule("nauthilus_context", func(L *lua.LState) int {
		state := map[string]lua.LValue{}
		mod := L.NewTable()

		mod.RawSetString("context_get", L.NewFunction(func(L *lua.LState) int {
			if value, ok := state[L.CheckString(1)]; ok {
				L.Push(value)
			} else {
				L.Push(lua.LNil)
			}

			return 1
		}))

		mod.RawSetString("context_set", L.NewFunction(func(L *lua.LState) int {
			state[L.CheckString(1)] = L.CheckAny(2)

			return 0
		}))

		L.Push(mod)

		return 1
	})
}
