// Copyright (C) 2025 Christian Rößner
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

// Package luapool provides a pool for reusing Lua states.
package luapool

import (
	lua "github.com/yuin/gopher-lua"
)

// ResetLuaState resets the Lua state between requests by clearing only the
// request environment and transient globals. The base environment and
// preloaded modules remain intact.
func ResetLuaState(L *lua.LState) {
	resetRequestEnv(L)
}
