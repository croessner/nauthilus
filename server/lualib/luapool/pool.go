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
	"sync"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/util"
	lua "github.com/yuin/gopher-lua"
)

// LuaStatePool is a pool of Lua states that can be reused.
var luaStatePool = sync.Pool{
	New: func() any {
		util.DebugModule(
			definitions.DbgLua,
			definitions.LogKeyMsg, "Creating new Lua state",
		)

		return lua.NewState()
	},
}

// Get returns a Lua state from the pool or creates a new one if the pool is empty.
func Get() *lua.LState {
	return luaStatePool.Get().(*lua.LState)
}

// Put resets the Lua state and returns it to the pool.
func Put(L *lua.LState) {
	if L == nil {
		return
	}

	// Reset the Lua state before returning it to the pool
	ResetLuaState(L)

	luaStatePool.Put(L)
}

// ResetLuaState resets the Lua state between requests by clearing only the
// request environment and transient globals. The base environment and
// preloaded modules remain intact.
func ResetLuaState(L *lua.LState) {
	resetRequestEnv(L)
}
