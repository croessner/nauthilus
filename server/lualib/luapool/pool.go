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
	resetLuaState(L)

	luaStatePool.Put(L)
}

// resetLuaState resets a Lua state to its initial state.
// This is a best-effort approach since gopher-lua doesn't provide a Reset method.
func resetLuaState(L *lua.LState) {
	// Clear the stack
	L.SetTop(0)

	// Clear the context
	L.SetContext(nil)

	// Clear specific global functions that are defined in Lua scripts
	// These functions need to be reset because they might be redefined in different scripts
	L.SetGlobal(definitions.LuaFnCallFilter, lua.LNil)
	L.SetGlobal(definitions.LuaFnCallFeature, lua.LNil)
	L.SetGlobal(definitions.LuaFnCallAction, lua.LNil)
	L.SetGlobal(definitions.LuaFnCallNeuralNetwork, lua.LNil)

	// Clear the default table which is recreated for each request
	L.SetGlobal(definitions.LuaDefaultTable, lua.LNil)

	// Clear the backend result type metatable which is recreated for each request
	L.SetGlobal(definitions.LuaBackendResultTypeName, lua.LNil)

	// Clear the nauthilus_backend module from the package.loaded table
	// This ensures that the module will be reloaded with fresh data on the next request
	packageTable := L.GetGlobal("package")
	if packageTable.Type() == lua.LTTable {
		loadedTable := L.GetField(packageTable, "loaded")
		if loadedTable.Type() == lua.LTTable {
			L.SetField(loadedTable, definitions.LuaModBackend, lua.LNil)
		}
	}

	// Note: We don't clear the dynamic_loader function or any modules loaded by it
	// as they need to persist between uses of the Lua state from the pool
}
