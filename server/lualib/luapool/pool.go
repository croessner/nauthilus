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

	// Clear the metatable for nil
	L.SetMetatable(lua.LNil, lua.LNil)

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

	// Clear the dynamic_loader function to ensure it's recreated for each request
	L.SetGlobal("dynamic_loader", lua.LNil)

	// Reset the global environment
	newEnv := L.NewTable()
	L.SetGlobal("_G", newEnv)

	// Clear all modules from the package.loaded table
	// This ensures that all modules will be reloaded with fresh data on the next request
	packageTable := L.GetGlobal("package")
	if packageTable.Type() == lua.LTTable {
		loadedTable := L.GetField(packageTable, "loaded")
		if loadedTable.Type() == lua.LTTable {
			// Clear all Nauthilus modules
			L.SetField(loadedTable, definitions.LuaModBackend, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModContext, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModMail, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModPassword, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModRedis, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModMisc, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModLDAP, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModHTTPRequest, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModPrometheus, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModSoftWhitelist, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModBruteForce, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModDNS, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModNeural, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModPsnet, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModCache, lua.LNil)

			// Clear GLua modules
			L.SetField(loadedTable, definitions.LuaModGLuaCrypto, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLuaHTTP, lua.LNil)

			// Clear GLL modules
			L.SetField(loadedTable, definitions.LuaModGLLPlugin, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLArgParse, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLBase64, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLBit, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLHex, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLCertUtil, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLChef, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLCloudWatch, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLCmd, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLCrypto, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLDB, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLFilePath, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLGOOS, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLHTTP, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLHumanize, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLInspect, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLIOUtil, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLJSON, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLLog, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLPb, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLPProf, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLPrometheus, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLRegExp, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLRuntime, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLShellEscape, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLStats, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLStorage, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLStrings, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLTAC, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLTCP, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLTelegram, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLTemplate, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLTime, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLXMLPath, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLYAML, lua.LNil)
			L.SetField(loadedTable, definitions.LuaModGLLZabbix, lua.LNil)

			// Clear non-constant modules that are directly required in Lua scripts
			L.SetField(loadedTable, "nauthilus_util", lua.LNil)
		}
	}
}
