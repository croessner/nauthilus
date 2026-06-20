// Copyright (C) 2026 Christian Roessner
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

const (
	luaFnGetenv       = "getenv"
	luaFnGetRedisKey  = "get_redis_key"
	luaFnIfErrorRaise = "if_error_raise"
	luaFnIsTable      = "is_table"
	luaFnLogInfo      = "log_info"
)

// preloadFixedTimeModule installs a deterministic Lua time module for plugin tests.
func preloadFixedTimeModule(L *lua.LState, formatted string) {
	L.PreloadModule("time", func(L *lua.LState) int {
		mod := L.NewTable()
		mod.RawSetString("unix", L.NewFunction(func(L *lua.LState) int {
			L.Push(lua.LNumber(1700000000))

			return 1
		}))
		mod.RawSetString("format", L.NewFunction(func(L *lua.LState) int {
			L.Push(lua.LString(formatted))

			return 1
		}))
		L.Push(mod)

		return 1
	})
}

// preloadStringFunctionModule installs a module exposing one string-returning function.
func preloadStringFunctionModule(L *lua.LState, moduleName string, functionName string, value string) {
	L.PreloadModule(moduleName, func(L *lua.LState) int {
		mod := L.NewTable()
		mod.RawSetString(functionName, L.NewFunction(func(L *lua.LState) int {
			L.Push(lua.LString(value))

			return 1
		}))
		L.Push(mod)

		return 1
	})
}

// requireLuaTableGlobal returns a global Lua table or fails the current test.
func requireLuaTableGlobal(t luaTestFailer, L *lua.LState, name string) *lua.LTable {
	value := L.GetGlobal(name)

	table, ok := value.(*lua.LTable)
	if !ok {
		t.Fatalf("expected %s table, got %v", name, value.Type())
	}

	return table
}

// luaTestFailer captures the subset of testing.TB used by Lua helper assertions.
type luaTestFailer interface {
	Fatalf(format string, args ...any)
}
