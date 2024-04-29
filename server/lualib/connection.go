package lualib

import (
	"github.com/croessner/nauthilus/server/monitoring"
	lua "github.com/yuin/gopher-lua"
)

func CheckBackendConnection() lua.LGFunction {
	return func(L *lua.LState) int {
		if L.GetTop() != 4 {
			L.RaiseError("Invalid number of arguments. Expected 4, got %d", L.GetTop())

			return 0
		}

		server := L.CheckString(1)
		port := L.CheckInt(2)
		haproxyV2 := L.CheckBool(3)
		tls := L.CheckBool(4)

		if err := monitoring.CheckBackendConnection(server, port, haproxyV2, tls); err != nil {
			L.Push(lua.LString(err.Error()))

			return 1
		}

		L.Push(lua.LNil)

		return 1
	}
}
