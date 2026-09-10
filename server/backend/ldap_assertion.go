package backend

import (
	"context"
	lua "github.com/yuin/gopher-lua"
)

// LuaLDAPModifyAssert requires an explicit assertion before delegating to the queued modifier.
func LuaLDAPModifyAssert(ctx context.Context) lua.LGFunction {
	modify := LuaLDAPModify(ctx)

	return func(L *lua.LState) int {
		value := L.GetField(L.CheckTable(1), "assertion_filter")

		filter, ok := value.(lua.LString)
		if !ok || filter == "" {
			L.RaiseError("assertion_filter is required")

			return 0
		}

		return modify(L)
	}
}
