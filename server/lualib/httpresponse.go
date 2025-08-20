package lualib

import (
	"net/http"

	"github.com/croessner/nauthilus/server/definitions"
	lua "github.com/yuin/gopher-lua"
)

// SetHTTPResponseHeader returns a Lua function that sets (overwrites) an HTTP response header
// Usage from Lua: nauthilus_http_response.set_http_response_header(name, value)
func SetHTTPResponseHeader(w http.ResponseWriter) lua.LGFunction {
	return func(L *lua.LState) int {
		name := L.CheckString(1)
		value := L.CheckString(2)

		w.Header().Set(name, value)

		return 0
	}
}

// AddHTTPResponseHeader returns a Lua function that adds a value to an HTTP response header
// Usage from Lua: nauthilus_http_response.add_http_response_header(name, value)
func AddHTTPResponseHeader(w http.ResponseWriter) lua.LGFunction {
	return func(L *lua.LState) int {
		name := L.CheckString(1)
		value := L.CheckString(2)
		w.Header().Add(name, value)

		return 0
	}
}

// RemoveHTTPResponseHeader returns a Lua function that removes an HTTP response header
// Usage from Lua: nauthilus_http_response.remove_http_response_header(name)
func RemoveHTTPResponseHeader(w http.ResponseWriter) lua.LGFunction {
	return func(L *lua.LState) int {
		name := L.CheckString(1)
		w.Header().Del(name)

		return 0
	}
}

// LoaderModHTTPResponse loads Lua functions to interact with the HTTP response writer
func LoaderModHTTPResponse(w http.ResponseWriter) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnSetHTTPResponseHeader:    SetHTTPResponseHeader(w),
			definitions.LuaFnAddHTTPResponseHeader:    AddHTTPResponseHeader(w),
			definitions.LuaFnRemoveHTTPResponseHeader: RemoveHTTPResponseHeader(w),
		})

		L.Push(mod)

		return 1
	}
}
