package lualib

import (
	"net/http"
	"strings"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-gonic/gin"
	lua "github.com/yuin/gopher-lua"
)

// SetHTTPResponseHeader returns a Lua function that sets (overwrites) an HTTP response header
// Usage from Lua: nauthilus_http_response.set_http_response_header(name, value)
func SetHTTPResponseHeader(ctx *gin.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		name := L.CheckString(1)
		value := L.CheckString(2)
		ctx.Header(name, value)

		return 0
	}
}

// AddHTTPResponseHeader returns a Lua function that adds a value to an HTTP response header
// Usage from Lua: nauthilus_http_response.add_http_response_header(name, value)
func AddHTTPResponseHeader(ctx *gin.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		name := L.CheckString(1)
		value := L.CheckString(2)
		ctx.Writer.Header().Add(name, value)

		return 0
	}
}

// RemoveHTTPResponseHeader returns a Lua function that removes an HTTP response header
// Usage from Lua: nauthilus_http_response.remove_http_response_header(name)
func RemoveHTTPResponseHeader(ctx *gin.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		name := L.CheckString(1)
		ctx.Writer.Header().Del(name)

		return 0
	}
}

// SetHTTPStatus returns a Lua function that sets the HTTP status code for the response
// Usage from Lua: nauthilus_http_response.set_http_status(code)
func SetHTTPStatus(ctx *gin.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		code := L.CheckInt(1)
		ctx.Status(code)

		return 0
	}
}

// WriteHTTPResponseBody returns a Lua function that writes raw data to the HTTP response body
// Usage from Lua: nauthilus_http_response.write_http_response_body(data)
// Note: Set appropriate Content-Type header before writing if needed.
func WriteHTTPResponseBody(ctx *gin.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		data := L.CheckString(1)
		// Do not write body for HEAD requests
		if strings.EqualFold(ctx.Request.Method, http.MethodHead) {
			return 0
		}

		// Use Gin's writer to ensure correct size/accounting
		_, _ = ctx.Writer.Write([]byte(data))

		return 0
	}
}

// SetHTTPContentType returns a Lua function that sets the Content-Type header explicitly
// Usage from Lua: nauthilus_http_response.set_http_content_type(value)
func SetHTTPContentType(ctx *gin.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		value := L.CheckString(1)
		ctx.Header("Content-Type", value)

		return 0
	}
}

// LoaderModHTTPResponse loads Lua functions to interact with the HTTP response using gin.Context.
func LoaderModHTTPResponse(ctx *gin.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnSetHTTPResponseHeader:    SetHTTPResponseHeader(ctx),
			definitions.LuaFnAddHTTPResponseHeader:    AddHTTPResponseHeader(ctx),
			definitions.LuaFnRemoveHTTPResponseHeader: RemoveHTTPResponseHeader(ctx),
			definitions.LuaFnSetHTTPStatus:            SetHTTPStatus(ctx),
			definitions.LuaFnWriteHTTPResponseBody:    WriteHTTPResponseBody(ctx),
			definitions.LuaFnSetHTTPContentType:       SetHTTPContentType(ctx),
		})
		L.Push(mod)
		return 1
	}
}
