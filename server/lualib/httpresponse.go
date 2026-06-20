// Copyright (C) 2024 Christian Rößner
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

import (
	"net/http"
	"strings"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib/luastack"

	"github.com/gin-gonic/gin"
	lua "github.com/yuin/gopher-lua"
)

// HTTPResponseManager manages HTTP response operations for Lua.
type HTTPResponseManager struct{}

// NewHTTPResponseManager creates a new HTTPResponseManager.
func NewHTTPResponseManager() *HTTPResponseManager {
	return &HTTPResponseManager{}
}

func (m *HTTPResponseManager) currentContext(L *lua.LState) *gin.Context {
	return RequireHTTPResponseContext(L)
}

// useHTTPResponseContext resolves the active Gin context and applies an HTTP response action.
func (m *HTTPResponseManager) useHTTPResponseContext(L *lua.LState, action func(*gin.Context)) int {
	ginCtx := m.currentContext(L)

	if ginCtx == nil {
		L.RaiseError("HTTP response context is nil")

		return 0
	}

	action(ginCtx)

	return 0
}

// writeHTTPResponse runs an action and marks the Lua HTTP response as written.
func (m *HTTPResponseManager) writeHTTPResponse(L *lua.LState, action func(*gin.Context)) int {
	return m.useHTTPResponseContext(L, func(ginCtx *gin.Context) {
		action(ginCtx)
		ginCtx.Set(definitions.CtxResponseWrittenKey, true)
	})
}

// SetHTTPResponseHeader sets (overwrites) an HTTP response header.
// Usage from Lua: nauthilus_http_response.set_http_response_header(name, value)
func (m *HTTPResponseManager) SetHTTPResponseHeader(L *lua.LState) int {
	stack := luastack.NewManager(L)
	name := stack.CheckString(1)
	value := stack.CheckString(2)

	return m.writeHTTPResponse(L, func(ginCtx *gin.Context) {
		ginCtx.Header(name, value)
	})
}

// AddHTTPResponseHeader adds a value to an HTTP response header.
// Usage from Lua: nauthilus_http_response.add_http_response_header(name, value)
func (m *HTTPResponseManager) AddHTTPResponseHeader(L *lua.LState) int {
	stack := luastack.NewManager(L)
	name := stack.CheckString(1)
	value := stack.CheckString(2)

	return m.writeHTTPResponse(L, func(ginCtx *gin.Context) {
		ginCtx.Writer.Header().Add(name, value)
	})
}

// RemoveHTTPResponseHeader removes an HTTP response header.
// Usage from Lua: nauthilus_http_response.remove_http_response_header(name)
func (m *HTTPResponseManager) RemoveHTTPResponseHeader(L *lua.LState) int {
	stack := luastack.NewManager(L)
	name := stack.CheckString(1)

	return m.writeHTTPResponse(L, func(ginCtx *gin.Context) {
		ginCtx.Writer.Header().Del(name)
	})
}

// SetHTTPStatus sets the HTTP status code for the response.
// Usage from Lua: nauthilus_http_response.set_http_status(code)
func (m *HTTPResponseManager) SetHTTPStatus(L *lua.LState) int {
	stack := luastack.NewManager(L)
	code := stack.CheckInt(1)

	return m.writeHTTPResponse(L, func(ginCtx *gin.Context) {
		ginCtx.Status(code)
	})
}

// WriteHTTPResponseBody writes raw data to the HTTP response body.
// Usage from Lua: nauthilus_http_response.write_http_response_body(data)
// Note: Set appropriate Content-Type header before writing if needed.
func (m *HTTPResponseManager) WriteHTTPResponseBody(L *lua.LState) int {
	stack := luastack.NewManager(L)
	data := stack.CheckString(1)

	return m.useHTTPResponseContext(L, func(ginCtx *gin.Context) {
		// Do not write body for HEAD requests
		if strings.EqualFold(ginCtx.Request.Method, http.MethodHead) {
			return
		}

		// Use Gin's writer to ensure correct size/accounting
		_, _ = ginCtx.Writer.Write([]byte(data))
		ginCtx.Set(definitions.CtxResponseWrittenKey, true)
	})
}

// SetHTTPContentType sets the Content-Type header explicitly.
// Usage from Lua: nauthilus_http_response.set_http_content_type(value)
func (m *HTTPResponseManager) SetHTTPContentType(L *lua.LState) int {
	stack := luastack.NewManager(L)
	value := stack.CheckString(1)

	return m.writeHTTPResponse(L, func(ginCtx *gin.Context) {
		ginCtx.Header("Content-Type", value)
	})
}

// HTTPString maps to Gin's ctx.String(status, body).
// Usage from Lua: nauthilus_http_response.string(status_code, body)
func (m *HTTPResponseManager) HTTPString(L *lua.LState) int {
	stack := luastack.NewManager(L)
	status := stack.CheckInt(1)
	body := stack.CheckString(2)

	return m.writeHTTPResponse(L, func(ginCtx *gin.Context) {
		ginCtx.String(status, body)
	})
}

// HTTPData maps to Gin's ctx.Data(status, contentType, data).
// Usage from Lua: nauthilus_http_response.data(status_code, content_type, data)
func (m *HTTPResponseManager) HTTPData(L *lua.LState) int {
	stack := luastack.NewManager(L)
	status := stack.CheckInt(1)
	contentType := stack.CheckString(2)
	data := stack.CheckString(3)

	return m.writeHTTPResponse(L, func(ginCtx *gin.Context) {
		// Do not write body for HEAD requests
		if strings.EqualFold(ginCtx.Request.Method, http.MethodHead) {
			ginCtx.Status(status)

			return
		}

		ginCtx.Data(status, contentType, []byte(data))
	})
}

// HTTPHTML sends HTML content (uses Gin's Data with text/html).
// Usage from Lua: nauthilus_http_response.html(status_code, html_string)
func (m *HTTPResponseManager) HTTPHTML(L *lua.LState) int {
	stack := luastack.NewManager(L)
	status := stack.CheckInt(1)
	html := stack.CheckString(2)

	return m.writeHTTPResponse(L, func(ginCtx *gin.Context) {
		if strings.EqualFold(ginCtx.Request.Method, http.MethodHead) {
			ginCtx.Status(status)

			return
		}

		ginCtx.Data(status, "text/html; charset=utf-8", []byte(html))
	})
}

// HTTPRedirect maps to Gin's ctx.Redirect(status, location).
// Usage from Lua: nauthilus_http_response.redirect(status_code, location)
func (m *HTTPResponseManager) HTTPRedirect(L *lua.LState) int {
	stack := luastack.NewManager(L)
	status := stack.CheckInt(1)
	location := stack.CheckString(2)

	return m.writeHTTPResponse(L, func(ginCtx *gin.Context) {
		ginCtx.Redirect(status, location)
	})
}

// LoaderModHTTPResponse loads Lua functions to interact with the HTTP response using gin.Context.
func LoaderModHTTPResponse(ctx *gin.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		stack := luastack.NewManager(L)
		manager := NewHTTPResponseManager()

		mod := newLuaModuleTable(L, httpHeaderFunctions(manager), httpBodyFunctions(manager))

		// Expose essential HTTP status codes as UPPER_CASE module variables
		statusCodes := map[string]int{
			"STATUS_OK":                     200,
			"STATUS_CREATED":                201,
			"STATUS_NO_CONTENT":             204,
			"STATUS_MOVED_PERMANENTLY":      301,
			"STATUS_FOUND":                  302,
			"STATUS_SEE_OTHER":              303,
			"STATUS_NOT_MODIFIED":           304,
			"STATUS_BAD_REQUEST":            400,
			"STATUS_UNAUTHORIZED":           401,
			"STATUS_FORBIDDEN":              403,
			"STATUS_NOT_FOUND":              404,
			"STATUS_METHOD_NOT_ALLOWED":     405,
			"STATUS_CONFLICT":               409,
			"STATUS_UNSUPPORTED_MEDIA_TYPE": 415,
			"STATUS_TOO_MANY_REQUESTS":      429,
			"STATUS_INTERNAL_SERVER_ERROR":  500,
			"STATUS_NOT_IMPLEMENTED":        501,
			"STATUS_BAD_GATEWAY":            502,
			"STATUS_SERVICE_UNAVAILABLE":    503,
			"STATUS_GATEWAY_TIMEOUT":        504,
		}

		for k, v := range statusCodes {
			mod.RawSetString(k, lua.LNumber(v))
		}

		if ctx != nil {
			bindRequestValue(L, mod, luaHTTPResponseContextKey, ctx)
		}

		return stack.PushResult(mod)
	}
}

// httpHeaderFunctions returns Lua functions that mutate HTTP response headers and status.
func httpHeaderFunctions(manager *HTTPResponseManager) map[string]lua.LGFunction {
	return map[string]lua.LGFunction{
		definitions.LuaFnSetHTTPResponseHeader:    manager.SetHTTPResponseHeader,
		definitions.LuaFnAddHTTPResponseHeader:    manager.AddHTTPResponseHeader,
		definitions.LuaFnRemoveHTTPResponseHeader: manager.RemoveHTTPResponseHeader,
		definitions.LuaFnSetHTTPStatus:            manager.SetHTTPStatus,
		definitions.LuaFnSetHTTPContentType:       manager.SetHTTPContentType,
	}
}

// httpBodyFunctions returns Lua functions that write HTTP response bodies.
func httpBodyFunctions(manager *HTTPResponseManager) map[string]lua.LGFunction {
	return map[string]lua.LGFunction{
		definitions.LuaFnWriteHTTPResponseBody: manager.WriteHTTPResponseBody,
		definitions.LuaFnHTTPString:            manager.HTTPString,
		definitions.LuaFnHTTPData:              manager.HTTPData,
		definitions.LuaFnHTTPHTML:              manager.HTTPHTML,
		definitions.LuaFnHTTPRedirect:          manager.HTTPRedirect,
	}
}

// LoaderHTTPResponseStateless returns an empty, stateless module table for nauthilus_http_response.
// It is intended to be preloaded once per VM (base environment). Per-request bindings will later
// clone this table and inject bound functions via WithCtx factories.
func LoaderHTTPResponseStateless() lua.LGFunction {
	return func(L *lua.LState) int {
		stack := luastack.NewManager(L)

		return stack.PushResult(L.NewTable())
	}
}
