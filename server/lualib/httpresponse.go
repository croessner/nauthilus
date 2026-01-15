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
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/luastack"

	"github.com/gin-gonic/gin"
	lua "github.com/yuin/gopher-lua"
)

// HTTPResponseManager manages HTTP response operations for Lua.
type HTTPResponseManager struct {
	*BaseManager
	ctx *gin.Context
}

// NewHTTPResponseManager creates a new HTTPResponseManager.
func NewHTTPResponseManager(ctx context.Context, cfg config.File, logger *slog.Logger, ginCtx *gin.Context) *HTTPResponseManager {
	return &HTTPResponseManager{
		BaseManager: NewBaseManager(ctx, cfg, logger),
		ctx:         ginCtx,
	}
}

// SetHTTPResponseHeader sets (overwrites) an HTTP response header.
// Usage from Lua: nauthilus_http_response.set_http_response_header(name, value)
func (m *HTTPResponseManager) SetHTTPResponseHeader(L *lua.LState) int {
	stack := luastack.NewManager(L)
	name := stack.CheckString(1)
	value := stack.CheckString(2)

	m.ctx.Header(name, value)
	m.ctx.Set(definitions.CtxResponseWrittenKey, true)

	return 0
}

// AddHTTPResponseHeader adds a value to an HTTP response header.
// Usage from Lua: nauthilus_http_response.add_http_response_header(name, value)
func (m *HTTPResponseManager) AddHTTPResponseHeader(L *lua.LState) int {
	stack := luastack.NewManager(L)
	name := stack.CheckString(1)
	value := stack.CheckString(2)

	m.ctx.Writer.Header().Add(name, value)
	m.ctx.Set(definitions.CtxResponseWrittenKey, true)

	return 0
}

// RemoveHTTPResponseHeader removes an HTTP response header.
// Usage from Lua: nauthilus_http_response.remove_http_response_header(name)
func (m *HTTPResponseManager) RemoveHTTPResponseHeader(L *lua.LState) int {
	stack := luastack.NewManager(L)
	name := stack.CheckString(1)

	m.ctx.Writer.Header().Del(name)
	m.ctx.Set(definitions.CtxResponseWrittenKey, true)

	return 0
}

// SetHTTPStatus sets the HTTP status code for the response.
// Usage from Lua: nauthilus_http_response.set_http_status(code)
func (m *HTTPResponseManager) SetHTTPStatus(L *lua.LState) int {
	stack := luastack.NewManager(L)
	code := stack.CheckInt(1)

	m.ctx.Status(code)
	m.ctx.Set(definitions.CtxResponseWrittenKey, true)

	return 0
}

// WriteHTTPResponseBody writes raw data to the HTTP response body.
// Usage from Lua: nauthilus_http_response.write_http_response_body(data)
// Note: Set appropriate Content-Type header before writing if needed.
func (m *HTTPResponseManager) WriteHTTPResponseBody(L *lua.LState) int {
	stack := luastack.NewManager(L)
	data := stack.CheckString(1)

	// Do not write body for HEAD requests
	if strings.EqualFold(m.ctx.Request.Method, http.MethodHead) {
		return 0
	}

	// Use Gin's writer to ensure correct size/accounting
	_, _ = m.ctx.Writer.Write([]byte(data))
	m.ctx.Set(definitions.CtxResponseWrittenKey, true)

	return 0
}

// SetHTTPContentType sets the Content-Type header explicitly.
// Usage from Lua: nauthilus_http_response.set_http_content_type(value)
func (m *HTTPResponseManager) SetHTTPContentType(L *lua.LState) int {
	stack := luastack.NewManager(L)
	value := stack.CheckString(1)

	m.ctx.Header("Content-Type", value)
	m.ctx.Set(definitions.CtxResponseWrittenKey, true)

	return 0
}

// HTTPString maps to Gin's ctx.String(status, body).
// Usage from Lua: nauthilus_http_response.string(status_code, body)
func (m *HTTPResponseManager) HTTPString(L *lua.LState) int {
	stack := luastack.NewManager(L)
	status := stack.CheckInt(1)
	body := stack.CheckString(2)

	m.ctx.String(status, body)
	m.ctx.Set(definitions.CtxResponseWrittenKey, true)

	return 0
}

// HTTPData maps to Gin's ctx.Data(status, contentType, data).
// Usage from Lua: nauthilus_http_response.data(status_code, content_type, data)
func (m *HTTPResponseManager) HTTPData(L *lua.LState) int {
	stack := luastack.NewManager(L)
	status := stack.CheckInt(1)
	contentType := stack.CheckString(2)
	data := stack.CheckString(3)

	// Do not write body for HEAD requests
	if strings.EqualFold(m.ctx.Request.Method, http.MethodHead) {
		m.ctx.Status(status)
		m.ctx.Set(definitions.CtxResponseWrittenKey, true)

		return 0
	}

	m.ctx.Data(status, contentType, []byte(data))
	m.ctx.Set(definitions.CtxResponseWrittenKey, true)

	return 0
}

// HTTPHTML sends HTML content (uses Gin's Data with text/html).
// Usage from Lua: nauthilus_http_response.html(status_code, html_string)
func (m *HTTPResponseManager) HTTPHTML(L *lua.LState) int {
	stack := luastack.NewManager(L)
	status := stack.CheckInt(1)
	html := stack.CheckString(2)

	if strings.EqualFold(m.ctx.Request.Method, http.MethodHead) {
		m.ctx.Status(status)
		m.ctx.Set(definitions.CtxResponseWrittenKey, true)

		return 0
	}

	m.ctx.Data(status, "text/html; charset=utf-8", []byte(html))
	m.ctx.Set(definitions.CtxResponseWrittenKey, true)

	return 0
}

// HTTPRedirect maps to Gin's ctx.Redirect(status, location).
// Usage from Lua: nauthilus_http_response.redirect(status_code, location)
func (m *HTTPResponseManager) HTTPRedirect(L *lua.LState) int {
	stack := luastack.NewManager(L)
	status := stack.CheckInt(1)
	location := stack.CheckString(2)

	m.ctx.Redirect(status, location)
	m.ctx.Set(definitions.CtxResponseWrittenKey, true)

	return 0
}

// LoaderModHTTPResponse loads Lua functions to interact with the HTTP response using gin.Context.
func LoaderModHTTPResponse(ctx context.Context, cfg config.File, logger *slog.Logger, ginCtx *gin.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		stack := luastack.NewManager(L)
		manager := NewHTTPResponseManager(ctx, cfg, logger, ginCtx)

		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnSetHTTPResponseHeader:    manager.SetHTTPResponseHeader,
			definitions.LuaFnAddHTTPResponseHeader:    manager.AddHTTPResponseHeader,
			definitions.LuaFnRemoveHTTPResponseHeader: manager.RemoveHTTPResponseHeader,
			definitions.LuaFnSetHTTPStatus:            manager.SetHTTPStatus,
			definitions.LuaFnWriteHTTPResponseBody:    manager.WriteHTTPResponseBody,
			definitions.LuaFnSetHTTPContentType:       manager.SetHTTPContentType,
			definitions.LuaFnHTTPString:               manager.HTTPString,
			definitions.LuaFnHTTPData:                 manager.HTTPData,
			definitions.LuaFnHTTPHTML:                 manager.HTTPHTML,
			definitions.LuaFnHTTPRedirect:             manager.HTTPRedirect,
		})

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

		return stack.PushResult(mod)
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
