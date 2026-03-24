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
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/luastack"
	"github.com/croessner/nauthilus/server/util"

	lua "github.com/yuin/gopher-lua"
)

// HTTPRequestMeta is a thin abstraction over HTTP request data needed by Lua HTTP module.
// It allows sources other than *http.Request while keeping behavior identical for Lua code.
type HTTPRequestMeta interface {
	Header() http.Header
	Method() string
	URL() *url.URL
	Body() io.ReadCloser
	SetBody(io.ReadCloser)
}

// httpRequestMeta wraps a real *http.Request
type httpRequestMeta struct{ req *http.Request }

func NewHTTPMetaFromRequest(req *http.Request) HTTPRequestMeta { return &httpRequestMeta{req: req} }

// Header returns the HTTP headers of the wrapped HTTP request. If the request is nil, an empty header is returned.
func (m *httpRequestMeta) Header() http.Header {
	if m.req != nil {
		return m.req.Header
	}

	return http.Header{}
}

// Method returns the HTTP method of the wrapped HTTP request. If the request is nil, an empty string is returned.
func (m *httpRequestMeta) Method() string {
	if m.req != nil {
		return m.req.Method
	}

	return ""
}

// URL retrieves the URL of the wrapped HTTP request. Returns an empty URL if the request is nil.
func (m *httpRequestMeta) URL() *url.URL {
	if m.req != nil {
		return m.req.URL
	}

	return &url.URL{}
}

// Body returns the body of the wrapped HTTP request as an io.ReadCloser. Returns an empty reader if the request is nil or has no body.
func (m *httpRequestMeta) Body() io.ReadCloser {
	if m.req != nil && m.req.Body != nil {
		return m.req.Body
	}

	return io.NopCloser(strings.NewReader(""))
}

// SetBody sets the body of the wrapped HTTP request to the provided io.ReadCloser if the request is not nil.
func (m *httpRequestMeta) SetBody(r io.ReadCloser) {
	if m.req != nil {
		m.req.Body = r
	}
}

var _ HTTPRequestMeta = (*httpRequestMeta)(nil)

// HTTPRequestManager manages HTTP request data needed by Lua.
type HTTPRequestManager struct{}

// NewHTTPRequestManager creates a new HTTPRequestManager.
func NewHTTPRequestManager() *HTTPRequestManager {

	return &HTTPRequestManager{}
}

func (m *HTTPRequestManager) currentMeta(L *lua.LState) HTTPRequestMeta {
	return RequireHTTPRequestMeta(L)
}

// GetAllHTTPRequestHeaders retrieves all headers from an HTTP request.
// The returned function accepts no arguments and pushes a Lua table where header names are keys and values are lists.
func (m *HTTPRequestManager) GetAllHTTPRequestHeaders(L *lua.LState) int {
	stack := luastack.NewManager(L)
	headerTable := L.NewTable()
	meta := m.currentMeta(L)

	for headerName, headerValues := range meta.Header() {
		headerName = strings.ToLower(headerName)

		headerList := L.NewTable()

		for _, headerValue := range headerValues {
			headerList.Append(lua.LString(headerValue))
		}

		headerTable.RawSetString(headerName, headerList)
	}

	return stack.PushResults(headerTable, lua.LNil)
}

// GetHTTPRequestHeader retrieves specific HTTP request header values as a Lua table.
// The function expects one argument: the name of the header to retrieve (case-insensitive).
// It returns a Lua table containing the header values or an empty table if the header is not present.
func (m *HTTPRequestManager) GetHTTPRequestHeader(L *lua.LState) int {
	stack := luastack.NewManager(L)
	reqzestedHeader := strings.ToLower(stack.CheckString(1))
	headerValueTable := L.NewTable()
	meta := m.currentMeta(L)

	for headerName, headerValues := range meta.Header() {
		headerName = strings.ToLower(headerName)

		if headerName != reqzestedHeader {
			continue
		}

		for _, headerValue := range headerValues {
			headerValueTable.Append(lua.LString(headerValue))
		}

		break
	}

	return stack.PushResults(headerValueTable, lua.LNil)
}

// GetHTTPRequestBody retrieves the body of an HTTP request as a Lua string.
// The returned function reads the HTTP request body, resets it for potential later use, and pushes it as a string to Lua.
func (m *HTTPRequestManager) GetHTTPRequestBody(L *lua.LState) int {
	stack := luastack.NewManager(L)
	meta := m.currentMeta(L)

	// Read the HTTP body
	bodyBytes, err := io.ReadAll(meta.Body())
	if err != nil {
		return stack.PushResults(lua.LNil, lua.LString(err.Error()))
	}

	// Make sure the body is readable for the next handler...
	meta.SetBody(io.NopCloser(bytes.NewBuffer(bodyBytes)))

	return stack.PushResults(lua.LString(bodyBytes), lua.LNil)
}

// GetHTTPMethod pushes the HTTP request method as a string onto the Lua stack.
func (m *HTTPRequestManager) GetHTTPMethod(L *lua.LState) int {
	stack := luastack.NewManager(L)

	return stack.PushResults(lua.LString(m.currentMeta(L).Method()), lua.LNil)
}

// GetHTTPPath pushes the HTTP request URL path onto the Lua stack when invoked.
func (m *HTTPRequestManager) GetHTTPPath(L *lua.LState) int {
	stack := luastack.NewManager(L)

	return stack.PushResults(lua.LString(m.currentMeta(L).URL().Path), lua.LNil)
}

// GetHTTPQueryParam fetches a query parameter from the provided HTTP request.
func (m *HTTPRequestManager) GetHTTPQueryParam(L *lua.LState) int {
	stack := luastack.NewManager(L)
	paramName := stack.CheckString(1)

	return stack.PushResults(lua.LString(m.currentMeta(L).URL().Query().Get(paramName)), lua.LNil)
}

// URLPartialDecode decodes valid percent-escaped sequences while preserving
// invalid escapes and '+' characters.
func (m *HTTPRequestManager) URLPartialDecode(L *lua.LState) int {
	stack := luastack.NewManager(L)
	raw := stack.CheckString(1)

	return stack.PushResults(lua.LString(util.URLPartialDecode(raw)), lua.LNil)
}

// LoaderModHTTP loads Lua functions based on an HTTPRequestMeta provider.
func LoaderModHTTP(meta HTTPRequestMeta) lua.LGFunction {
	return func(L *lua.LState) int {
		stack := luastack.NewManager(L)
		manager := NewHTTPRequestManager()

		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnGetAllHTTPRequestHeaders: manager.GetAllHTTPRequestHeaders,
			definitions.LuaFnGetHTTPRequestHeader:     manager.GetHTTPRequestHeader,
			definitions.LuaFnGetHTTPRequestBody:       manager.GetHTTPRequestBody,
			definitions.LuaFnGetHTTPMethod:            manager.GetHTTPMethod,
			definitions.LuaFnGetHTTPQueryParam:        manager.GetHTTPQueryParam,
			definitions.LuaFnGetHTTPPath:              manager.GetHTTPPath,
			definitions.LuaFnURLPartialDecode:         manager.URLPartialDecode,
		})

		if meta != nil {
			bindRequestValue(L, mod, luaHTTPRequestMetaKey, meta)
		}

		return stack.PushResult(mod)
	}
}

// LoaderHTTPRequestStateless returns an empty, stateless module table for nauthilus_http_request.
// It is intended to be preloaded once per VM (base environment). Per-request bindings will later
// clone this table and inject bound functions via WithMeta factories.
func LoaderHTTPRequestStateless() lua.LGFunction {
	return func(L *lua.LState) int {
		stack := luastack.NewManager(L)

		return stack.PushResult(L.NewTable())
	}
}
