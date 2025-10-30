package lualib

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/croessner/nauthilus/server/definitions"
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

// GetAllHTTPRequestHeaders returns a Lua function that retrieves all headers from an HTTP request.
// The returned function accepts no arguments and pushes a Lua table where header names are keys and values are lists.
func GetAllHTTPRequestHeaders(meta HTTPRequestMeta) lua.LGFunction {
	return func(L *lua.LState) int {
		headerTable := L.NewTable()

		for headerName, headerValues := range meta.Header() {
			headerName = strings.ToLower(headerName)

			headerList := L.NewTable()

			for _, headerValue := range headerValues {
				headerList.Append(lua.LString(headerValue))
			}

			headerTable.RawSetString(headerName, headerList)
		}

		L.Push(headerTable)

		return 1
	}
}

// GetHTTPRequestHeader returns a Lua function that retrieves specific HTTP request header values as a Lua table.
// The function expects one argument: the name of the header to retrieve (case-insensitive).
// It returns a Lua table containing the header values or an empty table if the header is not present.
func GetHTTPRequestHeader(meta HTTPRequestMeta) lua.LGFunction {
	return func(L *lua.LState) int {
		reqzestedHeader := strings.ToLower(L.CheckString(1))
		headerValueTable := L.NewTable()

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

		L.Push(headerValueTable)

		return 1
	}
}

// GetHTTPRequestBody returns a Lua function that retrieves the body of an HTTP request as a Lua string.
// The returned function reads the HTTP request body, resets it for potential later use, and pushes it as a string to Lua.
func GetHTTPRequestBody(meta HTTPRequestMeta) lua.LGFunction {
	return func(L *lua.LState) int {
		// Read the HTTP body
		bodyBytes, err := io.ReadAll(meta.Body())
		if err != nil {
			L.RaiseError("failed to read request body: %v", err)

			return 0
		}

		// Make sure the body is readable for the next handler...
		meta.SetBody(io.NopCloser(bytes.NewBuffer(bodyBytes)))

		L.Push(lua.LString(bodyBytes))

		return 1
	}
}

// GetHTTPMethod returns a Lua function that pushes the HTTP request method as a string onto the Lua stack.
func GetHTTPMethod(meta HTTPRequestMeta) lua.LGFunction {
	return func(L *lua.LState) int {
		L.Push(lua.LString(meta.Method()))

		return 1
	}
}

// GetHTTPPath returns a Lua function that pushes the HTTP request URL path onto the Lua stack when invoked.
func GetHTTPPath(meta HTTPRequestMeta) lua.LGFunction {
	return func(L *lua.LState) int {
		L.Push(lua.LString(meta.URL().Path))

		return 1
	}
}

// GetHTTPQueryParam returns a Lua function to fetch a query parameter from the provided HTTP request.
func GetHTTPQueryParam(meta HTTPRequestMeta) lua.LGFunction {
	return func(L *lua.LState) int {
		paramName := L.CheckString(1)

		L.Push(lua.LString(meta.URL().Query().Get(paramName)))

		return 1
	}
}

// LoaderModHTTP loads Lua functions based on an HTTPRequestMeta provider.
func LoaderModHTTP(meta HTTPRequestMeta) lua.LGFunction { // ctx reserved for future use (timeouts, etc.)
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnGetAllHTTPRequestHeaders: GetAllHTTPRequestHeaders(meta),
			definitions.LuaFnGetHTTPRequestHeader:     GetHTTPRequestHeader(meta),
			definitions.LuaFnGetHTTPRequestBody:       GetHTTPRequestBody(meta),
			definitions.LuaFnGetHTTPMethod:            GetHTTPMethod(meta),
			definitions.LuaFnGetHTTPQueryParam:        GetHTTPQueryParam(meta),
			definitions.LuaFnGetHTTPPath:              GetHTTPPath(meta),
		})

		L.Push(mod)

		return 1
	}
}
