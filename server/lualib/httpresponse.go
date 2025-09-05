package lualib

import (
	"net/http"
	"strings"

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

// SetHTTPStatus returns a Lua function that sets the HTTP status code for the response
// Usage from Lua: nauthilus_http_response.set_http_status(code)
func SetHTTPStatus(w http.ResponseWriter) lua.LGFunction {
	return func(L *lua.LState) int {
		code := L.CheckInt(1)
		// If headers are not written yet, set the status code
		// Gin's ResponseWriter implements http.ResponseWriter and will track the status
		w.WriteHeader(code)

		return 0
	}
}

// WriteHTTPResponseBody returns a Lua function that writes raw data to the HTTP response body
// Usage from Lua: nauthilus_http_response.write_http_response_body(data)
// Note: Set appropriate Content-Type header before writing if needed.
func WriteHTTPResponseBody(w http.ResponseWriter) lua.LGFunction {
	return func(L *lua.LState) int {
		data := L.CheckString(1)
		_, _ = w.Write([]byte(data))

		return 0
	}
}

// headNoBodyWriter wraps an http.ResponseWriter and discards any body writes.
type headNoBodyWriter struct{ w http.ResponseWriter }

// Header returns the header map of the wrapped http.ResponseWriter.
func (h headNoBodyWriter) Header() http.Header {
	return h.w.Header()
}

// Write discards the input byte slice and returns its length with a nil error.
func (h headNoBodyWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

// WriteHeader sends an HTTP response header with the provided status code using the wrapped http.ResponseWriter.
func (h headNoBodyWriter) WriteHeader(statusCode int) {
	h.w.WriteHeader(statusCode)
}

// LoaderModHTTPResponse loads Lua functions to interact with the HTTP response writer.
// If the HTTP method is HEAD, body writes are turned into a no-op to avoid crashes when
// Lua code attempts to write a response body for HEAD requests.
func LoaderModHTTPResponse(w http.ResponseWriter, method string) lua.LGFunction {
	// For HEAD responses, discard body writes but keep headers and status handling intact
	if strings.EqualFold(method, http.MethodHead) {
		w = headNoBodyWriter{w: w}
	}

	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnSetHTTPResponseHeader:    SetHTTPResponseHeader(w),
			definitions.LuaFnAddHTTPResponseHeader:    AddHTTPResponseHeader(w),
			definitions.LuaFnRemoveHTTPResponseHeader: RemoveHTTPResponseHeader(w),
			definitions.LuaFnSetHTTPStatus:            SetHTTPStatus(w),
			definitions.LuaFnWriteHTTPResponseBody:    WriteHTTPResponseBody(w),
		})

		L.Push(mod)

		return 1
	}
}
