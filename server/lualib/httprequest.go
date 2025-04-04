package lualib

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/croessner/nauthilus/server/definitions"
	lua "github.com/yuin/gopher-lua"
)

// GetAllHTTPRequestHeaders returns a Lua function that retrieves all headers from an HTTP request.
// The returned function accepts no arguments and pushes a Lua table where header names are keys and values are lists.
func GetAllHTTPRequestHeaders(httpRequest *http.Request) lua.LGFunction {
	return func(L *lua.LState) int {
		headerTable := L.NewTable()

		for headerName, headerValues := range httpRequest.Header {
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
func GetHTTPRequestHeader(httpRequest *http.Request) lua.LGFunction {
	return func(L *lua.LState) int {
		reqzestedHeader := strings.ToLower(L.CheckString(1))
		headerValueTable := L.NewTable()

		for headerName, headerValues := range httpRequest.Header {
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
func GetHTTPRequestBody(httpRequest *http.Request) lua.LGFunction {
	return func(L *lua.LState) int {
		// Read the HTTP body
		bodyBytes, err := io.ReadAll(httpRequest.Body)
		if err != nil {
			L.RaiseError("failed to read request body: %v", err)

			return 0
		}

		// Make sure the body is readable for the next handler...
		httpRequest.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		L.Push(lua.LString(bodyBytes))

		return 1
	}
}

// GetHTTPMethod returns a Lua function that pushes the HTTP request method as a string onto the Lua stack.
func GetHTTPMethod(httpRequest *http.Request) lua.LGFunction {
	return func(L *lua.LState) int {
		L.Push(lua.LString(httpRequest.Method))

		return 1
	}
}

// GetHTTPPath returns a Lua function that pushes the HTTP request URL path onto the Lua stack when invoked.
func GetHTTPPath(httpRequest *http.Request) lua.LGFunction {
	return func(L *lua.LState) int {
		L.Push(lua.LString(httpRequest.URL.Path))

		return 1
	}
}

// GetHTTPQueryParam returns a Lua function to fetch a query parameter from the provided HTTP request.
func GetHTTPQueryParam(httpRequest *http.Request) lua.LGFunction {
	return func(L *lua.LState) int {
		paramName := L.CheckString(1)

		L.Push(lua.LString(httpRequest.URL.Query().Get(paramName)))

		return 1
	}
}

// LoaderModHTTPRequest loads Lua functions to interact with the provided HTTP request and returns them as a Lua module.
func LoaderModHTTPRequest(httpRequest *http.Request) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnGetAllHTTPRequestHeaders: GetAllHTTPRequestHeaders(httpRequest),
			definitions.LuaFnGetHTTPRequestHeader:     GetHTTPRequestHeader(httpRequest),
			definitions.LuaFnGetHTTPRequestBody:       GetHTTPRequestBody(httpRequest),
			definitions.LuaFnGetHTTPMethod:            GetHTTPMethod(httpRequest),
			definitions.LuaFnGetHTTPQueryParam:        GetHTTPQueryParam(httpRequest),
			definitions.LuaFnGetHTTPPath:              GetHTTPPath(httpRequest),
		})

		L.Push(mod)

		return 1
	}
}
