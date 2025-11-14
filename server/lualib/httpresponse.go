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
		ctx.Set(definitions.CtxResponseWrittenKey, true)

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
		ctx.Set(definitions.CtxResponseWrittenKey, true)

		return 0
	}
}

// RemoveHTTPResponseHeader returns a Lua function that removes an HTTP response header
// Usage from Lua: nauthilus_http_response.remove_http_response_header(name)
func RemoveHTTPResponseHeader(ctx *gin.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		name := L.CheckString(1)

		ctx.Writer.Header().Del(name)
		ctx.Set(definitions.CtxResponseWrittenKey, true)

		return 0
	}
}

// SetHTTPStatus returns a Lua function that sets the HTTP status code for the response
// Usage from Lua: nauthilus_http_response.set_http_status(code)
func SetHTTPStatus(ctx *gin.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		code := L.CheckInt(1)

		ctx.Status(code)
		ctx.Set(definitions.CtxResponseWrittenKey, true)

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
		ctx.Set(definitions.CtxResponseWrittenKey, true)

		return 0
	}
}

// SetHTTPContentType returns a Lua function that sets the Content-Type header explicitly
// Usage from Lua: nauthilus_http_response.set_http_content_type(value)
func SetHTTPContentType(ctx *gin.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		value := L.CheckString(1)

		ctx.Header("Content-Type", value)
		ctx.Set(definitions.CtxResponseWrittenKey, true)

		return 0
	}
}

// HTTPString returns a Lua function that maps to Gin's ctx.String(status, body)
// Usage from Lua: nauthilus_http_response.string(status_code, body)
func HTTPString(ctx *gin.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		status := L.CheckInt(1)
		body := L.CheckString(2)

		ctx.String(status, body)
		ctx.Set(definitions.CtxResponseWrittenKey, true)

		return 0
	}
}

// HTTPData returns a Lua function that maps to Gin's ctx.Data(status, contentType, data)
// Usage from Lua: nauthilus_http_response.data(status_code, content_type, data)
func HTTPData(ctx *gin.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		status := L.CheckInt(1)
		contentType := L.CheckString(2)
		data := L.CheckString(3)

		// Do not write body for HEAD requests
		if strings.EqualFold(ctx.Request.Method, http.MethodHead) {
			ctx.Status(status)
			ctx.Set(definitions.CtxResponseWrittenKey, true)

			return 0
		}

		ctx.Data(status, contentType, []byte(data))
		ctx.Set(definitions.CtxResponseWrittenKey, true)

		return 0
	}
}

// HTTPHTML returns a Lua function to send HTML content (uses Gin's Data with text/html)
// Usage from Lua: nauthilus_http_response.html(status_code, html_string)
func HTTPHTML(ctx *gin.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		status := L.CheckInt(1)
		html := L.CheckString(2)

		if strings.EqualFold(ctx.Request.Method, http.MethodHead) {
			ctx.Status(status)
			ctx.Set(definitions.CtxResponseWrittenKey, true)

			return 0
		}

		ctx.Data(status, "text/html; charset=utf-8", []byte(html))
		ctx.Set(definitions.CtxResponseWrittenKey, true)

		return 0
	}
}

// HTTPRedirect returns a Lua function that maps to Gin's ctx.Redirect(status, location)
// Usage from Lua: nauthilus_http_response.redirect(status_code, location)
func HTTPRedirect(ctx *gin.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		status := L.CheckInt(1)
		location := L.CheckString(2)

		ctx.Redirect(status, location)
		ctx.Set(definitions.CtxResponseWrittenKey, true)

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
			definitions.LuaFnHTTPString:               HTTPString(ctx),
			definitions.LuaFnHTTPData:                 HTTPData(ctx),
			definitions.LuaFnHTTPHTML:                 HTTPHTML(ctx),
			definitions.LuaFnHTTPRedirect:             HTTPRedirect(ctx),
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

		L.Push(mod)

		return 1
	}
}

// LoaderHTTPResponseStateless returns an empty, stateless module table for nauthilus_http_response.
// It is intended to be preloaded once per VM (base environment). Per-request bindings will later
// clone this table and inject bound functions via WithCtx factories.
func LoaderHTTPResponseStateless() lua.LGFunction {
	return func(L *lua.LState) int {
		L.Push(L.NewTable())

		return 1
	}
}

// SetHTTPResponseHeaderWithCtx is a factory alias that returns the same function as SetHTTPResponseHeader(ctx).
func SetHTTPResponseHeaderWithCtx(ctx *gin.Context) lua.LGFunction { return SetHTTPResponseHeader(ctx) }

// AddHTTPResponseHeaderWithCtx is a factory alias that returns the same function as AddHTTPResponseHeader(ctx).
func AddHTTPResponseHeaderWithCtx(ctx *gin.Context) lua.LGFunction { return AddHTTPResponseHeader(ctx) }

// RemoveHTTPResponseHeaderWithCtx is a factory alias that returns the same function as RemoveHTTPResponseHeader(ctx).
func RemoveHTTPResponseHeaderWithCtx(ctx *gin.Context) lua.LGFunction {
	return RemoveHTTPResponseHeader(ctx)
}

// SetHTTPStatusWithCtx is a factory alias that returns the same function as SetHTTPStatus(ctx).
func SetHTTPStatusWithCtx(ctx *gin.Context) lua.LGFunction { return SetHTTPStatus(ctx) }

// WriteHTTPResponseBodyWithCtx is a factory alias that returns the same function as WriteHTTPResponseBody(ctx).
func WriteHTTPResponseBodyWithCtx(ctx *gin.Context) lua.LGFunction { return WriteHTTPResponseBody(ctx) }

// SetHTTPContentTypeWithCtx is a factory alias that returns the same function as SetHTTPContentType(ctx).
func SetHTTPContentTypeWithCtx(ctx *gin.Context) lua.LGFunction { return SetHTTPContentType(ctx) }

// HTTPStringWithCtx is a factory alias that returns the same function as HTTPString(ctx).
func HTTPStringWithCtx(ctx *gin.Context) lua.LGFunction { return HTTPString(ctx) }
