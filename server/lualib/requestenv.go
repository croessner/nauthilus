// Copyright (C) 2026 Christian Rößner
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
	"strings"

	"github.com/gin-gonic/gin"
	lua "github.com/yuin/gopher-lua"
)

const (
	luaRequestEnvKey        = "__NAUTH_REQ_ENV"
	luaRequestBindingPrefix = "__NAUTH_REQ_"
	luaRequestModulesKey    = "__NAUTH_REQ_MODULE_TABLES"

	luaRequestContextKey      = "__NAUTH_REQ_CONTEXT"
	luaHTTPRequestMetaKey     = "__NAUTH_REQ_HTTP_REQUEST_META"
	luaHTTPResponseContextKey = "__NAUTH_REQ_HTTP_RESPONSE_CONTEXT"
	luaRuntimeContextKey      = "__NAUTH_REQ_RUNTIME_CONTEXT"
)

// getRequestEnv returns the active request environment table stored on the Lua state.
func getRequestEnv(L *lua.LState) *lua.LTable {
	if L == nil {
		return nil
	}

	req, ok := L.GetGlobal(luaRequestEnvKey).(*lua.LTable)
	if !ok {
		return nil
	}

	return req
}

// bindRequestValue stores a Go value as Lua userdata under a request-binding key in a module table.
func bindRequestValue(L *lua.LState, mod *lua.LTable, key string, value any) {
	if L == nil || mod == nil || key == "" || value == nil {
		return
	}

	userData := L.NewUserData()
	userData.Value = value

	L.SetField(mod, key, userData)
}

// getTrackedRequestModules returns the Lua table that tracks request-bound module tables for the current state.
func getTrackedRequestModules(L *lua.LState) *lua.LTable {
	if L == nil {
		return nil
	}

	tracked, ok := L.GetGlobal(luaRequestModulesKey).(*lua.LTable)
	if ok {
		return tracked
	}

	tracked = L.NewTable()
	L.SetGlobal(luaRequestModulesKey, tracked)

	return tracked
}

// trackRequestModule registers a request-bound module table so its hidden bindings can be scrubbed on reset.
func trackRequestModule(L *lua.LState, req *lua.LTable, mod *lua.LTable) {
	if req == nil || mod == nil {
		return
	}

	tracked := getTrackedRequestModules(L)
	if tracked == nil {
		return
	}

	tracked.Append(mod)
	L.SetField(req, luaRequestModulesKey, tracked)
}

// BindRequestValuesToEnv copies request-bound module values into the active request environment.
func BindRequestValuesToEnv(L *lua.LState, req *lua.LTable, mod *lua.LTable) {
	if L == nil || req == nil || mod == nil {
		return
	}

	mod.ForEach(func(key lua.LValue, value lua.LValue) {
		fieldName, ok := key.(lua.LString)
		if !ok {
			return
		}

		if !strings.HasPrefix(string(fieldName), luaRequestBindingPrefix) {
			return
		}

		L.SetField(req, string(fieldName), value)
	})

	trackRequestModule(L, req, mod)
}

// collectRequestBindingKeys returns the table keys that carry request-bound data.
func collectRequestBindingKeys(tbl *lua.LTable) []string {
	if tbl == nil {
		return nil
	}

	keys := make([]string, 0, 4)

	tbl.ForEach(func(key lua.LValue, _ lua.LValue) {
		fieldName, ok := key.(lua.LString)
		if !ok {
			return
		}

		if strings.HasPrefix(string(fieldName), luaRequestBindingPrefix) {
			keys = append(keys, string(fieldName))
		}
	})

	return keys
}

// collectTableKeys returns all keys currently stored in the provided Lua table.
func collectTableKeys(tbl *lua.LTable) []lua.LValue {
	if tbl == nil {
		return nil
	}

	keys := make([]lua.LValue, 0, 4)

	tbl.ForEach(func(key lua.LValue, _ lua.LValue) {
		keys = append(keys, key)
	})

	return keys
}

// scrubRequestBindingTable removes all request-bound fields from the provided Lua table.
func scrubRequestBindingTable(L *lua.LState, tbl *lua.LTable) {
	if L == nil || tbl == nil {
		return
	}

	for _, key := range collectRequestBindingKeys(tbl) {
		L.SetField(tbl, key, lua.LNil)
	}
}

// scrubTrackedRequestModules removes request-bound values from tracked module tables and drops stale references.
func scrubTrackedRequestModules(L *lua.LState) {
	tracked := getTrackedRequestModules(L)
	if tracked == nil {
		return
	}

	tracked.ForEach(func(_ lua.LValue, value lua.LValue) {
		mod, ok := value.(*lua.LTable)
		if !ok {
			return
		}

		scrubRequestBindingTable(L, mod)
	})

	for _, key := range collectTableKeys(tracked) {
		tracked.RawSet(key, lua.LNil)
	}
}

// resetTrackedRequestModules resets the tracked request-module registry for the current Lua state.
func resetTrackedRequestModules(L *lua.LState) {
	if L == nil {
		return
	}

	L.SetGlobal(luaRequestModulesKey, L.NewTable())
}

// ScrubRequestBindings removes request-bound data from the request environment and from all tracked module tables.
func ScrubRequestBindings(L *lua.LState, req *lua.LTable) {
	scrubTrackedRequestModules(L)
	scrubRequestBindingTable(L, req)
	resetTrackedRequestModules(L)
}

// getRequestValue reads a typed request-bound value from the active request environment.
func getRequestValue[T any](L *lua.LState, key string) (T, bool) {
	var zero T

	req := getRequestEnv(L)
	if req == nil {
		return zero, false
	}

	userData, ok := L.GetField(req, key).(*lua.LUserData)
	if !ok || userData == nil {
		return zero, false
	}

	value, ok := userData.Value.(T)
	if !ok {
		return zero, false
	}

	return value, true
}

// raiseMissingRequestValue raises a Lua error for modules that require an active request binding.
func raiseMissingRequestValue(L *lua.LState, moduleName string) {
	if L == nil {
		return
	}

	L.RaiseError("%s requires an active request binding", moduleName)
}

// CurrentLuaContext returns the Lua request context bound to the current request environment.
func CurrentLuaContext(L *lua.LState) *Context {
	requestCtx, _ := getRequestValue[*Context](L, luaRequestContextKey)

	return requestCtx
}

// RequireLuaContext returns the current Lua request context or raises a Lua error if none is bound.
func RequireLuaContext(L *lua.LState) *Context {
	if requestCtx := CurrentLuaContext(L); requestCtx != nil {
		return requestCtx
	}

	raiseMissingRequestValue(L, "nauthilus_context")

	return nil
}

// CurrentHTTPRequestMeta returns the HTTP request metadata bound to the current request environment.
func CurrentHTTPRequestMeta(L *lua.LState) HTTPRequestMeta {
	meta, _ := getRequestValue[HTTPRequestMeta](L, luaHTTPRequestMetaKey)

	return meta
}

// RequireHTTPRequestMeta returns the current HTTP request metadata or raises a Lua error if none is bound.
func RequireHTTPRequestMeta(L *lua.LState) HTTPRequestMeta {
	if meta := CurrentHTTPRequestMeta(L); meta != nil {
		return meta
	}

	raiseMissingRequestValue(L, "nauthilus_http_request")

	return nil
}

// CurrentHTTPResponseContext returns the Gin response context bound to the current request environment.
func CurrentHTTPResponseContext(L *lua.LState) *gin.Context {
	ginCtx, _ := getRequestValue[*gin.Context](L, luaHTTPResponseContextKey)

	return ginCtx
}

// RequireHTTPResponseContext returns the current Gin response context or raises a Lua error if none is bound.
func RequireHTTPResponseContext(L *lua.LState) *gin.Context {
	if ginCtx := CurrentHTTPResponseContext(L); ginCtx != nil {
		return ginCtx
	}

	raiseMissingRequestValue(L, "nauthilus_http_response")

	return nil
}

// CurrentRuntimeContext returns the Go runtime context bound to the current request environment.
func CurrentRuntimeContext(L *lua.LState) context.Context {
	ctx, _ := getRequestValue[context.Context](L, luaRuntimeContextKey)

	return ctx
}

// RequireRuntimeContext returns the current Go runtime context or raises a Lua error if none is bound.
func RequireRuntimeContext(L *lua.LState, moduleName string) context.Context {
	if ctx := CurrentRuntimeContext(L); ctx != nil {
		return ctx
	}

	raiseMissingRequestValue(L, moduleName)

	return nil
}

// BindRequestRuntimeContext binds the Go runtime context to a request-bound Lua module table.
func BindRequestRuntimeContext(L *lua.LState, mod *lua.LTable, ctx context.Context) {
	bindRequestValue(L, mod, luaRuntimeContextKey, ctx)
}
