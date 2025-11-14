// Copyright (C) 2025 Christian Rößner
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

// Runtime helpers for the Lua migration: base environment + request environment.
// This file provides the new optional runtime API without wiring it into call sites yet.
//
// APIs:
//  - NewLuaState(httpClient *http.Client) *lua.LState
//  - PrepareRequestEnv(L *lua.LState, ctx any) *lua.LTable
//  - ResetRequestEnv(L *lua.LState)
//  - bindModuleIntoReq (helper function from the migration plan)

package luapool

import (
	stdhttp "net/http"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/metrics"

	"github.com/cjoudrey/gluahttp"
	"github.com/vadv/gopher-lua-libs/plugin"
	lua "github.com/yuin/gopher-lua"
)

const (
	baseEnvKey = "__NAUTH_BASE_ENV"
	reqEnvKey  = "__NAUTH_REQ_ENV"
)

// NewLuaState creates a new Lua VM with standard libraries opened and stateless modules preloaded.
// Context-bound modules are NOT bound here (see PrepareRequestEnv).
func NewLuaState(httpClient *stdhttp.Client) *lua.LState {
	L := lua.NewState()
	L.OpenLibs()

	// Remember the base environment (_G) to enable inheritance.
	setBaseEnv(L, L.Get(lua.GlobalsIndex))

	// Preload all gopher-lua-libs at once.
	plugin.Preload(L)

	// Special case glua_http: needs an httpClient.
	if httpClient != nil {
		httpModule := gluahttp.NewHttpModule(httpClient)
		L.PreloadModule("glua_http", httpModule.Loader)
	}

	// Internal stateless modules. No context bindings!
	L.PreloadModule(definitions.LuaModPassword, lualib.LoaderModPassword)
	L.PreloadModule(definitions.LuaModMisc, lualib.LoaderModMisc)
	L.PreloadModule(definitions.LuaModPrometheus, metrics.LoaderModPrometheus)

	return L
}

// PrepareRequestEnv creates a per-request environment that inherits from the base environment via metatable.
// It calls binding skeletons to register request-bound functions/modules (currently stubs).
func PrepareRequestEnv(L *lua.LState, ctx any) *lua.LTable {
	base := getBaseEnv(L)
	if base == nil {
		// Fallback: If markers are missing, use _G as the base env.
		base = L.Get(lua.GlobalsIndex).(*lua.LTable)
		setBaseEnv(L, base)
	}

	req := L.NewTable()
	mt := L.NewTable()

	L.SetField(mt, "__index", base)
	L.SetMetatable(req, mt)

	// Call binding skeletons (currently no-ops; placeholders for Phase 2+).
	bindRequestFunctions(L, req, ctx)
	bindRequestModules(L, req, ctx)

	// Set as global marker.
	L.SetGlobal(reqEnvKey, req)

	return req
}

// ResetRequestEnv clears the request environment and removes transient globals.
func ResetRequestEnv(L *lua.LState) {
	resetRequestEnv(L)
}

// --- Helper functions ---

func getBaseEnv(L *lua.LState) *lua.LTable {
	v := L.GetGlobal(baseEnvKey)
	if tbl, ok := v.(*lua.LTable); ok {
		return tbl
	}

	return nil
}

func setBaseEnv(L *lua.LState, v lua.LValue) {
	if v == nil || v.Type() != lua.LTTable {
		return
	}

	L.SetGlobal(baseEnvKey, v)
}

// cloneTable creates a shallow copy of a Lua table (keys/values only, no metatable copy).
func cloneTable(L *lua.LState, src *lua.LTable) *lua.LTable {
	if src == nil {
		return L.NewTable()
	}

	dst := L.NewTable()
	src.ForEach(func(k, val lua.LValue) {
		dst.RawSet(k, val)
	})

	return dst
}

// bindModuleIntoReq makes a module visible both in the reqEnv and in package.loaded.
func bindModuleIntoReq(L *lua.LState, req *lua.LTable, name string, mod *lua.LTable) {
	// 1) Visible in the request env (direct global access in reqEnv)
	L.SetField(req, name, mod)

	// 2) Visible to require()
	pkg := L.GetGlobal("package")
	if t, ok := pkg.(*lua.LTable); ok {
		loaded := L.GetField(t, "loaded")
		if lt, ok := loaded.(*lua.LTable); ok {
			L.SetField(lt, name, mod)
		}
	}
}

func isTable(v lua.LValue) bool { _, ok := v.(*lua.LTable); return ok }

// resetRequestEnv clears only the request env and some transient globals; keeps baseEnv and package.loaded warm.
func resetRequestEnv(L *lua.LState) {
	// Clear stack and context
	L.SetTop(0)
	L.SetContext(nil)

	// Clear request env
	if v := L.GetGlobal(reqEnvKey); v.Type() == lua.LTTable {
		req := v.(*lua.LTable)

		// Replace with a new empty table while preserving the metatable
		mt := L.GetMetatable(req)
		newReq := L.NewTable()

		if mt != lua.LNil {
			L.SetMetatable(newReq, mt)
		}

		L.SetGlobal(reqEnvKey, newReq)
	}

	// Remove transient globals (as outlined in the plan)
	L.SetGlobal(definitions.LuaFnCallFilter, lua.LNil)
	L.SetGlobal(definitions.LuaFnCallFeature, lua.LNil)
	L.SetGlobal(definitions.LuaFnCallAction, lua.LNil)
	L.SetGlobal(definitions.LuaDefaultTable, lua.LNil)
	L.SetGlobal(definitions.LuaBackendResultTypeName, lua.LNil)

	// Force dynamic_loader to be recreated per request
	L.SetGlobal("dynamic_loader", lua.LNil)
}

// bindRequestFunctions registers request-bound helpers directly on reqEnv (Phase 1: stub).
func bindRequestFunctions(L *lua.LState, req *lua.LTable, ctx any) {
	// Placeholder for Phase 2+: logging, tracing, status, etc.
}

// bindRequestModules clones stateless modules and replaces functions with ctx-bound closures (Phase 1: stub).
func bindRequestModules(L *lua.LState, req *lua.LTable, ctx any) {
	// Placeholder: Phase 2 will add Redis/HTTP/LDAP/Context/Backend bindings here.
}
