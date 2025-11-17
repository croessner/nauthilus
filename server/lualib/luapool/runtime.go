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
//  - bindModuleIntoReq (helper function from the migration plan)

package luapool

import (
	stdhttp "net/http"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib"
	bflib "github.com/croessner/nauthilus/server/lualib/bruteforce"
	"github.com/croessner/nauthilus/server/lualib/connmgr"
	"github.com/croessner/nauthilus/server/lualib/metrics"
	"github.com/croessner/nauthilus/server/lualib/redislib"
	gluacrypto "github.com/tengattack/gluacrypto/crypto"

	"github.com/cjoudrey/gluahttp"
	libs "github.com/vadv/gopher-lua-libs"
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
	libs.Preload(L)

	// Preload gluacrypto.
	L.PreloadModule("glua_crypto", gluacrypto.Loader)

	// Special case glua_http: needs an httpClient.
	if httpClient != nil {
		httpModule := gluahttp.NewHttpModule(httpClient)
		L.PreloadModule("glua_http", httpModule.Loader)
	}

	// Internal stateless modules. No context bindings!
	L.PreloadModule(definitions.LuaModPassword, lualib.LoaderModPassword)
	L.PreloadModule(definitions.LuaModMisc, lualib.LoaderModMisc)
	L.PreloadModule(definitions.LuaModPrometheus, metrics.LoaderModPrometheus)
	L.PreloadModule(definitions.LuaModCache, lualib.LoaderModCache)
	L.PreloadModule(definitions.LuaModSoftWhitelist, lualib.LoaderModSoftWhitelist)
	L.PreloadModule(definitions.LuaModMail, lualib.LoaderModMail)
	L.PreloadModule(definitions.LuaModBackend, lualib.LoaderBackendStateless())

	// Preload stateless placeholders for context-bound modules. These will be
	// replaced per request via BindModuleIntoReq when a bound version is
	// available. Keeping them warm avoids dynamic_loader usage for ctx-bound
	// modules and satisfies static analyzers.
	L.PreloadModule(definitions.LuaModRedis, redislib.Loader())
	L.PreloadModule(definitions.LuaModHTTPRequest, lualib.LoaderHTTPRequestStateless())
	L.PreloadModule(definitions.LuaModHTTPResponse, lualib.LoaderHTTPResponseStateless())
	L.PreloadModule(definitions.LuaModContext, lualib.LoaderContextStateless())
	L.PreloadModule(definitions.LuaModLDAP, lualib.LoaderLDAPStateless())
	L.PreloadModule(definitions.LuaModPsnet, connmgr.LoaderPsnetStateless())
	L.PreloadModule(definitions.LuaModDNS, lualib.LoaderDNSStateless())
	L.PreloadModule(definitions.LuaModBruteForce, bflib.LoaderBruteForceStateless())

	return L
}

// PrepareRequestEnv creates a per-request environment that inherits from the base environment via metatable.
// It calls binding skeletons to register request-bound functions/modules (currently stubs).
func PrepareRequestEnv(L *lua.LState) *lua.LTable {
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

	// Request environment prepared; concrete per-request bindings are provided
	// by subsystems using BindModuleIntoReq where needed.

	// Set as global marker.
	L.SetGlobal(reqEnvKey, req)

	// Install per-request dynamic_loader stub for backward compatibility
	ensureDynamicLoaderStub(L)

	return req
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

	// Recreate dynamic_loader stub per request
	ensureDynamicLoaderStub(L)
}

// ensureDynamicLoaderStub installs a no-op dynamic_loader function that logs usage.
// This keeps legacy scripts running while making remaining dynamic_loader calls visible.
func ensureDynamicLoaderStub(L *lua.LState) {
	if v := L.GetGlobal("dynamic_loader"); v != lua.LNil && v != nil {
		return
	}

	stub := L.NewFunction(func(L *lua.LState) int {
		name := L.OptString(1, "")
		level.Warn(log.Logger).Log(
			definitions.LogKeyMsg, "Lua dynamic_loader called",
			"module", name,
		)

		// no return values (no-op)
		return 0
	})

	L.SetGlobal("dynamic_loader", stub)
}

// BindModuleIntoReq exposes the module-binding helper for subsystems that need
// to bind request-scoped modules (e.g., backend/action/filter/feature) without
// directly mutating globals. It ensures the module is visible both via direct
// access from the reqEnv and via require() through package.loaded.
func BindModuleIntoReq(L *lua.LState, name string, mod *lua.LTable) {
	// Try to get the current request environment; if missing, create one.
	var req *lua.LTable

	if v := L.GetGlobal(reqEnvKey); v != nil {
		if t, ok := v.(*lua.LTable); ok {
			req = t
		}
	}

	if req == nil {
		req = PrepareRequestEnv(L)
	}

	bindModuleIntoReq(L, req, name, mod)
}
