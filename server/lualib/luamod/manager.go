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

// Package luamod provides luamod functionality.
package luamod

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/croessner/nauthilus/v4/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/lualib"
	bflib "github.com/croessner/nauthilus/v4/server/lualib/bruteforce"
	"github.com/croessner/nauthilus/v4/server/lualib/connmgr"
	"github.com/croessner/nauthilus/v4/server/lualib/luapool"
	"github.com/croessner/nauthilus/v4/server/lualib/redislib"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/gin-gonic/gin"
	lua "github.com/yuin/gopher-lua"
)

// ModuleManager manages the loading and binding of Lua modules.
type ModuleManager struct {
	ctx         context.Context
	cfg         config.File
	logger      *slog.Logger
	redisClient rediscli.Client
}

// RequestModules carries the per-request owners that complete the default module surface of one Lua runtime.
type RequestModules struct {
	// Context is the request-local Lua context behind nauthilus_context.
	Context *lualib.Context

	// Tolerate provides the brute-force toleration state behind nauthilus_brute_force.
	Tolerate tolerate.Tolerate

	// HTTPRequest is the inbound request behind nauthilus_http_request; nil leaves the module unbound.
	HTTPRequest *http.Request

	// HTTPResponse is the live response behind nauthilus_http_response; nil leaves the module unbound.
	HTTPResponse *gin.Context

	// LDAP loads nauthilus_ldap. The module is bound only when an LDAP backend is configured.
	LDAP lua.LGFunction
}

// NewModuleManager creates a new ModuleManager instance.
func NewModuleManager(ctx context.Context, cfg config.File, logger *slog.Logger, redisClient rediscli.Client) *ModuleManager {
	return &ModuleManager{
		ctx:         ctx,
		cfg:         cfg,
		logger:      logger,
		redisClient: redisClient,
	}
}

// BindModule loads a module using the provided loader and binds it into the Lua state's request environment.
func (mm *ModuleManager) BindModule(L *lua.LState, moduleName string, loader lua.LGFunction) {
	if loader == nil {
		return
	}

	_ = loader(L)

	if mod, ok := L.Get(-1).(*lua.LTable); ok {
		L.Pop(1)
		luapool.BindModuleIntoReq(L, moduleName, mod)
	} else {
		L.Pop(1)
	}
}

// BindContext binds the nauthilus_context module.
func (mm *ModuleManager) BindContext(L *lua.LState, requestCtx *lualib.Context) {
	loader := lualib.LoaderModContext(requestCtx)

	mm.BindModule(L, definitions.LuaModContext, loader)
}

// BindHTTP binds the nauthilus_http_request module.
func (mm *ModuleManager) BindHTTP(L *lua.LState, httpMeta lualib.HTTPRequestMeta) {
	if httpMeta == nil {
		return
	}

	loader := lualib.LoaderModHTTP(httpMeta)

	mm.BindModule(L, definitions.LuaModHTTPRequest, loader)
}

// BindHTTPResponse binds the nauthilus_http_response module.
func (mm *ModuleManager) BindHTTPResponse(L *lua.LState, ginCtx *gin.Context) {
	if ginCtx == nil {
		return
	}

	loader := lualib.LoaderModHTTPResponse(ginCtx)

	mm.BindModule(L, definitions.LuaModHTTPResponse, loader)
}

// BindRedis binds the nauthilus_redis module.
func (mm *ModuleManager) BindRedis(redisCtx context.Context, L *lua.LState) {
	loader := redislib.LoaderModRedis(redisCtx, mm.cfg, mm.redisClient)

	mm.BindModule(L, definitions.LuaModRedis, loader)
}

// BindLDAP binds the nauthilus_ldap module.
func (mm *ModuleManager) BindLDAP(L *lua.LState, loader lua.LGFunction) {
	if mm.cfg.HaveLDAPBackend() {
		mm.BindModule(L, definitions.LuaModLDAP, loader)
	}
}

// BindPsnet binds the nauthilus_psnet module.
func (mm *ModuleManager) BindPsnet(L *lua.LState) {
	loader := connmgr.LoaderModPsnet(mm.ctx, mm.cfg, mm.logger)

	mm.BindModule(L, definitions.LuaModPsnet, loader)
}

// BindDNS binds the nauthilus_dns module.
func (mm *ModuleManager) BindDNS(L *lua.LState) {
	loader := lualib.LoaderModDNS(mm.ctx, mm.cfg, mm.logger)

	mm.BindModule(L, definitions.LuaModDNS, loader)
}

// BindOTEL binds the nauthilus_opentelemetry module.
func (mm *ModuleManager) BindOTEL(L *lua.LState) {
	var loader lua.LGFunction

	if mm.cfg.GetServer().GetInsights().GetTracing().IsEnabled() {
		loader = lualib.LoaderModOTEL(mm.ctx, mm.cfg, mm.logger)
	} else {
		loader = lualib.LoaderOTELStateless()
	}

	mm.BindModule(L, definitions.LuaModOpenTelemetry, loader)
}

// BindBruteForce binds the nauthilus_brute_force module.
func (mm *ModuleManager) BindBruteForce(L *lua.LState, tolerate tolerate.Tolerate) {
	loader := bflib.LoaderModBruteForce(mm.ctx, mm.cfg, mm.logger, mm.redisClient, tolerate)

	mm.BindModule(L, definitions.LuaModBruteForce, loader)
}

// BindCBOR binds the nauthilus_cbor module.
func (mm *ModuleManager) BindCBOR(L *lua.LState) {
	mm.BindModule(L, definitions.LuaModCBOR, lualib.LoaderModCBOR())
}

// BindI18N binds the nauthilus_i18n module.
func (mm *ModuleManager) BindI18N(L *lua.LState, mode lualib.I18NMode) {
	mm.BindI18NRuntime(L, nil, mode)
}

// BindI18NRuntime binds the nauthilus_i18n module with an explicit runtime.
func (mm *ModuleManager) BindI18NRuntime(L *lua.LState, runtime *lualib.I18NRuntime, mode lualib.I18NMode) {
	mm.BindModule(L, definitions.LuaModI18N, lualib.LoaderModI18N(runtime, mode))
}

// BindRequestI18N binds the resolver captured by the exact Decision session.
func (mm *ModuleManager) BindRequestI18N(ctx context.Context, L *lua.LState) {
	mm.BindI18NRuntime(L, requestI18NRuntime(ctx), lualib.I18NModeRequest)
}

// BindAllDefault binds the default modules that need no HTTP or LDAP owner into the Lua state.
func (mm *ModuleManager) BindAllDefault(redisCtx context.Context, L *lua.LState, requestCtx *lualib.Context, tolerate tolerate.Tolerate) {
	mm.BindContext(L, requestCtx)
	mm.BindCBOR(L)
	mm.BindRedis(redisCtx, L)
	mm.BindPsnet(L)
	mm.BindDNS(L)
	mm.BindOTEL(L)
	mm.BindBruteForce(L, tolerate)
	mm.BindRequestI18N(redisCtx, L)
}

// BindRequestModules binds the complete module surface of one Lua runtime.
//
// Custom hooks, Lua backends, the cache-flush script, environment sources, subject sources, and actions all bind
// through this method, so every runtime exposes the same Lua API.
func (mm *ModuleManager) BindRequestModules(redisCtx context.Context, L *lua.LState, modules RequestModules) {
	mm.BindAllDefault(redisCtx, L, modules.Context, modules.Tolerate)

	if modules.HTTPRequest != nil {
		mm.BindHTTP(L, lualib.NewHTTPMetaFromRequest(modules.HTTPRequest))
	}

	mm.BindHTTPResponse(L, modules.HTTPResponse)
	mm.BindLDAP(L, modules.LDAP)
}

// BindBackendResult exposes the backend-result constructor as a global and as a request module.
//
// Captured shared modules run in the global environment, so the constructor must be a real global there as well.
func (mm *ModuleManager) BindBackendResult(L *lua.LState) {
	_ = lualib.LoaderModBackendResult(mm.ctx, mm.cfg, mm.logger)(L)

	mod, ok := L.Get(-1).(*lua.LTable)

	L.Pop(1)

	if !ok {
		return
	}

	L.SetGlobal(definitions.LuaBackendResultTypeName, mod)
	luapool.BindModuleIntoReq(L, definitions.LuaBackendResultTypeName, mod)
}

// requestI18NRuntime binds request Lua to the immutable resolver captured by its Decision session.
func requestI18NRuntime(ctx context.Context) *lualib.I18NRuntime {
	resolver, ok := decisionservice.CapturedMessageResolverFromContext(ctx)
	if !ok {
		return lualib.NewI18NRuntime(lualib.I18NRuntimeOptions{})
	}

	return lualib.NewI18NRuntime(lualib.I18NRuntimeOptions{Resolver: resolver})
}
