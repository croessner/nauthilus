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

	"github.com/croessner/nauthilus/v4/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/lualib"
	bflib "github.com/croessner/nauthilus/v4/server/lualib/bruteforce"
	"github.com/croessner/nauthilus/v4/server/lualib/connmgr"
	"github.com/croessner/nauthilus/v4/server/lualib/luapool"
	"github.com/croessner/nauthilus/v4/server/lualib/metrics"
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

// BindRedisRequest binds Redis commands without process-global pool registration.
func (mm *ModuleManager) BindRedisRequest(redisCtx context.Context, L *lua.LState) {
	loader := redislib.LoaderModRedisRequest(redisCtx, mm.cfg, mm.redisClient)

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

// BindPsnetRequest binds connection counters without process-global target registration.
func (mm *ModuleManager) BindPsnetRequest(L *lua.LState) {
	loader := connmgr.LoaderModPsnetRequest(mm.ctx, mm.cfg, mm.logger)

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

// BindBruteForceRequest binds read-only toleration and blocking facts.
func (mm *ModuleManager) BindBruteForceRequest(L *lua.LState, tolerance tolerate.Tolerate) {
	loader := bflib.LoaderModBruteForceRequest(mm.ctx, mm.cfg, mm.logger, mm.redisClient, tolerance)

	mm.BindModule(L, definitions.LuaModBruteForce, loader)
}

// BindCBOR binds the nauthilus_cbor module.
func (mm *ModuleManager) BindCBOR(L *lua.LState) {
	mm.BindModule(L, definitions.LuaModCBOR, lualib.LoaderModCBOR())
}

// BindMiscRequest binds deterministic request-safe miscellaneous helpers.
func (mm *ModuleManager) BindMiscRequest(L *lua.LState) {
	mm.BindModule(L, definitions.LuaModMisc, lualib.LoaderModMiscRequest(mm.ctx, mm.cfg, mm.logger))
}

// BindCacheRequest binds read-only process-cache observations.
func (mm *ModuleManager) BindCacheRequest(L *lua.LState) {
	mm.BindModule(L, definitions.LuaModCache, lualib.LoaderModCacheRequest(mm.ctx, mm.cfg, mm.logger))
}

// BindPrometheusRequest binds updates to startup-registered metric vectors.
func (mm *ModuleManager) BindPrometheusRequest(L *lua.LState) {
	mm.BindModule(
		L,
		definitions.LuaModPrometheus,
		metrics.LoaderModPrometheusRequest(mm.ctx, mm.cfg, mm.logger),
	)
}

// BindPolicyTime binds UTC-only, context-bounded time helpers.
func (mm *ModuleManager) BindPolicyTime(L *lua.LState) {
	mm.BindModule(L, "time", lualib.LoaderModPolicyTime())
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

// BindAllDefault binds all default modules into the Lua state.
func (mm *ModuleManager) BindAllDefault(redisCtx context.Context, L *lua.LState, requestCtx *lualib.Context, tolerate tolerate.Tolerate) {
	mm.bindRequestDefaults(
		redisCtx,
		L,
		requestCtx,
		tolerate,
		mm.BindRedis,
		mm.BindPsnet,
		mm.BindDNS,
		mm.BindBruteForce,
	)
}

// BindAllPolicyRequest binds request modules without process-global registration authorities.
func (mm *ModuleManager) BindAllPolicyRequest(
	redisCtx context.Context,
	L *lua.LState,
	requestCtx *lualib.Context,
	tolerance tolerate.Tolerate,
) {
	mm.bindRequestDefaults(
		redisCtx,
		L,
		requestCtx,
		tolerance,
		mm.BindRedisRequest,
		mm.BindPsnetRequest,
		nil,
		mm.BindBruteForceRequest,
	)
	mm.BindMiscRequest(L)
	mm.BindCacheRequest(L)
	mm.BindPrometheusRequest(L)
	mm.BindPolicyTime(L)
}

// bindRequestDefaults composes the common request module surface around injected mutable boundaries.
func (mm *ModuleManager) bindRequestDefaults(
	redisCtx context.Context,
	L *lua.LState,
	requestCtx *lualib.Context,
	tolerance tolerate.Tolerate,
	bindRedis func(context.Context, *lua.LState),
	bindPsnet func(*lua.LState),
	bindDNS func(*lua.LState),
	bindBruteForce func(*lua.LState, tolerate.Tolerate),
) {
	mm.BindContext(L, requestCtx)
	mm.BindCBOR(L)
	bindRedis(redisCtx, L)
	bindPsnet(L)

	if bindDNS != nil {
		bindDNS(L)
	}
	mm.BindOTEL(L)
	bindBruteForce(L, tolerance)
	mm.BindRequestI18N(redisCtx, L)
}

// requestI18NRuntime binds request Lua to the immutable resolver captured by its Decision session.
func requestI18NRuntime(ctx context.Context) *lualib.I18NRuntime {
	resolver, ok := decisionservice.CapturedMessageResolverFromContext(ctx)
	if !ok {
		return lualib.NewI18NRuntime(lualib.I18NRuntimeOptions{})
	}

	return lualib.NewI18NRuntime(lualib.I18NRuntimeOptions{Resolver: resolver})
}
