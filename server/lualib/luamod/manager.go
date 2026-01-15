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

package luamod

import (
	"context"
	"log/slog"

	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib"
	bflib "github.com/croessner/nauthilus/server/lualib/bruteforce"
	"github.com/croessner/nauthilus/server/lualib/connmgr"
	"github.com/croessner/nauthilus/server/lualib/luapool"
	"github.com/croessner/nauthilus/server/lualib/redislib"
	"github.com/croessner/nauthilus/server/rediscli"
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
	loader := lualib.LoaderModContext(mm.ctx, mm.cfg, mm.logger, requestCtx)

	mm.BindModule(L, definitions.LuaModContext, loader)
}

// BindHTTP binds the nauthilus_http_request module.
func (mm *ModuleManager) BindHTTP(L *lua.LState, httpMeta lualib.HTTPRequestMeta) {
	if httpMeta == nil {
		return
	}

	loader := lualib.LoaderModHTTP(mm.ctx, mm.cfg, mm.logger, httpMeta)

	mm.BindModule(L, definitions.LuaModHTTPRequest, loader)
}

// BindHTTPResponse binds the nauthilus_http_response module.
func (mm *ModuleManager) BindHTTPResponse(L *lua.LState, ginCtx *gin.Context) {
	if ginCtx == nil {
		return
	}

	loader := lualib.LoaderModHTTPResponse(mm.ctx, mm.cfg, mm.logger, ginCtx)

	mm.BindModule(L, definitions.LuaModHTTPResponse, loader)
}

// BindRedis binds the nauthilus_redis module.
func (mm *ModuleManager) BindRedis(L *lua.LState, redisCtx context.Context) {
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

// BindAllDefault binds all default modules into the Lua state.
func (mm *ModuleManager) BindAllDefault(L *lua.LState, requestCtx *lualib.Context, redisCtx context.Context, tolerate tolerate.Tolerate) {
	mm.BindContext(L, requestCtx)
	mm.BindRedis(L, redisCtx)
	mm.BindPsnet(L)
	mm.BindDNS(L)
	mm.BindOTEL(L)
	mm.BindBruteForce(L, tolerate)
}
