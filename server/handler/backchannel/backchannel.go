// Copyright (C) 2024 Christian Rößner
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

package backchannel

import (
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/handler/asyncjobs"
	"github.com/croessner/nauthilus/server/handler/auth"
	"github.com/croessner/nauthilus/server/handler/bruteforce"
	"github.com/croessner/nauthilus/server/handler/cache"
	"github.com/croessner/nauthilus/server/handler/confighandler"
	"github.com/croessner/nauthilus/server/handler/custom"
	handlerdeps "github.com/croessner/nauthilus/server/handler/deps"

	mdauth "github.com/croessner/nauthilus/server/middleware/auth"
	mdlua "github.com/croessner/nauthilus/server/middleware/lua"

	"github.com/gin-gonic/gin"
)

// Setup registers the backchannel endpoints on the provided engine.
// It mirrors the previous setupBackChannelEndpoints behavior while delegating concrete
// route registrations to modular handlers.
func Setup(router *gin.Engine) {
	deps := &handlerdeps.Deps{Cfg: config.GetFile(), Svc: handlerdeps.NewDefaultServices()}

	SetupWithDeps(router, deps)
}

func SetupWithDeps(router *gin.Engine, deps *handlerdeps.Deps) {
	if deps == nil || deps.Cfg == nil {
		// Keep legacy safety net for callers that are not migrated yet.
		deps = &handlerdeps.Deps{Cfg: config.GetFile(), Svc: handlerdeps.NewDefaultServices()}
	}

	cfg := deps.Cfg
	jwtDeps := core.JWTDeps{Cfg: cfg, Logger: deps.Logger, Redis: deps.Redis}

	// Public JWT endpoints first (token and refresh)
	if cfg.GetServer().GetJWTAuth().IsEnabled() && !cfg.GetServer().GetEndpoint().IsAuthJWTDisabled() {
		jwtGroup := router.Group("/api/v1/jwt")

		jwtGroup.Use(mdlua.LuaContextMiddleware())
		jwtGroup.POST("/token", core.HandleJWTTokenGenerationWithDeps(jwtDeps))

		if cfg.GetServer().GetJWTAuth().IsRefreshTokenEnabled() {
			jwtGroup.POST("/refresh", core.HandleJWTTokenRefreshWithDeps(jwtDeps))
		}
	}

	// Main API group with configured authentication
	group := router.Group("/api/v1")

	if cfg.GetServer().GetBasicAuth().IsEnabled() {
		group.Use(mdauth.BasicAuthMiddleware())
	}

	if cfg.GetServer().GetJWTAuth().IsEnabled() {
		group.Use(core.JWTAuthMiddlewareWithDeps(jwtDeps))
	}

	group.Use(mdlua.LuaContextMiddleware())

	// Register modules
	auth.New(cfg).Register(group)
	bruteforce.New(deps).Register(group)
	confighandler.NewWithDeps(deps).Register(group)
	custom.New().Register(group)
	cache.NewWithDeps(deps).Register(group)
	asyncjobs.New().Register(group)
}
