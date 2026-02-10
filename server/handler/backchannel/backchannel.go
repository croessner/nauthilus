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
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/handler/asyncjobs"
	"github.com/croessner/nauthilus/server/handler/auth"
	"github.com/croessner/nauthilus/server/handler/bruteforce"
	"github.com/croessner/nauthilus/server/handler/cache"
	"github.com/croessner/nauthilus/server/handler/confighandler"
	"github.com/croessner/nauthilus/server/handler/custom"
	handlerdeps "github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/handler/devui"
	"github.com/croessner/nauthilus/server/handler/mfa_backchannel"

	mdauth "github.com/croessner/nauthilus/server/middleware/auth"
	mdlua "github.com/croessner/nauthilus/server/middleware/lua"

	"github.com/gin-gonic/gin"
)

// Setup registers the backchannel endpoints on the provided engine.
// It mirrors the previous setupBackChannelEndpoints behavior while delegating concrete
// route registrations to modular handlers.
func Setup(router *gin.Engine) {
	panic("backchannel.Setup is deprecated; use backchannel.SetupWithDeps with explicit dependencies")
}

func SetupWithDeps(router *gin.Engine, deps *handlerdeps.Deps) {
	if deps == nil || deps.Cfg == nil || deps.Logger == nil {
		panic("backchannel.SetupWithDeps requires non-nil deps (Cfg, Logger)")
	}

	if deps.Svc == nil {
		deps.Svc = handlerdeps.NewDefaultServices(deps)
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
		group.Use(mdauth.BasicAuthMiddlewareWithDeps(cfg, deps.Logger))
	}

	if cfg.GetServer().GetJWTAuth().IsEnabled() {
		group.Use(core.JWTAuthMiddlewareWithDeps(jwtDeps))
	}

	group.Use(mdlua.LuaContextMiddleware())

	// Register modules
	auth.NewWithDeps(deps).Register(group)
	bruteforce.New(deps).Register(group)
	confighandler.NewWithDeps(deps).Register(group)
	custom.NewWithDeps(deps.CfgProvider, deps.Logger, deps.Redis).Register(group)
	cache.NewWithDeps(deps).Register(group)
	asyncjobs.NewWithDeps(deps).Register(group)
	mfa_backchannel.NewWithDeps(deps).Register(group)

	if deps.Env != nil && deps.Env.GetDevMode() {
		devui.New(deps).Register(group)
	}
}
