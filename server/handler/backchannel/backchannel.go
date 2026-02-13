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
	"github.com/croessner/nauthilus/server/handler/asyncjobs"
	"github.com/croessner/nauthilus/server/handler/auth"
	"github.com/croessner/nauthilus/server/handler/bruteforce"
	"github.com/croessner/nauthilus/server/handler/cache"
	"github.com/croessner/nauthilus/server/handler/confighandler"
	"github.com/croessner/nauthilus/server/handler/custom"
	handlerdeps "github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/handler/devui"
	"github.com/croessner/nauthilus/server/handler/mfa_backchannel"
	"github.com/croessner/nauthilus/server/idp"

	mdauth "github.com/croessner/nauthilus/server/middleware/auth"
	mdlua "github.com/croessner/nauthilus/server/middleware/lua"
	"github.com/croessner/nauthilus/server/middleware/oidcbearer"

	"github.com/gin-gonic/gin"
)

// Setup registers backchannel API endpoints with explicit dependencies.
// Authentication uses Basic Auth and/or OIDC Bearer tokens (client_credentials flow).
// The legacy HS256 JWT mechanism (/api/v1/jwt/token, /api/v1/jwt/refresh) has been
// removed in favor of the standard OIDC /oidc/token endpoint.
func Setup(router *gin.Engine, deps *handlerdeps.Deps) {
	if deps == nil || deps.Cfg == nil || deps.Logger == nil {
		panic("backchannel.Setup requires non-nil deps (Cfg, Logger)")
	}

	if deps.Svc == nil {
		deps.Svc = handlerdeps.NewDefaultServices(deps)
	}

	cfg := deps.Cfg

	// Main API group with configured authentication (mandatory token)
	group := router.Group("/api/v1")

	if cfg.GetServer().GetBasicAuth().IsEnabled() {
		group.Use(mdauth.BasicAuthMiddlewareWithDeps(cfg, deps.Logger))
	}

	// OIDC Bearer token middleware (replaces the legacy JWT mechanism).
	// Uses the IdP's ValidateToken to verify RS256-signed tokens from client_credentials grant.
	// Controlled by server.oidc_auth.enabled, independent of idp.oidc.enabled.
	var nauthilusIdP oidcbearer.TokenValidator

	if cfg.GetServer().GetOIDCAuth().IsEnabled() {
		nauthilusIdP = idp.NewNauthilusIdP(deps)

		group.Use(oidcbearer.Middleware(nauthilusIdP, cfg, deps.Logger))
	}

	group.Use(mdlua.LuaContextMiddleware())

	// Register modules (require mandatory authentication)
	auth.New(deps).Register(group)
	bruteforce.New(deps).Register(group)
	confighandler.New(deps).Register(group)
	cache.New(deps).Register(group)
	asyncjobs.New(deps).Register(group)
	mfa_backchannel.New(deps).Register(group)

	// Custom hooks use a separate group without authentication middleware.
	// Authentication and authorization are handled per-hook inside HasRequiredScopes:
	// hooks that define required scopes perform token extraction, validation, and
	// scope checking; hooks without scopes are publicly accessible.
	hookGroup := router.Group("/api/v1")
	hookGroup.Use(mdlua.LuaContextMiddleware())

	custom.New(deps.CfgProvider, deps.Logger, deps.Redis, nauthilusIdP).Register(hookGroup)

	if deps.Env != nil && deps.Env.GetDevMode() {
		devui.New(deps).Register(group)
	}
}
