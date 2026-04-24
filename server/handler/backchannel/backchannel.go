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
	"errors"

	"github.com/croessner/nauthilus/server/config"
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

var errBackchannelAuthNotConfigured = errors.New("backchannel setup requires at least one configured authentication method: auth.backchannel.basic_auth.enabled=true or auth.backchannel.oidc_bearer.enabled=true")

func ensureBackchannelAuthConfigured(cfg config.File, developerMode bool) error {
	if hasBackchannelProtectedRouteAuth(cfg, developerMode) {
		return nil
	}

	if cfg != nil && cfg.HaveLuaHooks() {
		return nil
	}

	return errBackchannelAuthNotConfigured
}

func hasBackchannelProtectedRouteAuth(cfg config.File, developerMode bool) bool {
	if developerMode {
		return true
	}

	if cfg == nil {
		return false
	}

	if cfg.GetServer().GetBasicAuth().IsEnabled() || cfg.GetServer().GetOIDCAuth().IsEnabled() {
		return true
	}

	return false
}

// ValidateAuthConfiguration validates required authentication settings for backchannel endpoints.
func ValidateAuthConfiguration(cfg config.File, developerMode bool) error {
	return ensureBackchannelAuthConfigured(cfg, developerMode)
}

// Setup registers backchannel API endpoints with explicit dependencies.
// Authentication uses Basic Auth and/or OIDC Bearer tokens (client_credentials flow).
// The legacy HS256 JWT mechanism (/api/v1/jwt/token, /api/v1/jwt/refresh) has been
// removed in favor of the standard OIDC /oidc/token endpoint.
func Setup(router *gin.Engine, deps *handlerdeps.Deps) error {
	if deps == nil || deps.Cfg == nil || deps.Logger == nil {
		return errors.New("backchannel setup requires non-nil deps (Cfg, Logger)")
	}

	if deps.Svc == nil {
		deps.Svc = handlerdeps.NewDefaultServices(deps)
	}

	cfg := deps.Cfg
	developerMode := deps.Env != nil && deps.Env.GetDevMode()

	// Main API group with configured authentication (mandatory token)
	var nauthilusIdP oidcbearer.TokenValidator
	var authenticatedGroup *gin.RouterGroup

	if hasBackchannelProtectedRouteAuth(cfg, developerMode) {
		authenticatedGroup = router.Group("/api/v1")

		if cfg.GetServer().GetBasicAuth().IsEnabled() {
			authenticatedGroup.Use(mdauth.BasicAuthMiddlewareWithDeps(cfg, deps.Logger))
		}

		// OIDC Bearer token middleware (replaces the legacy JWT mechanism).
		// Uses the IdP's ValidateToken to verify RS256-signed tokens from client_credentials grant.
		// Controlled by auth.backchannel.oidc_bearer.enabled, independent of identity.oidc.enabled.
		if cfg.GetServer().GetOIDCAuth().IsEnabled() {
			nauthilusIdP = idp.NewNauthilusIdP(deps)

			authenticatedGroup.Use(oidcbearer.Middleware(nauthilusIdP, cfg, deps.Logger))
		}

		authenticatedGroup.Use(mdlua.LuaContextMiddleware())

		// Register modules (require mandatory authentication)
		auth.New(deps).Register(authenticatedGroup)
		bruteforce.New(deps).Register(authenticatedGroup)
		confighandler.New(deps).Register(authenticatedGroup)
		cache.New(deps).Register(authenticatedGroup)
		asyncjobs.New(deps).Register(authenticatedGroup)
		mfa_backchannel.New(deps).Register(authenticatedGroup)
	} else {
		deps.Logger.Warn(
			"Skipping authenticated backchannel endpoints because no auth.backchannel method is configured",
		)
	}

	// Custom hooks use a separate group without authentication middleware.
	// Authentication and authorization are handled per-hook inside HasRequiredScopes:
	// hooks that define required scopes perform token extraction, validation, and
	// scope checking; hooks without scopes are publicly accessible.
	hookGroup := router.Group("/api/v1")
	hookGroup.Use(mdlua.LuaContextMiddleware())

	custom.New(deps.CfgProvider, deps.Logger, deps.Redis, nauthilusIdP).Register(hookGroup)

	if deps.Env != nil && deps.Env.GetDevMode() && authenticatedGroup != nil {
		devui.New(deps).Register(authenticatedGroup)
	}

	return nil
}
