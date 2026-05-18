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
	"log/slog"
	"net/http"
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
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
	mdopenapivalidation "github.com/croessner/nauthilus/server/middleware/openapivalidation"
	approuter "github.com/croessner/nauthilus/server/router"

	"github.com/gin-gonic/gin"
)

var errBackchannelAuthNotConfigured = errors.New("backchannel setup requires at least one configured authentication method: auth.backchannel.basic_auth.enabled=true or auth.backchannel.oidc_bearer.enabled=true")

const (
	openAPICategory = "openapi"
	openAPIService  = "spec"
)

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

func hasConfiguredBackchannelAuth(cfg config.File) bool {
	if cfg == nil || cfg.GetServer() == nil {
		return false
	}

	return cfg.GetServer().GetBasicAuth().IsEnabled() || cfg.GetServer().GetOIDCAuth().IsEnabled()
}

// ValidateAuthConfiguration validates required authentication settings for backchannel endpoints.
func ValidateAuthConfiguration(cfg config.File, developerMode bool) error {
	return ensureBackchannelAuthConfigured(cfg, developerMode)
}

func backchannelAuthMiddleware(
	cfg config.File,
	validator oidcbearer.TokenValidator,
	logger *slog.Logger,
) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if !authorizeBackchannelRequest(ctx, cfg, validator, logger) {
			return
		}

		ctx.Next()
	}
}

func openAPIContextMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		switch ctx.Request.URL.Path {
		case "/api/v1/openapi.yaml", "/api/v1/openapi.json":
			ctx.Set(definitions.CtxCategoryKey, openAPICategory)
			ctx.Set(definitions.CtxServiceKey, openAPIService)
		}

		ctx.Next()
	}
}

func authorizeBackchannelRequest(
	ctx *gin.Context,
	cfg config.File,
	validator oidcbearer.TokenValidator,
	logger *slog.Logger,
) bool {
	if cfg == nil || cfg.GetServer() == nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "backchannel authentication is not configured"})

		return false
	}

	basicEnabled := cfg.GetServer().GetBasicAuth().IsEnabled()
	oidcEnabled := cfg.GetServer().GetOIDCAuth().IsEnabled()
	if !basicEnabled && !oidcEnabled {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "backchannel authentication is not configured"})

		return false
	}

	switch authorizationHeaderScheme(ctx) {
	case "basic":
		if basicEnabled {
			return mdauth.AuthorizeBasicAuthWithDeps(ctx, cfg, logger)
		}
	case "bearer":
		if oidcEnabled {
			return oidcbearer.AuthorizeAuthenticateScope(ctx, validator, cfg, logger)
		}
	case "":
		if basicEnabled && !oidcEnabled {
			return mdauth.AuthorizeBasicAuthWithDeps(ctx, cfg, logger)
		}
	}

	if oidcEnabled {
		return oidcbearer.AuthorizeAuthenticateScope(ctx, validator, cfg, logger)
	}

	return mdauth.AuthorizeBasicAuthWithDeps(ctx, cfg, logger)
}

func authorizationHeaderScheme(ctx *gin.Context) string {
	header := strings.TrimSpace(ctx.GetHeader("Authorization"))
	scheme, _, ok := strings.Cut(header, " ")
	if !ok {
		return ""
	}

	return strings.ToLower(scheme)
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
		authenticatedGroup.Use(openAPIContextMiddleware())

		// OIDC Bearer token middleware (replaces the legacy JWT mechanism).
		// Uses the IdP's ValidateToken to verify RS256-signed tokens from client_credentials grant.
		// Controlled by auth.backchannel.oidc_bearer.enabled, independent of identity.oidc.enabled.
		if cfg.GetServer().GetOIDCAuth().IsEnabled() {
			nauthilusIdP = idp.NewNauthilusIdP(deps)
		}

		if hasConfiguredBackchannelAuth(cfg) {
			authenticatedGroup.Use(backchannelAuthMiddleware(cfg, nauthilusIdP, deps.Logger))
		}

		authenticatedGroup.Use(mdlua.LuaContextMiddleware())

		openAPIValidationMiddleware, err := mdopenapivalidation.NewManagementMiddleware(
			cfg.GetServer().GetOpenAPIValidation(),
			deps.Logger,
		)
		if err != nil {
			return err
		}

		if openAPIValidationMiddleware != nil {
			authenticatedGroup.Use(openAPIValidationMiddleware)
		}

		approuter.RegisterManagementOpenAPI(authenticatedGroup)

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
