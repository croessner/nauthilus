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

// Package backchannel provides backchannel functionality.
package backchannel

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	handlerapiv1 "github.com/croessner/nauthilus/v3/server/handler/api/v1"
	"github.com/croessner/nauthilus/v3/server/handler/asyncjobs"
	"github.com/croessner/nauthilus/v3/server/handler/auth"
	"github.com/croessner/nauthilus/v3/server/handler/bruteforce"
	"github.com/croessner/nauthilus/v3/server/handler/cache"
	"github.com/croessner/nauthilus/v3/server/handler/custom"
	handlerdeps "github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/handler/devui"
	"github.com/croessner/nauthilus/v3/server/handler/mfa_backchannel"
	"github.com/croessner/nauthilus/v3/server/idp"
	"github.com/croessner/nauthilus/v3/server/pluginruntime"

	mdauth "github.com/croessner/nauthilus/v3/server/middleware/auth"
	mdlua "github.com/croessner/nauthilus/v3/server/middleware/lua"
	"github.com/croessner/nauthilus/v3/server/middleware/oidcbearer"
	mdopenapivalidation "github.com/croessner/nauthilus/v3/server/middleware/openapivalidation"
	approuter "github.com/croessner/nauthilus/v3/server/router"

	"github.com/gin-gonic/gin"
)

var errBackchannelAuthNotConfigured = errors.New("backchannel setup requires at least one configured authentication method: auth.backchannel.basic_auth.enabled=true or auth.backchannel.oidc_bearer.enabled=true")

const (
	backchannelAuthNotConfigured = "backchannel authentication is not configured"
	backchannelResponseKeyError  = "error"
	openAPICategory              = "openapi"
	openAPIService               = "spec"
)

type backchannelAuthState struct {
	basicEnabled bool
	oidcEnabled  bool
}

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
	authState, ok := resolveBackchannelAuthState(ctx, cfg)
	if !ok {
		return false
	}

	return authorizeBackchannelScheme(ctx, cfg, validator, logger, authState)
}

// resolveBackchannelAuthState validates configured backchannel auth methods.
func resolveBackchannelAuthState(ctx *gin.Context, cfg config.File) (backchannelAuthState, bool) {
	if cfg == nil || cfg.GetServer() == nil {
		abortBackchannelAuthNotConfigured(ctx)

		return backchannelAuthState{}, false
	}

	authState := backchannelAuthState{
		basicEnabled: cfg.GetServer().GetBasicAuth().IsEnabled(),
		oidcEnabled:  cfg.GetServer().GetOIDCAuth().IsEnabled(),
	}
	if !authState.basicEnabled && !authState.oidcEnabled {
		abortBackchannelAuthNotConfigured(ctx)

		return backchannelAuthState{}, false
	}

	return authState, true
}

// authorizeBackchannelScheme dispatches to the configured Basic or Bearer authorizer.
func authorizeBackchannelScheme(
	ctx *gin.Context,
	cfg config.File,
	validator oidcbearer.TokenValidator,
	logger *slog.Logger,
	authState backchannelAuthState,
) bool {
	switch authorizationHeaderScheme(ctx) {
	case "basic":
		if authState.basicEnabled {
			return mdauth.AuthorizeBasicAuthWithDeps(ctx, cfg, logger)
		}
	case "bearer":
		if authState.oidcEnabled {
			return oidcbearer.AuthorizeAuthenticateScope(ctx, validator, cfg, logger)
		}
	case "":
		if authState.basicEnabled && !authState.oidcEnabled {
			return mdauth.AuthorizeBasicAuthWithDeps(ctx, cfg, logger)
		}
	}

	if authState.oidcEnabled {
		return oidcbearer.AuthorizeAuthenticateScope(ctx, validator, cfg, logger)
	}

	return mdauth.AuthorizeBasicAuthWithDeps(ctx, cfg, logger)
}

// abortBackchannelAuthNotConfigured writes the uniform missing-auth response.
func abortBackchannelAuthNotConfigured(ctx *gin.Context) {
	ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{backchannelResponseKeyError: backchannelAuthNotConfigured})
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

	nauthilusIDP, authenticatedGroup, err := registerAuthenticatedBackchannelRoutes(router, deps, cfg, developerMode)
	if err != nil {
		return err
	}

	registerCustomHookRoutes(router, deps, nauthilusIDP)
	registerDevUIRoutes(deps, authenticatedGroup)

	return nil
}

// registerAuthenticatedBackchannelRoutes registers protected management API routes.
func registerAuthenticatedBackchannelRoutes(
	router *gin.Engine,
	deps *handlerdeps.Deps,
	cfg config.File,
	developerMode bool,
) (oidcbearer.TokenValidator, *gin.RouterGroup, error) {
	if !hasBackchannelProtectedRouteAuth(cfg, developerMode) {
		deps.Logger.Warn(
			"Skipping authenticated backchannel endpoints because no auth.backchannel method is configured",
		)

		return nil, nil, nil
	}

	authenticatedGroup := router.Group("/api/v1")
	authenticatedGroup.Use(openAPIContextMiddleware())

	nauthilusIDP := backchannelTokenValidator(deps, cfg)
	if hasConfiguredBackchannelAuth(cfg) {
		authenticatedGroup.Use(backchannelAuthMiddleware(cfg, nauthilusIDP, deps.Logger))
	}

	authenticatedGroup.Use(mdlua.ContextMiddleware())

	if err := useManagementOpenAPIValidation(authenticatedGroup, deps, cfg); err != nil {
		return nil, nil, err
	}

	registerManagementModules(authenticatedGroup, deps)
	registerOIDCSessionManagement(authenticatedGroup, deps)

	return nauthilusIDP, authenticatedGroup, nil
}

// backchannelTokenValidator returns the OIDC token validator when Bearer auth is enabled.
func backchannelTokenValidator(deps *handlerdeps.Deps, cfg config.File) oidcbearer.TokenValidator {
	if cfg.GetServer().GetOIDCAuth().IsEnabled() {
		return idp.NewNauthilusIDP(deps)
	}

	return nil
}

// useManagementOpenAPIValidation wires OpenAPI validation middleware when configured.
func useManagementOpenAPIValidation(authenticatedGroup *gin.RouterGroup, deps *handlerdeps.Deps, cfg config.File) error {
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

	return nil
}

// registerManagementModules registers management modules on the authenticated group.
func registerManagementModules(authenticatedGroup *gin.RouterGroup, deps *handlerdeps.Deps) {
	auth.New(deps).Register(authenticatedGroup)
	bruteforce.New(deps).Register(authenticatedGroup)
	cache.New(deps).Register(authenticatedGroup)
	asyncjobs.New(deps).Register(authenticatedGroup)
	mfa_backchannel.New(deps).Register(authenticatedGroup)
}

// registerOIDCSessionManagement registers OIDC session administration when OIDC is enabled.
func registerOIDCSessionManagement(authenticatedGroup *gin.RouterGroup, deps *handlerdeps.Deps) {
	if deps == nil || deps.Cfg == nil || !deps.Cfg.GetIDP().OIDC.Enabled {
		return
	}

	handlerapiv1.NewOIDCSessionsAPI(deps, oidcSessionStoreFromDeps(deps)).Register(authenticatedGroup)
}

// oidcSessionStoreFromDeps resolves the Redis-backed OIDC token storage for management routes.
func oidcSessionStoreFromDeps(deps *handlerdeps.Deps) handlerapiv1.OIDCSessionStore {
	if deps == nil {
		return nil
	}

	if storage, ok := deps.TokenFlusher.(*idp.RedisTokenStorage); ok && storage != nil {
		return storage
	}

	if deps.Cfg == nil || deps.Redis == nil {
		return nil
	}

	return idp.NewRedisTokenStorageWithConfig(
		deps.Redis,
		deps.Cfg.GetServer().GetRedis().GetPrefix(),
		deps.Cfg,
	)
}

// registerCustomHookRoutes registers unauthenticated custom hook routes.
func registerCustomHookRoutes(router *gin.Engine, deps *handlerdeps.Deps, nauthilusIDP oidcbearer.TokenValidator) {
	hookGroup := router.Group("/api/v1")
	hookGroup.Use(mdlua.ContextMiddleware())

	custom.New(
		deps.CfgProvider,
		deps.Logger,
		deps.Redis,
		nauthilusIDP,
		custom.WithNativeHooks(nativeHookBindings()),
	).Register(hookGroup)
}

// registerDevUIRoutes registers the development UI on the authenticated group.
func registerDevUIRoutes(deps *handlerdeps.Deps, authenticatedGroup *gin.RouterGroup) {
	if deps.Env != nil && deps.Env.GetDevMode() && authenticatedGroup != nil {
		devui.New(deps).Register(authenticatedGroup)
	}
}

// nativeHookBindings adapts registered native plugin hooks into custom routes.
func nativeHookBindings() []custom.NativeHook {
	runner, ok := pluginruntime.DefaultRunner()
	if !ok {
		return nil
	}

	components := runner.Hooks()
	if len(components) == 0 {
		return nil
	}

	hooks := make([]custom.NativeHook, 0, len(components))
	for _, component := range components {
		hooks = append(hooks, custom.NativeHook{
			Runner:        runner,
			BuildRequest:  nativeHookRequest,
			Descriptor:    component.HookDescriptor,
			QualifiedName: component.QualifiedName,
			ModuleName:    component.ModuleName,
			ComponentName: component.LocalName,
		})
	}

	return hooks
}

// nativeHookRequest builds the public plugin hook request from the Gin boundary.
func nativeHookRequest(
	ctx *gin.Context,
	cfg config.File,
	_ pluginapi.HookDescriptor,
	caller custom.NativeHookCaller,
	body []byte,
) (pluginapi.HookRequest, error) {
	clientPort := ""
	if ctx != nil && ctx.Request != nil {
		_, clientPort, _ = net.SplitHostPort(ctx.Request.RemoteAddr)
	}

	return pluginruntime.NewHookRequestFromHTTPRequest(ctx.Request, body, pluginruntime.HookRequestMetadata{
		Session:       ctx.GetString(definitions.CtxGUIDKey),
		Service:       "custom_hook",
		Protocol:      "http",
		Username:      caller.Subject,
		ClientIP:      ctx.ClientIP(),
		ClientPort:    clientPort,
		ClientHost:    ctx.Request.Host,
		OIDCCID:       caller.ClientID,
		Authenticated: caller.Authenticated,
	}, pluginruntime.WithSnapshotConfig(cfg)), nil
}
