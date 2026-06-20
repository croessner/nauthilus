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

package core

import (
	"log/slog"
	"net"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/errors"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
)

// ProtectEndpointMiddleware is a Gin middleware that performs authentication and security checks for HTTP requests.
// It handles client IP extraction, brute force detection, protocol handling, and various authentication environment controls.
func ProtectEndpointMiddleware(cfg config.File, logger *slog.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		guid := ctx.GetString(definitions.CtxGUIDKey) // MiddleWare behind Logger!
		auth := newProtectedEndpointAuthState(ctx, cfg, logger, guid)
		auth.Request.ClientIP, auth.Request.XClientPort = protectedEndpointClient(ctx, cfg, logger, auth)

		// Store remote client IP into connection context. It can be used for brute force updates.
		ctx.Set(definitions.CtxClientIPKey, auth.Request.ClientIP)

		if auth.CheckBruteForce(ctx) && handleProtectedPreAuthBruteForce(ctx, auth) {
			return
		}

		if handleProtectedEnvironment(ctx, auth) {
			return
		}

		ctx.Next()
	}
}

// newProtectedEndpointAuthState creates the no-auth HTTP AuthState used by protected endpoints.
func newProtectedEndpointAuthState(ctx *gin.Context, cfg config.File, logger *slog.Logger, guid string) *AuthState {
	protocol := &config.Protocol{}
	protocol.Set(definitions.ProtoHTTP)

	auth := &AuthState{
		deps: AuthDeps{
			Cfg:    cfg,
			Logger: logger,
		},
		Request: AuthRequest{
			HTTPClientContext: ctx,
			HTTPClientRequest: ctx.Request,
			NoAuth:            true,
			Protocol:          protocol,
			Method:            "plain",
		},
		Runtime: AuthRuntime{
			GUID: guid,
		},
	}

	auth.WithUserAgent(ctx)
	auth.WithXSSL(ctx)

	return auth
}

// protectedEndpointClient resolves the effective client address for protected endpoints.
func protectedEndpointClient(ctx *gin.Context, cfg config.File, logger *slog.Logger, auth *AuthState) (string, string) {
	clientIP := ctx.GetHeader("Client-IP")
	clientPort := util.WithNotAvailable(ctx.GetHeader("X-Client-Port"))

	if clientIP == "" {
		clientIP, clientPort, _ = net.SplitHostPort(ctx.Request.RemoteAddr)
	}

	util.ProcessXForwardedFor(ctx, cfg, logger, &clientIP, &clientPort, &auth.Request.XSSL)

	if clientIP == "" {
		clientIP = definitions.NotAvailable
	}

	if clientPort == "" {
		clientPort = definitions.NotAvailable
	}

	return clientIP, clientPort
}

// handleProtectedPreAuthBruteForce applies configured and fallback pre-auth brute-force decisions.
func handleProtectedPreAuthBruteForce(ctx *gin.Context, auth *AuthState) bool {
	if auth.applyConfiguredPreAuthDecision(ctx) {
		return true
	}

	if auth.applyConfiguredPreAuthControl(ctx, definitions.AuthResultFail) || auth.HasConfiguredPreAuthPolicyAuthority(ctx) {
		return false
	}

	if auth.applyDefaultPreAuthDecision(ctx) {
		return true
	}

	auth.markEnvironmentRejected(ctx)
	auth.UpdateBruteForceBucketsCounter(ctx)
	protectedPostLuaAction(ctx, auth)
	auth.AuthFail(ctx)
	ctx.Abort()

	return true
}

// handleProtectedEnvironment turns environment decisions into HTTP responses.
func handleProtectedEnvironment(ctx *gin.Context, auth *AuthState) bool {
	//nolint:exhaustive // Ignore some results
	switch auth.HandleEnvironment(ctx) {
	case definitions.AuthResultPreAuthTLS:
		protectedPostLuaAction(ctx, auth)
		HandleErrWithDeps(ctx, errors.ErrNoTLS, auth.deps)
		ctx.Abort()

		return true
	case definitions.AuthResultPreAuthRelayDomain, definitions.AuthResultPreAuthRBL, definitions.AuthResultLuaEnvironment:
		protectedPostLuaAction(ctx, auth)
		auth.AuthFail(ctx)
		ctx.Abort()

		return true
	case definitions.AuthResultTempFail:
		protectedPostLuaAction(ctx, auth)
		auth.AuthTempFail(ctx, definitions.TempFailDefault)
		ctx.Abort()

		return true
	default:
		return false
	}
}

// protectedPostLuaAction runs post-action hooks with a pooled empty PassDB result.
func protectedPostLuaAction(ctx *gin.Context, auth *AuthState) {
	result := GetPassDBResultFromPool()
	auth.PostLuaAction(ctx, result)
	PutPassDBResultToPool(result)
}
