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

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
)

// ProtectEndpointMiddleware is a Gin middleware that performs authentication and security checks for HTTP requests.
// It handles client IP extraction, brute force detection, protocol handling, and various authentication features.
func ProtectEndpointMiddleware(cfg config.File, logger *slog.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		guid := ctx.GetString(definitions.CtxGUIDKey) // MiddleWare behind Logger!

		protocol := &config.Protocol{}
		protocol.Set(definitions.ProtoHTTP)

		clientIP := ctx.GetHeader("Client-IP")
		clientPort := util.WithNotAvailable(ctx.GetHeader("X-Client-Port"))

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

		auth.Request.ClientIP = clientIP
		auth.Request.XClientPort = clientPort

		// Store remote client IP into connection context. It can be used for brute force updates.
		ctx.Set(definitions.CtxClientIPKey, clientIP)

		if auth.CheckBruteForce(ctx) {
			auth.UpdateBruteForceBucketsCounter(ctx)
			result := GetPassDBResultFromPool()
			auth.PostLuaAction(ctx, result)
			PutPassDBResultToPool(result)
			auth.AuthFail(ctx)
			ctx.Abort()

			return
		}

		//nolint:exhaustive // Ignore some results
		switch auth.HandleFeatures(ctx) {
		case definitions.AuthResultFeatureTLS:
			result := GetPassDBResultFromPool()
			auth.PostLuaAction(ctx, result)
			PutPassDBResultToPool(result)
			HandleErrWithDeps(ctx, errors.ErrNoTLS, auth.deps)
			ctx.Abort()

			return
		case definitions.AuthResultFeatureRelayDomain, definitions.AuthResultFeatureRBL, definitions.AuthResultFeatureLua:
			result := GetPassDBResultFromPool()
			auth.PostLuaAction(ctx, result)
			PutPassDBResultToPool(result)
			auth.AuthFail(ctx)
			ctx.Abort()

			return
		case definitions.AuthResultUnset:
		case definitions.AuthResultOK:
		case definitions.AuthResultFail:
		case definitions.AuthResultTempFail:
			result := GetPassDBResultFromPool()
			auth.PostLuaAction(ctx, result)
			PutPassDBResultToPool(result)
			auth.AuthTempFail(ctx, definitions.TempFailDefault)
			ctx.Abort()

			return
		case definitions.AuthResultEmptyUsername:
		case definitions.AuthResultEmptyPassword:
		}

		ctx.Next()
	}
}
