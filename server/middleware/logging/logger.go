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

package logging

import (
	"crypto/tls"
	"log/slog"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-gonic/gin"
	"github.com/segmentio/ksuid"
)

// LoggerMiddleware creates a middleware for logging HTTP requests and responses, including latency and client details.
// It assigns a unique identifier (GUID) to each request and logs authentication methods, TLS info, and status codes.
func LoggerMiddleware() gin.HandlerFunc {
	return LoggerMiddlewareWithLogger(log.Logger)
}

// LoggerMiddlewareWithLogger is a deps-based variant of LoggerMiddleware.
//
// HTTP stack should not rely on `log.Logger` globals.
// Call sites that are already DI-based should pass an injected `*slog.Logger`.
func LoggerMiddlewareWithLogger(logger *slog.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			logWrapper func(logger *slog.Logger) level.Logger
		)

		guid := ksuid.New().String()
		ctx.Set(definitions.CtxGUIDKey, guid)
		ctx.Set(definitions.CtxLocalCacheAuthKey, false)

		// Start timer
		start := time.Now()

		// Process request
		ctx.Next()

		err := ctx.Errors.Last()

		// Decide which logger to use
		if err != nil {
			logWrapper = level.Error
		} else {
			logWrapper = level.Info
		}

		// Stop timer
		end := time.Now()
		latency := end.Sub(start)

		negotiatedProtocol := definitions.NotAvailable
		cipherSuiteName := definitions.NotAvailable

		if ctx.Request.TLS != nil {
			negotiatedProtocol = tls.VersionName(ctx.Request.TLS.Version)
			cipherSuiteName = tls.CipherSuiteName(ctx.Request.TLS.CipherSuite)
		}

		// Determine authentication information
		authType := "none"

		// Check if authentication was attempted
		if ctx.Request.Header.Get("Authorization") != "" {
			if strings.HasPrefix(ctx.Request.Header.Get("Authorization"), "Basic ") {
				authType = "basic"
			} else if strings.HasPrefix(ctx.Request.Header.Get("Authorization"), "Bearer ") {
				authType = "bearer"
			} else {
				authType = "other"
			}
		}

		// Fall back to legacy global logger if caller passed nil.
		if logger == nil {
			logger = log.Logger
		}

		logWrapper(logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyClientIP, ctx.ClientIP(),
			definitions.LogKeyMethod, ctx.Request.Method,
			definitions.LogKeyProtocol, ctx.Request.Proto,
			definitions.LogKeyHTTPStatus, ctx.Writer.Status(),
			definitions.LogKeyLatency, util.FormatDurationMs(latency),
			definitions.LogKeyUserAgent, func() string {
				if ctx.Request.UserAgent() != "" {
					return ctx.Request.UserAgent()
				}

				return definitions.NotAvailable
			}(),
			definitions.LogKeyTLSSecure, negotiatedProtocol,
			definitions.LogKeyTLSCipher, cipherSuiteName,
			definitions.LogKeyUriPath, ctx.Request.URL.Path,
			definitions.LogKeyAuthMethod, authType,
			definitions.LogKeyMsg, func() string {
				if err != nil {
					return err.Error()
				}

				return "HTTP request"
			}(),
		)
	}
}
