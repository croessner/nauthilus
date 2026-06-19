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

// Package logging provides logging functionality.
package logging

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/util"

	"github.com/gin-gonic/gin"
	"github.com/segmentio/ksuid"
)

// LoggerMiddleware is a deps-based variant of LoggerMiddleware.
//
// HTTP stack should not rely on `log.Logger` globals.
// Call sites that are already DI-based should pass an injected `*slog.Logger`.
func LoggerMiddleware(logger *slog.Logger) gin.HandlerFunc {
	return LoggerMiddlewareWithConfig(logger, nil)
}

// LoggerMiddlewareWithConfig logs each HTTP request using the configured
// trusted proxy rules when resolving the client IP.
func LoggerMiddlewareWithConfig(logger *slog.Logger, cfg config.File) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		guid := ksuid.New().String()
		ctx.Set(definitions.CtxGUIDKey, guid)
		ctx.Set(definitions.CtxLocalCacheAuthKey, false)

		start := time.Now()

		ctx.Next()

		err := ctx.Errors.Last()
		activeLogger := loggerWithDefault(logger)
		keyvals := requestLogFields(ctx, cfg, activeLogger, guid, time.Since(start), err)

		_ = requestLogWrapper(ctx.Writer.Status(), err)(activeLogger).Log(keyvals...)
	}
}

// loggerWithDefault returns the process default logger when no logger was injected.
func loggerWithDefault(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return slog.Default()
	}

	return logger
}

// requestLogWrapper selects the log level wrapper for the completed request.
func requestLogWrapper(status int, err *gin.Error) func(logger *slog.Logger) level.Logger {
	if err != nil {
		return level.Error
	}

	if status == http.StatusTooManyRequests {
		return level.Warn
	}

	return level.Info
}

// requestLogFields builds the structured access-log attributes for a request.
func requestLogFields(
	ctx *gin.Context,
	cfg config.File,
	logger *slog.Logger,
	guid string,
	latency time.Duration,
	err *gin.Error,
) []any {
	negotiatedProtocol, cipherSuiteName := requestTLSInfo(ctx)
	keyvals := []any{
		definitions.LogKeyGUID, guid,
		definitions.LogKeyClientIP, util.RequestClientIPWithConfig(ctx, cfg, logger),
		definitions.LogKeyMethod, ctx.Request.Method,
		definitions.LogKeyProtocol, ctx.Request.Proto,
		definitions.LogKeyHTTPStatus, ctx.Writer.Status(),
		definitions.LogKeyLatency, util.FormatDurationMs(latency),
		definitions.LogKeyUserAgent, requestUserAgent(ctx),
		definitions.LogKeyTLSSecure, negotiatedProtocol,
		definitions.LogKeyTLSCipher, cipherSuiteName,
		definitions.LogKeyURIPath, ctx.Request.URL.Path,
		definitions.LogKeyAuthMethod, requestAuthType(ctx),
		definitions.LogKeyMsg, requestLogMessage(err),
	}

	if reason, exists := ctx.Get(definitions.CtxRateLimitReasonKey); exists {
		keyvals = append(keyvals, definitions.LogKeyRateLimitReason, reason)
	}

	if externalSessionID := strings.TrimSpace(ctx.GetString(definitions.CtxExternalSessionKey)); externalSessionID != "" {
		keyvals = append(keyvals, definitions.LogKeyExternalSession, externalSessionID)
	}

	return keyvals
}

// requestTLSInfo returns the negotiated TLS protocol and cipher names.
func requestTLSInfo(ctx *gin.Context) (string, string) {
	if ctx.Request.TLS == nil {
		return definitions.NotAvailable, definitions.NotAvailable
	}

	return tls.VersionName(ctx.Request.TLS.Version), tls.CipherSuiteName(ctx.Request.TLS.CipherSuite)
}

// requestAuthType resolves the access-log authentication method.
func requestAuthType(ctx *gin.Context) string {
	if authMethod, exists := ctx.Get(definitions.CtxAuthMethodKey); exists {
		if method, ok := authMethod.(string); ok && method != "" {
			return method
		}
	}

	authHeader := ctx.Request.Header.Get("Authorization")
	if authHeader == "" {
		return "none"
	}

	if strings.HasPrefix(authHeader, "Basic ") {
		return "basic"
	}

	if strings.HasPrefix(authHeader, "Bearer ") {
		return "bearer"
	}

	return "other"
}

// requestUserAgent returns a stable fallback for empty User-Agent headers.
func requestUserAgent(ctx *gin.Context) string {
	if ctx.Request.UserAgent() == "" {
		return definitions.NotAvailable
	}

	return ctx.Request.UserAgent()
}

// requestLogMessage returns the access-log message for success or failure.
func requestLogMessage(err *gin.Error) string {
	if err != nil {
		return err.Error()
	}

	return "HTTP request"
}
