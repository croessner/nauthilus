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

// Package auth provides auth functionality.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"github.com/croessner/nauthilus/v4/server/util"

	"github.com/gin-gonic/gin"
)

const (
	authBypassHealthPath  = "/healthz"
	authBypassMetricsPath = "/metrics"
	authBypassPingPath    = "/ping"
)

// secureCompare compares two strings in constant time by hashing them first.
func secureCompare(a, b string) bool {
	h1 := sha256.Sum256([]byte(a))
	h2 := sha256.Sum256([]byte(b))

	return subtle.ConstantTimeCompare(h1[:], h2[:]) == 1
}

// ValidateBasicCredentials compares submitted Basic credentials with the
// configured backchannel Basic Auth credentials.
func ValidateBasicCredentials(cfg config.File, username, password string) bool {
	if cfg == nil || cfg.GetServer() == nil {
		return false
	}

	return ValidateBasicAuthCredentials(cfg.GetServer().GetBasicAuth(), username, password)
}

// ValidateBasicAuthCredentials compares submitted Basic credentials with the
// provided BasicAuth settings.
func ValidateBasicAuthCredentials(basicAuth *config.BasicAuth, username, password string) bool {
	if basicAuth == nil || !basicAuth.IsEnabled() {
		return false
	}

	if basicAuth.GetUsername() == "" || basicAuth.GetPassword().IsZero() {
		return false
	}

	expectedPassword := ""

	basicAuth.GetPassword().WithString(func(value string) {
		expectedPassword = value
	})

	return secureCompare(username, basicAuth.GetUsername()) && secureCompare(password, expectedPassword)
}

// NewHTTPCallerAccounting records the outcome of an HTTP backchannel caller. The client IP is resolved
// through runtime.servers.http.trusted_proxies and only ever logged.
func NewHTTPCallerAccounting(ctx *gin.Context, cfg config.File, logger *slog.Logger) *CallerAccounting {
	return NewCallerAccounting(logger, CallerTransportHTTP, requestClientIP(ctx, cfg))
}

// isAuthBypassPath reports routes whose rejected credentials are delayed without caller accounting.
func isAuthBypassPath(ctx *gin.Context) bool {
	switch ctx.FullPath() {
	case authBypassPingPath, authBypassHealthPath, authBypassMetricsPath:
		return true
	default:
		return false
	}
}

// ApplyAuthBackoffOnFailure delays a rejected credential by the fixed rejection delay. Outside the
// bypass routes the rejection is also accounted for the client IP resolved from the request.
func ApplyAuthBackoffOnFailure(ctx *gin.Context, cfg config.File) {
	if isAuthBypassPath(ctx) {
		time.Sleep(callerRejectionDelay)

		return
	}

	NewHTTPCallerAccounting(ctx, cfg, nil).Reject("invalid credentials")
}

// CheckAndRequireBasicAuth enforces basic authentication if it's enabled in the server configuration.
// It validates credentials provided in the request against the configured username and password.
// Returns true if authentication is successful or not required, false if the authentication fails.
func CheckAndRequireBasicAuth(ctx *gin.Context, cfg config.File) bool {
	return CheckAndRequireBasicAuthWithCfg(ctx, cfg)
}

// CheckAndRequireBasicAuthWithCfg provides the exported CheckAndRequireBasicAuthWithCfg function.
func CheckAndRequireBasicAuthWithCfg(ctx *gin.Context, cfg config.File) bool {
	if cfg == nil {
		return true
	}

	if !cfg.GetServer().GetBasicAuth().IsEnabled() {
		return true
	}

	bypass := isAuthBypassPath(ctx)

	username, password, ok := ctx.Request.BasicAuth()
	if ok && ValidateBasicCredentials(cfg, username, password) {
		ctx.Set(definitions.CtxBasicAuthValidatedKey, true)
		ctx.Set(definitions.CtxAuthMethodKey, "basic_auth")

		if !bypass {
			NewHTTPCallerAccounting(ctx, cfg, nil).Accept()
		}

		return true
	}

	// Failure: fixed delay, then respond uniformly. Callers are never blocked.
	if bypass {
		time.Sleep(callerRejectionDelay)
	} else {
		NewHTTPCallerAccounting(ctx, cfg, nil).Reject("invalid basic credentials")
	}

	ctx.Header("WWW-Authenticate", "Basic realm=\"restricted\", charset=\"UTF-8\"")
	ctx.AbortWithStatus(http.StatusUnauthorized)

	return false
}

// AuthorizeBasicAuthWithDeps validates Basic Auth for the current request and
// keeps the route-specific behavior used by the backchannel middleware.
func AuthorizeBasicAuthWithDeps(ctx *gin.Context, cfg config.File, logger *slog.Logger) bool {
	guid := ctx.GetString(definitions.CtxGUIDKey)
	cat, svc := basicAuthRouteContext(ctx)

	if !requireBasicAuthRouteContext(ctx, logger, guid, cat, svc) {
		return false
	}

	// Note: Chicken-egg problem.
	if cat == definitions.CatAuth && svc == definitions.ServBasic {
		_ = level.Warn(logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "Disabling HTTP basic Auth",
			"category", cat,
			"service", svc,
		)

		return true
	}

	return CheckAndRequireBasicAuthWithCfg(ctx, cfg)
}

// basicAuthRouteContext resolves category and service from context or route path.
func basicAuthRouteContext(ctx *gin.Context) (string, string) {
	cat := ctx.GetString(definitions.CtxCategoryKey)
	svc := ctx.GetString(definitions.CtxServiceKey)

	if cat != "" && svc != "" {
		return cat, svc
	}

	parts := strings.Split(strings.Trim(ctx.FullPath(), "/"), "/")
	if len(parts) < 4 || parts[0] != "api" || parts[1] != "v1" {
		return cat, svc
	}

	if cat == "" {
		cat = parts[2]
		ctx.Set(definitions.CtxCategoryKey, cat)
	}

	if svc == "" {
		svc = parts[3]
		ctx.Set(definitions.CtxServiceKey, svc)
	}

	return cat, svc
}

// requireBasicAuthRouteContext aborts the request when routing metadata is missing.
func requireBasicAuthRouteContext(ctx *gin.Context, logger *slog.Logger, guid string, cat string, svc string) bool {
	if cat != "" && svc != "" {
		return true
	}

	_ = level.Error(logger).Log(
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, "missing routing context keys",
		definitions.LogKeyError, "missing routing context keys",
		"category", cat,
		"service", svc,
	)

	ctx.AbortWithStatus(http.StatusInternalServerError)

	return false
}

// requestClientIP resolves the request IP through the shared trusted proxy helper.
func requestClientIP(ctx *gin.Context, cfg config.File) string {
	return util.RequestClientIPWithConfig(ctx, cfg, nil)
}

// BasicAuthMiddlewareWithDeps returns a Gin middleware that enforces the
// configured Basic Auth credentials for protected backchannel routes.
func BasicAuthMiddlewareWithDeps(cfg config.File, logger *slog.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if !AuthorizeBasicAuthWithDeps(ctx, cfg, logger) {
			return
		}

		ctx.Next()
	}
}
