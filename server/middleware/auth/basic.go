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
	"strconv"
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

// NewHTTPCallerGuard classifies the caller of an HTTP backchannel request for failure accounting.
// Untrusted callers are locked out by the client IP resolved through runtime.servers.http.trusted_proxies;
// the exemption only ever considers the direct peer. HTTP has no dedicated client CA for backchannel
// callers, so client certificates never exempt an HTTP caller.
func NewHTTPCallerGuard(ctx *gin.Context, cfg config.File, logger *slog.Logger) *CallerGuard {
	return NewCallerGuard(cfg, logger, CallerIdentity{
		IP:        requestClientIP(ctx, cfg),
		PeerIP:    directPeerIP(ctx),
		Presented: PresentedCredentialIdentity(ctx.Request.Header.Values("Authorization")),
		Transport: CallerTransportHTTP,
	})
}

// isAuthBypassPath reports routes whose credentials never feed the backchannel caller lockout.
func isAuthBypassPath(ctx *gin.Context) bool {
	switch ctx.FullPath() {
	case authBypassPingPath, authBypassHealthPath, authBypassMetricsPath:
		return true
	default:
		return false
	}
}

// MaybeThrottleAuthByIP checks if the client IP is temporarily blocked and, if so, responds with 429 and a Retry-After header.
// It only enforces throttling if the brute-force control is enabled in the configuration.
func MaybeThrottleAuthByIP(ctx *gin.Context, cfg config.File) bool {
	if isAuthBypassPath(ctx) {
		return false
	}

	return AbortIfThrottled(ctx, NewHTTPCallerGuard(ctx, cfg, nil))
}

// AbortIfThrottled answers 429 with Retry-After when guard reports an active lockout before the
// credentials are checked. Exempt callers are never refused here.
func AbortIfThrottled(ctx *gin.Context, guard *CallerGuard) bool {
	return abortThrottled(ctx, guard.Throttled)
}

// AbortIfRejectionThrottled answers 429 with Retry-After when rejected credentials meet an active lockout,
// including the per-identity lockout of exempt callers.
func AbortIfRejectionThrottled(ctx *gin.Context, guard *CallerGuard) bool {
	return abortThrottled(ctx, guard.RejectionThrottled)
}

// abortThrottled writes the uniform throttling response when check reports an active lockout.
func abortThrottled(ctx *gin.Context, check func() (bool, time.Duration)) bool {
	exceeded, remaining := check()
	if !exceeded {
		return false
	}

	ctx.Set(definitions.CtxRateLimitReasonKey, "brute-force")
	ctx.Header("Retry-After", strconv.Itoa(int(remaining.Seconds())))
	ctx.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
		definitions.LogKeyMsg: "Too many authentication failures",
		"scope":               "brute-force",
	})

	return true
}

// ApplyAuthBackoffOnFailure notes a failure for this IP and sleeps a short duration.
func ApplyAuthBackoffOnFailure(ctx *gin.Context) {
	ApplyAuthBackoffOnFailureWithCfg(ctx, nil)
}

// ApplyAuthBackoffOnFailureWithCfg notes a rejected credential for the trusted client IP
// resolved from the request and applies the configured delay.
func ApplyAuthBackoffOnFailureWithCfg(ctx *gin.Context, cfg config.File) {
	if isAuthBypassPath(ctx) {
		time.Sleep(sleepOnFail(cfg))

		return
	}

	NewHTTPCallerGuard(ctx, cfg, nil).Reject("invalid credentials")
}

// CheckAndRequireBasicAuth enforces basic authentication if it's enabled in the server configuration.
// It validates credentials provided in the request against the configured username and password.
// Returns true if authentication is successful or not required, false if the authentication fails or is throttled.
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

	guard := NewHTTPCallerGuard(ctx, cfg, nil)
	bypass := isAuthBypassPath(ctx)

	// Simple per-IP throttling for repeated failures
	if !bypass && AbortIfThrottled(ctx, guard) {
		return false
	}

	username, password, ok := ctx.Request.BasicAuth()
	if ok && ValidateBasicCredentials(cfg, username, password) {
		ctx.Set(definitions.CtxBasicAuthValidatedKey, true)
		ctx.Set(definitions.CtxAuthMethodKey, "basic_auth")

		if !bypass {
			guard.Accept()
		}

		return true
	}

	// Failure: count + small fixed delay, then respond uniformly
	if bypass {
		time.Sleep(sleepOnFail(cfg))
	} else {
		if AbortIfRejectionThrottled(ctx, guard) {
			return false
		}

		guard.Reject("invalid basic credentials")
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
