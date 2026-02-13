// Copyright (C) 2025 Christian Rößner
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

// Package oidcbearer provides a Gin middleware that validates Bearer tokens
// issued by the Nauthilus IdP (client_credentials flow). It replaces the
// legacy HS256 JWT mechanism for backchannel API authentication.
package oidcbearer

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	mdauth "github.com/croessner/nauthilus/server/middleware/auth"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// TokenValidator abstracts the token validation interface so the middleware
// can be tested without a full NauthilusIdP instance.
type TokenValidator interface {
	ValidateToken(ctx context.Context, tokenString string) (jwt.MapClaims, error)
}

// Middleware returns a Gin middleware that extracts a Bearer token from the
// Authorization header, validates it via the IdP, and stores the resulting
// claims in the Gin context under definitions.CtxOIDCClaimsKey.
//
// The middleware also verifies that the token contains the "nauthilus:authenticate"
// scope, which is required for all backchannel API access.
func Middleware(validator TokenValidator, cfg config.File, logger *slog.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		tokenString, ok := ExtractBearerToken(ctx)
		if !ok {
			if mdauth.MaybeThrottleAuthByIP(ctx, cfg) {
				return
			}

			mdauth.ApplyAuthBackoffOnFailure(ctx)
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid authorization header"})

			return
		}

		claims := ValidateAndStoreClaims(ctx, validator, cfg, tokenString)
		if claims == nil {
			return
		}

		// Verify the authenticate scope is present
		if ctx.Query("mode") != "no-auth" {
			if !HasScope(claims, definitions.ScopeAuthenticate) {
				util.DebugModuleWithCfg(
					ctx.Request.Context(),
					cfg,
					logger,
					definitions.DbgIdp,
					definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
					definitions.LogKeyMsg, "OIDC token missing required scope: "+definitions.ScopeAuthenticate,
				)

				ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "missing required scope: " + definitions.ScopeAuthenticate})

				return
			}
		}

		ctx.Next()
	}
}

// ValidateAndStoreClaims validates the given bearer token, stores the resulting
// claims in the Gin context under definitions.CtxOIDCClaimsKey, and applies
// throttling on failure. Returns the claims on success or nil on failure
// (request is aborted with 401).
//
// This is the shared validation core used by both Middleware (for backchannel
// API endpoints) and HasRequiredScopes in the hook package (for custom hooks).
func ValidateAndStoreClaims(ctx *gin.Context, validator TokenValidator, cfg config.File, tokenString string) jwt.MapClaims {
	claims, err := validator.ValidateToken(ctx.Request.Context(), tokenString)
	if err != nil {
		if mdauth.MaybeThrottleAuthByIP(ctx, cfg) {
			return nil
		}

		mdauth.ApplyAuthBackoffOnFailure(ctx)
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})

		return nil
	}

	// Store claims in context for downstream handlers
	ctx.Set(definitions.CtxOIDCClaimsKey, claims)

	return claims
}

// ExtractBearerToken extracts the Bearer token from the Authorization header.
func ExtractBearerToken(ctx *gin.Context) (string, bool) {
	authHeader := ctx.GetHeader("Authorization")

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", false
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	if token == "" {
		return "", false
	}

	return token, true
}

// HasScope checks whether the given claims contain a specific scope.
// Scopes are stored as a space-separated string in the "scope" claim
// per RFC 6749 / RFC 9068.
func HasScope(claims jwt.MapClaims, scope string) bool {
	if claims == nil || scope == "" {
		return false
	}

	scopeStr, ok := claims["scope"].(string)
	if !ok {
		return false
	}

	for s := range strings.SplitSeq(scopeStr, " ") {
		if s == scope {
			return true
		}
	}

	return false
}

// HasAnyScope checks whether the given claims contain at least one of the specified scopes.
func HasAnyScope(claims jwt.MapClaims, scopes ...string) bool {
	for _, scope := range scopes {
		if HasScope(claims, scope) {
			return true
		}
	}

	return false
}

// GetClaimsFromContext retrieves the OIDC claims from the Gin context.
// Returns nil if no claims are stored.
func GetClaimsFromContext(ctx *gin.Context) jwt.MapClaims {
	claimsValue, exists := ctx.Get(definitions.CtxOIDCClaimsKey)
	if !exists {
		return nil
	}

	claims, ok := claimsValue.(jwt.MapClaims)
	if !ok {
		return nil
	}

	return claims
}

// HasScopeFromContext is a convenience function that checks if the current
// request's OIDC token contains the specified scope.
func HasScopeFromContext(ctx *gin.Context, scope string) bool {
	claims := GetClaimsFromContext(ctx)

	return HasScope(claims, scope)
}
