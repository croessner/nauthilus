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
// issued by the Nauthilus IDP (client_credentials flow). It replaces the
// legacy HS256 JWT mechanism for backchannel API authentication.
package oidcbearer

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	servererrors "github.com/croessner/nauthilus/v4/server/errors"
	mdauth "github.com/croessner/nauthilus/v4/server/middleware/auth"
	"github.com/croessner/nauthilus/v4/server/tokenclaims"
	"github.com/croessner/nauthilus/v4/server/util"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// TokenValidator abstracts the token validation interface so the middleware
// can be tested without a full NauthilusIDP instance.
type TokenValidator interface {
	ValidateToken(ctx context.Context, tokenString string) (jwt.MapClaims, error)
}

const (
	oidcBearerResponseKeyError    = "error"
	oidcBearerUnauthorizedMessage = "missing or invalid authorization header"
	oidcBearerInvalidTokenMessage = "invalid token"

	retryAfterHeader = "Retry-After"
	// tokenValidationRetryAfterSeconds asks clients to retry an undecided validation soon instead of
	// treating it as rejected credentials.
	tokenValidationRetryAfterSeconds = "1"
)

// EnforceBearerScopeAuthOptions describes the exported EnforceBearerScopeAuthOptions type.
type EnforceBearerScopeAuthOptions struct {
	RequiredScopes      []string
	MissingScopeMessage string
	DelayOnMissingToken bool
}

// Middleware returns a Gin middleware that extracts a Bearer token from the
// Authorization header, validates it via the IDP, and stores the resulting
// claims and caller in the Gin context.
//
// It authenticates only. Every route names the scopes it requires through RequireAnyScope.
func Middleware(validator TokenValidator, cfg config.File, logger *slog.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if !AuthorizeBackchannelToken(ctx, validator, cfg, logger) {
			return
		}

		ctx.Next()
	}
}

// RequireAnyScope enforces the route-specific scopes of an authenticated backchannel caller. Basic and Bearer
// callers are authorized alike through the scopes they hold; only the unrestricted Basic credential passes
// without one, because it remains the administrative management credential.
func RequireAnyScope(requiredScopes ...string) gin.HandlerFunc {
	scopes := append([]string(nil), requiredScopes...)

	return func(ctx *gin.Context) {
		if len(scopes) == 0 {
			ctx.Next()

			return
		}

		caller := mdauth.CallerFromContext(ctx)
		if caller == nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{oidcBearerResponseKeyError: oidcBearerUnauthorizedMessage})

			return
		}

		if !caller.Grants(scopes...) {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{oidcBearerResponseKeyError: MissingScopeMessage(scopes...)})

			return
		}

		ctx.Next()
	}
}

// AuthorizeBackchannelToken authenticates the Bearer token of a backchannel request and stores its claims and
// caller in the Gin context. It requires no scope: the route decides which scopes it needs.
func AuthorizeBackchannelToken(
	ctx *gin.Context,
	validator TokenValidator,
	cfg config.File,
	logger *slog.Logger,
) bool {
	_, ok := EnforceBearerScopeAuth(ctx, validator, cfg, EnforceBearerScopeAuthOptions{DelayOnMissingToken: true})
	if !ok {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			cfg,
			logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "Backchannel Bearer token was not accepted",
		)

		return false
	}

	return true
}

// CallerFromClaims maps validated backchannel token claims to the caller they authenticate.
func CallerFromClaims(claims jwt.MapClaims) *mdauth.Caller {
	if claims == nil {
		return nil
	}

	clientID, _ := claims[definitions.ClaimClientID].(string)

	return mdauth.NewScopedCaller(mdauth.CallerMethodBearer, clientID, tokenclaims.Scopes(claims))
}

// EnforceBearerScopeAuth validates the Bearer token of the request, enforces the required scopes, and
// records the outcome in the backchannel caller accounting.
func EnforceBearerScopeAuth(
	ctx *gin.Context,
	validator TokenValidator,
	cfg config.File,
	options EnforceBearerScopeAuthOptions,
) (jwt.MapClaims, bool) {
	accounting := mdauth.NewHTTPCallerAccounting(ctx, cfg, nil)

	tokenString, ok := ExtractBearerToken(ctx)
	if !ok {
		rejectMissingBearerToken(ctx, accounting, options.DelayOnMissingToken)

		return nil, false
	}

	claims := validateAndStoreClaims(ctx, validator, accounting, tokenString)
	if claims == nil {
		return nil, false
	}

	if len(options.RequiredScopes) > 0 && !HasAnyScope(claims, options.RequiredScopes...) {
		msg := options.MissingScopeMessage
		if msg == "" {
			msg = "insufficient permissions"
		}

		accounting.Deny()
		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{oidcBearerResponseKeyError: msg})

		return nil, false
	}

	accounting.Accept()

	return claims, true
}

// rejectMissingBearerToken answers a request without Bearer token. Only routes that require a token
// treat the attempt as a rejected credential and delay it.
func rejectMissingBearerToken(ctx *gin.Context, accounting *mdauth.CallerAccounting, delay bool) {
	if !delay {
		accounting.Deny()
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{oidcBearerResponseKeyError: oidcBearerUnauthorizedMessage})

		return
	}

	accounting.Reject("missing bearer token")
	ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{oidcBearerResponseKeyError: oidcBearerUnauthorizedMessage})
}

// ValidateAndStoreClaims validates the given bearer token, stores the resulting
// claims in the Gin context under definitions.CtxOIDCClaimsKey, and delays
// rejected tokens. Returns the claims on success or nil on failure
// (request is aborted with 401, or 503 when validation could not decide).
//
// This is the shared validation core used by both Middleware (for backchannel
// API endpoints) and HasRequiredScopes in the hook package (for custom hooks).
func ValidateAndStoreClaims(ctx *gin.Context, validator TokenValidator, cfg config.File, tokenString string) jwt.MapClaims {
	accounting := mdauth.NewHTTPCallerAccounting(ctx, cfg, nil)

	claims := validateAndStoreClaims(ctx, validator, accounting, tokenString)
	if claims != nil {
		accounting.Accept()
	}

	return claims
}

// validateAndStoreClaims validates tokenString and separates rejected tokens, which are delayed, from
// validations the token store could not decide, which answer 503 and are never treated as rejections.
func validateAndStoreClaims(ctx *gin.Context, validator TokenValidator, accounting *mdauth.CallerAccounting, tokenString string) jwt.MapClaims {
	claims, err := validator.ValidateToken(ctx.Request.Context(), tokenString)
	if err != nil {
		if servererrors.IsTokenValidationUnavailable(err) {
			accounting.Unavailable()
			ctx.Header(retryAfterHeader, tokenValidationRetryAfterSeconds)
			ctx.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{oidcBearerResponseKeyError: "temporarily_unavailable"})

			return nil
		}

		accounting.Reject("invalid bearer token")
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{oidcBearerResponseKeyError: oidcBearerInvalidTokenMessage})

		return nil
	}

	if !IsBackchannelAccessToken(claims) {
		accounting.Deny()
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{oidcBearerResponseKeyError: oidcBearerInvalidTokenMessage})

		return nil
	}

	BindClaims(ctx, claims)

	return claims
}

// BindClaims stores validated backchannel token claims and the caller they authenticate in the Gin context for
// downstream handlers. Only code that validated the token itself may call it.
func BindClaims(ctx *gin.Context, claims jwt.MapClaims) {
	ctx.Set(definitions.CtxOIDCClaimsKey, claims)
	mdauth.StoreCaller(ctx, CallerFromClaims(claims))
}

// IsBackchannelAccessToken reports whether claims target the protected backchannel API.
func IsBackchannelAccessToken(claims jwt.MapClaims) bool {
	return HasTokenType(claims, definitions.TokenTypeAccessToken) &&
		hasServiceTokenClientID(claims) &&
		hasExactAudienceSet(claims, definitions.AudienceBackchannelAPI)
}

// hasServiceTokenClientID requires the issuer-owned discriminator emitted only for service tokens.
func hasServiceTokenClientID(claims jwt.MapClaims) bool {
	if claims == nil {
		return false
	}

	clientID, ok := claims[definitions.ClaimClientID].(string)

	return ok && clientID != ""
}

// HasTokenType reports whether the claims carry exactly the given Nauthilus token type.
func HasTokenType(claims jwt.MapClaims, tokenType string) bool {
	return tokenclaims.HasTokenType(claims, tokenType)
}

// HasAudience reports whether the normalized audience set contains audience.
func HasAudience(claims jwt.MapClaims, audience string) bool {
	return tokenclaims.HasAudience(claims, audience)
}

// hasExactAudienceSet reports whether the token targets exactly the expected audience.
func hasExactAudienceSet(claims jwt.MapClaims, expected string) bool {
	return tokenclaims.HasExactAudienceSet(claims, expected)
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

// HasScope reports whether the scope claim contains scope exactly.
func HasScope(claims jwt.MapClaims, scope string) bool {
	return tokenclaims.HasScope(claims, scope)
}

// HasAnyScope reports whether the scope claim contains at least one of scopes.
func HasAnyScope(claims jwt.MapClaims, scopes ...string) bool {
	return tokenclaims.HasAnyScope(claims, scopes...)
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

// MissingScopeMessage renders a compact scope error without exposing token data.
func MissingScopeMessage(scopes ...string) string {
	if len(scopes) == 0 {
		return "insufficient permissions"
	}

	return "missing required scope: " + strings.Join(scopes, " or ")
}
