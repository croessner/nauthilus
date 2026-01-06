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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/jwtclaims"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	mdauth "github.com/croessner/nauthilus/server/middleware/auth"
	jwtapi "github.com/croessner/nauthilus/server/model/jwt"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

// JWTDeps bundles dependencies required by JWT request paths.
// Uses this to eliminate global Redis/config/logger access.
type JWTDeps struct {
	Cfg    config.File
	Logger *slog.Logger
	Redis  rediscli.Client
}

func (d JWTDeps) effectiveLogger() *slog.Logger {
	if d.Logger != nil {
		return d.Logger
	}

	return log.Logger
}

func (d JWTDeps) jwtConfig() *config.JWTAuth {
	return d.Cfg.GetServer().GetJWTAuth()
}

func (d JWTDeps) redisPrefix() string {
	return d.Cfg.GetServer().GetRedis().GetPrefix()
}

// GenerateJWTToken generates a JWT token for the given username and roles
func GenerateJWTToken(username string, roles []string) (string, int64, error) {
	jwtConfig := config.GetFile().GetServer().GetJWTAuth()

	if !jwtConfig.IsEnabled() {
		return "", 0, errors.New("JWT authentication is not enabled")
	}

	// Set token expiry time
	expiryTime := time.Now().Add(jwtConfig.GetTokenExpiry())
	if jwtConfig.GetTokenExpiry() == 0 {
		// Default to 1 hour if not specified
		expiryTime = time.Now().Add(time.Hour)
	}

	// Create claims
	claims := jwtclaims.Claims{
		Username: username,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiryTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "nauthilus",
			Subject:   username,
		},
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token with secret key
	tokenString, err := token.SignedString([]byte(jwtConfig.GetSecretKey()))
	if err != nil {
		return "", 0, err
	}

	return tokenString, expiryTime.Unix(), nil
}

// GenerateRefreshToken generates a refresh token for the given username
func GenerateRefreshToken(username string) (string, error) {
	jwtConfig := config.GetFile().GetServer().GetJWTAuth()

	if !jwtConfig.IsEnabled() || !jwtConfig.IsRefreshTokenEnabled() {
		return "", errors.New("JWT refresh tokens are not enabled")
	}

	// Set token expiry time (refresh tokens typically last longer)
	expiryTime := time.Now().Add(jwtConfig.GetRefreshTokenExpiry())
	if jwtConfig.GetRefreshTokenExpiry() == 0 {
		// Default to 24 hours if not specified
		expiryTime = time.Now().Add(24 * time.Hour)
	}

	// Create claims
	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expiryTime),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "nauthilus",
		Subject:   username,
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token with secret key
	tokenString, err := token.SignedString([]byte(jwtConfig.GetSecretKey()))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// StoreTokenInRedis stores a JWT token in Redis for multi-instance compatibility
func StoreTokenInRedis(ctx context.Context, username, token string, expiresAt int64) error {
	deps := JWTDeps{Cfg: config.GetFile(), Logger: log.Logger, Redis: getDefaultRedisClient()}

	return StoreTokenInRedisWithDeps(ctx, username, token, expiresAt, deps)
}

func StoreTokenInRedisWithDeps(ctx context.Context, username, token string, expiresAt int64, deps JWTDeps) error {
	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	if deps.Cfg == nil {
		return errors.New("config is nil")
	}

	if deps.Redis == nil {
		return errors.New("redis client is nil")
	}

	if !deps.jwtConfig().IsStoreInRedisEnabled() {
		return nil
	}

	// Calculate TTL based on expiry time
	ttl := time.Until(time.Unix(expiresAt, 0))
	if ttl <= 0 {
		return errors.New("token has already expired")
	}

	key := fmt.Sprintf(deps.redisPrefix()+"jwt:token:%s", username)

	return deps.Redis.GetWriteHandle().Set(ctx, key, token, ttl).Err()
}

// StoreRefreshTokenInRedis stores a JWT refresh token in Redis for multi-instance compatibility
func StoreRefreshTokenInRedis(ctx context.Context, username, refreshToken string) error {
	deps := JWTDeps{Cfg: config.GetFile(), Logger: log.Logger, Redis: getDefaultRedisClient()}

	return StoreRefreshTokenInRedisWithDeps(ctx, username, refreshToken, deps)
}

func StoreRefreshTokenInRedisWithDeps(ctx context.Context, username, refreshToken string, deps JWTDeps) error {
	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	if deps.Cfg == nil {
		return errors.New("config is nil")
	}

	if deps.Redis == nil {
		return errors.New("redis client is nil")
	}

	jwtConfig := deps.jwtConfig()
	if !jwtConfig.IsStoreInRedisEnabled() {
		return nil
	}

	key := fmt.Sprintf(deps.redisPrefix()+"jwt:refresh:%s", username)

	// Determine expiry time
	expiry := jwtConfig.GetRefreshTokenExpiry()
	if expiry == 0 {
		// Default to 24 hours if not specified
		expiry = 24 * time.Hour
	}

	return deps.Redis.GetWriteHandle().Set(ctx, key, refreshToken, expiry).Err()
}

// GetTokenFromRedis retrieves a JWT token from Redis
func GetTokenFromRedis(ctx context.Context, username string) (string, error) {
	deps := JWTDeps{Cfg: config.GetFile(), Logger: log.Logger, Redis: getDefaultRedisClient()}

	return GetTokenFromRedisWithDeps(ctx, username, deps)
}

func GetTokenFromRedisWithDeps(ctx context.Context, username string, deps JWTDeps) (string, error) {
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	if deps.Cfg == nil {
		return "", errors.New("config is nil")
	}

	if deps.Redis == nil {
		return "", errors.New("redis client is nil")
	}

	if !deps.jwtConfig().IsStoreInRedisEnabled() {
		return "", errors.New("redis storage is not enabled for JWT tokens")
	}

	key := fmt.Sprintf(deps.redisPrefix()+"jwt:token:%s", username)

	token, err := deps.Redis.GetReadHandle().Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", errors.New("token not found in Redis")
		}

		return "", err
	}

	return token, nil
}

// GetRefreshTokenFromRedis retrieves a JWT refresh token from Redis
func GetRefreshTokenFromRedis(ctx context.Context, username string) (string, error) {
	deps := JWTDeps{Cfg: config.GetFile(), Logger: log.Logger, Redis: getDefaultRedisClient()}

	return GetRefreshTokenFromRedisWithDeps(ctx, username, deps)
}

func GetRefreshTokenFromRedisWithDeps(ctx context.Context, username string, deps JWTDeps) (string, error) {
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	if deps.Cfg == nil {
		return "", errors.New("config is nil")
	}

	if deps.Redis == nil {
		return "", errors.New("redis client is nil")
	}

	if !deps.jwtConfig().IsStoreInRedisEnabled() {
		return "", errors.New("redis storage is not enabled for JWT tokens")
	}

	key := fmt.Sprintf(deps.redisPrefix()+"jwt:refresh:%s", username)

	token, err := deps.Redis.GetReadHandle().Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", errors.New("refresh token not found in Redis")
		}

		return "", err
	}

	return token, nil
}

// ValidateJWTToken validates a JWT token and returns the claims
func ValidateJWTToken(ctx context.Context, tokenString string) (*jwtclaims.Claims, error) {
	deps := JWTDeps{Cfg: config.GetFile(), Logger: log.Logger, Redis: getDefaultRedisClient()}

	return ValidateJWTTokenWithDeps(ctx, tokenString, deps)
}

func ValidateJWTTokenWithDeps(ctx context.Context, tokenString string, deps JWTDeps) (*jwtclaims.Claims, error) {
	if deps.Cfg == nil {
		return nil, errors.New("config is nil")
	}

	jwtConfig := deps.jwtConfig()

	if !jwtConfig.IsEnabled() {
		return nil, errors.New("JWT authentication is not enabled")
	}

	// Parse token
	token, err := jwt.ParseWithClaims(tokenString, &jwtclaims.Claims{}, func(token *jwt.Token) (any, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}

		return []byte(jwtConfig.GetSecretKey()), nil
	})

	if err != nil {
		return nil, err
	}

	// Validate token
	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Get claims
	claims, ok := token.Claims.(*jwtclaims.Claims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	// If Redis storage is enabled, verify that the token exists in Redis
	if jwtConfig.IsStoreInRedisEnabled() {
		storedToken, err := GetTokenFromRedisWithDeps(ctx, claims.Username, deps)
		if err != nil {
			util.DebugModule(
				definitions.DbgJWT,
				definitions.LogKeyMsg, "Token not found in Redis",
				"error", err,
				"username", claims.Username,
			)

			return nil, errors.New("token not found in Redis")
		}

		// Verify that the token matches the one in Redis
		if storedToken != tokenString {
			util.DebugModule(
				definitions.DbgJWT,
				definitions.LogKeyMsg, "Token does not match the one in Redis",
				"username", claims.Username,
			)

			return nil, errors.New("token does not match the one in Redis")
		}
	}

	return claims, nil
}

func ExtractJWTTokenWithCfg(ctx *gin.Context, cfg config.File) (string, error) {
	if cfg == nil {
		return "", errors.New("config is nil")
	}

	// Check if JWT auth is enabled
	if !cfg.GetServer().GetJWTAuth().IsEnabled() {
		return "", errors.New("JWT authentication is not enabled")
	}

	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header is required")
	}

	// Check if the header starts with "Bearer "
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", errors.New("authorization header must be Bearer token")
	}

	// Extract the token
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return "", errors.New("token is required")
	}

	return token, nil
}

// ExtractJWTToken extracts the JWT token from the Authorization header
func ExtractJWTToken(ctx *gin.Context) (string, error) {
	return ExtractJWTTokenWithCfg(ctx, config.GetFile())
}

// JWTAuthMiddlewareWithDeps is a deps-based variant of JWTAuthMiddleware.
// It allows boundary wiring to inject Redis/config/logger and avoid calling globals.
func JWTAuthMiddlewareWithDeps(deps JWTDeps) gin.HandlerFunc {
	logger := deps.effectiveLogger()

	return func(ctx *gin.Context) {
		if deps.Cfg == nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server misconfigured"})
			return
		}

		// Skip if JWT auth is not enabled
		if !deps.jwtConfig().IsEnabled() {
			ctx.Next()
			return
		}

		// Extract token
		tokenString, err := ExtractJWTTokenWithCfg(ctx, deps.Cfg)
		if err != nil {
			if mdauth.MaybeThrottleAuthByIP(ctx) {
				return
			}

			mdauth.ApplyAuthBackoffOnFailure(ctx)
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		// Validate token
		claims, err := ValidateJWTTokenWithDeps(ctx, tokenString, deps)
		if err != nil {
			if mdauth.MaybeThrottleAuthByIP(ctx) {
				return
			}

			mdauth.ApplyAuthBackoffOnFailure(ctx)
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		// Set claims in context
		ctx.Set(definitions.CtxJWTClaimsKey, claims)

		// Check if the user has the authenticate role when NoAuth is false
		// NoAuth==false mode requires the authenticate role
		if ctx.Query("mode") != "no-auth" {
			hasAuthenticateRole := false
			for _, role := range claims.Roles {
				if role == definitions.RoleAuthenticate {
					hasAuthenticateRole = true
					break
				}
			}

			if !hasAuthenticateRole {
				level.Warn(logger).Log(
					definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
					definitions.LogKeyUsername, claims.Username,
					definitions.LogKeyClientIP, ctx.ClientIP(),
					definitions.LogKeyMsg, "JWT user does not have the 'authenticate' role required for authentication",
				)
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing required role: authenticate"})
				return
			}
		}

		ctx.Next()
	}
}

// JWTAuthMiddleware is a middleware that validates JWT tokens
func JWTAuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Skip if JWT auth is not enabled
		if !config.GetFile().GetServer().GetJWTAuth().IsEnabled() {
			ctx.Next()

			return
		}

		// Extract token
		tokenString, err := ExtractJWTToken(ctx)
		if err != nil {
			if mdauth.MaybeThrottleAuthByIP(ctx) {
				return
			}

			mdauth.ApplyAuthBackoffOnFailure(ctx)
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})

			return
		}

		// Validate token
		claims, err := ValidateJWTToken(ctx, tokenString)
		if err != nil {
			if mdauth.MaybeThrottleAuthByIP(ctx) {
				return
			}

			mdauth.ApplyAuthBackoffOnFailure(ctx)
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})

			return
		}

		// Set claims in context
		ctx.Set(definitions.CtxJWTClaimsKey, claims)

		// Check if the user has the authenticate role when NoAuth is false
		// NoAuth==false mode requires the authenticate role
		if ctx.Query("mode") != "no-auth" {
			hasAuthenticateRole := false
			for _, role := range claims.Roles {
				if role == definitions.RoleAuthenticate {
					hasAuthenticateRole = true

					break
				}
			}

			if !hasAuthenticateRole {
				level.Warn(log.Logger).Log(
					definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
					definitions.LogKeyUsername, claims.Username,
					definitions.LogKeyClientIP, ctx.ClientIP(),
					definitions.LogKeyMsg, "JWT user does not have the 'authenticate' role required for authentication",
				)
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing required role: authenticate"})

				return
			}
		}

		ctx.Next()
	}
}

// HandleJWTTokenGenerationWithDeps is a deps-based variant of HandleJWTTokenGeneration.
//
// It preserves the legacy behavior (including backend fallback when no static JWT users are configured)
// but uses the injected Redis facade for token persistence.
func HandleJWTTokenGenerationWithDeps(deps JWTDeps) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		cfg := deps.Cfg
		if cfg == nil {
			cfg = config.GetFile()
		}

		logger := deps.effectiveLogger()
		jwtConfig := cfg.GetServer().GetJWTAuth()

		if !jwtConfig.IsEnabled() {
			ctx.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "JWT authentication is not enabled"})
			return
		}

		var request jwtapi.Request
		if err := ctx.ShouldBindJSON(&request); err != nil {
			// Treat malformed input similar to an auth failure to avoid side channels
			if mdauth.MaybeThrottleAuthByIP(ctx) {
				return
			}

			mdauth.ApplyAuthBackoffOnFailure(ctx)
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Blocked IPs get fast-fail 429
		if mdauth.MaybeThrottleAuthByIP(ctx) {
			return
		}

		// Get GUID for logging
		guid := ctx.GetString(definitions.CtxGUIDKey)

		// Check if we have configured JWT users
		if len(jwtConfig.GetUsers()) > 0 {
			// Try to authenticate against configured JWT users
			authenticated := false
			var userRoles []string

			for _, user := range jwtConfig.GetUsers() {
				if user.GetUsername() == request.Username && user.GetPassword() == request.Password {
					authenticated = true
					userRoles = user.GetRoles()
					break
				}
			}

			if !authenticated {
				level.Error(logger).Log(
					definitions.LogKeyGUID, guid,
					definitions.LogKeyUsername, request.Username,
					definitions.LogKeyClientIP, ctx.ClientIP(),
					definitions.LogKeyMsg, "JWT token generation failed: authentication failed",
					definitions.LogKeyError, "username or password is incorrect",
				)
				mdauth.ApplyAuthBackoffOnFailure(ctx)
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication failed"})
				return
			}

			// Generate JWT token
			token, expiresAt, err := GenerateJWTToken(request.Username, userRoles)
			if err != nil {
				level.Error(logger).Log(
					definitions.LogKeyGUID, guid,
					definitions.LogKeyUsername, request.Username,
					definitions.LogKeyClientIP, ctx.ClientIP(),
					definitions.LogKeyMsg, "JWT token generation failed",
					definitions.LogKeyError, err,
				)
				ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
				return
			}

			response := jwtapi.Response{Token: token, ExpiresAt: expiresAt}

			// Generate refresh token if enabled
			if jwtConfig.IsRefreshTokenEnabled() {
				refreshToken, err := GenerateRefreshToken(request.Username)
				if err != nil {
					level.Error(logger).Log(
						definitions.LogKeyGUID, guid,
						definitions.LogKeyUsername, request.Username,
						definitions.LogKeyClientIP, ctx.ClientIP(),
						definitions.LogKeyMsg, "JWT refresh token generation failed",
						definitions.LogKeyError, err,
					)
				} else {
					response.RefreshToken = refreshToken
				}
			}

			// Store tokens in Redis if enabled
			if jwtConfig.IsStoreInRedisEnabled() {
				redisDeps := deps
				redisDeps.Cfg = cfg

				if err := StoreTokenInRedisWithDeps(ctx, request.Username, token, expiresAt, redisDeps); err != nil {
					level.Error(logger).Log(
						definitions.LogKeyGUID, guid,
						definitions.LogKeyUsername, request.Username,
						definitions.LogKeyClientIP, ctx.ClientIP(),
						definitions.LogKeyMsg, "Failed to store JWT token in Redis",
						definitions.LogKeyError, err,
					)
				}

				if jwtConfig.IsRefreshTokenEnabled() && response.RefreshToken != "" {
					if err := StoreRefreshTokenInRedisWithDeps(ctx, request.Username, response.RefreshToken, redisDeps); err != nil {
						level.Error(logger).Log(
							definitions.LogKeyGUID, guid,
							definitions.LogKeyUsername, request.Username,
							definitions.LogKeyClientIP, ctx.ClientIP(),
							definitions.LogKeyMsg, "Failed to store JWT refresh token in Redis",
							definitions.LogKeyError, err,
						)
					}
				}
			}

			level.Info(logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyUsername, request.Username,
				definitions.LogKeyClientIP, ctx.ClientIP(),
				definitions.LogKeyMsg, "JWT token generated successfully",
			)

			ctx.JSON(http.StatusOK, response)
			return
		}

		// If no JWT users are configured, fall back to existing authentication backends
		auth := NewAuthStateWithSetup(ctx)
		if auth == nil {
			ctx.AbortWithStatus(http.StatusBadRequest)
			return
		}

		// Set username and password
		auth.SetUsername(request.Username)
		auth.SetPassword(request.Password)

		// Authenticate user
		authResult := auth.HandlePassword(ctx)
		if authResult != definitions.AuthResultOK {
			level.Error(logger).Log(
				definitions.LogKeyGUID, auth.GetGUID(),
				definitions.LogKeyUsername, auth.GetUsername(),
				definitions.LogKeyClientIP, auth.GetClientIP(),
				definitions.LogKeyMsg, "JWT token generation failed: authentication failed",
				definitions.LogKeyError, "username or password is incorrect",
			)
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication failed"})
			return
		}

		// Determine user roles - default is empty
		var roles []string

		// Add user info role if NoAuth is true
		if auth.(*AuthState).NoAuth {
			roles = append(roles, definitions.RoleUserInfo)
		}

		// Add list accounts role if the user can list accounts
		accountList := auth.(*AuthState).ListUserAccounts()
		if len(accountList) > 0 {
			roles = append(roles, definitions.RoleListAccounts)
		}

		// Generate JWT token
		token, expiresAt, err := GenerateJWTToken(request.Username, roles)
		if err != nil {
			level.Error(logger).Log(
				definitions.LogKeyGUID, auth.GetGUID(),
				definitions.LogKeyUsername, auth.GetUsername(),
				definitions.LogKeyClientIP, auth.GetClientIP(),
				definitions.LogKeyMsg, "JWT token generation failed",
				definitions.LogKeyError, err,
			)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
			return
		}

		response := jwtapi.Response{Token: token, ExpiresAt: expiresAt}

		// Generate refresh token if enabled
		if jwtConfig.IsRefreshTokenEnabled() {
			refreshToken, err := GenerateRefreshToken(request.Username)
			if err != nil {
				level.Error(logger).Log(
					definitions.LogKeyGUID, auth.GetGUID(),
					definitions.LogKeyUsername, auth.GetUsername(),
					definitions.LogKeyClientIP, auth.GetClientIP(),
					definitions.LogKeyMsg, "JWT refresh token generation failed",
					definitions.LogKeyError, err,
				)
			} else {
				response.RefreshToken = refreshToken
			}
		}

		// Store tokens in Redis if enabled
		if jwtConfig.IsStoreInRedisEnabled() {
			redisDeps := deps
			redisDeps.Cfg = cfg

			if err := StoreTokenInRedisWithDeps(ctx, request.Username, token, expiresAt, redisDeps); err != nil {
				level.Error(logger).Log(
					definitions.LogKeyGUID, auth.GetGUID(),
					definitions.LogKeyUsername, auth.GetUsername(),
					definitions.LogKeyClientIP, auth.GetClientIP(),
					definitions.LogKeyMsg, "Failed to store JWT token in Redis",
					definitions.LogKeyError, err,
				)
			}

			if jwtConfig.IsRefreshTokenEnabled() && response.RefreshToken != "" {
				if err := StoreRefreshTokenInRedisWithDeps(ctx, request.Username, response.RefreshToken, redisDeps); err != nil {
					level.Error(logger).Log(
						definitions.LogKeyGUID, auth.GetGUID(),
						definitions.LogKeyUsername, auth.GetUsername(),
						definitions.LogKeyClientIP, auth.GetClientIP(),
						definitions.LogKeyMsg, "Failed to store JWT refresh token in Redis",
						definitions.LogKeyError, err,
					)
				}
			}
		}

		level.Info(logger).Log(
			definitions.LogKeyGUID, auth.GetGUID(),
			definitions.LogKeyUsername, auth.GetUsername(),
			definitions.LogKeyClientIP, auth.GetClientIP(),
			definitions.LogKeyMsg, "JWT token generated successfully",
		)

		ctx.JSON(http.StatusOK, response)
	}
}

// HandleJWTTokenRefreshWithDeps is a deps-based variant of HandleJWTTokenRefresh.
// It verifies refresh tokens against Redis using injected dependencies.
func HandleJWTTokenRefreshWithDeps(deps JWTDeps) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		cfg := deps.Cfg
		if cfg == nil {
			cfg = config.GetFile()
		}

		logger := deps.effectiveLogger()
		jwtConfig := cfg.GetServer().GetJWTAuth()

		if !jwtConfig.IsEnabled() || !jwtConfig.IsRefreshTokenEnabled() {
			ctx.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "JWT refresh tokens are not enabled"})
			return
		}

		// Blocked IPs get fast-fail 429
		if mdauth.MaybeThrottleAuthByIP(ctx) {
			return
		}

		// Extract refresh token
		refreshToken := ctx.GetHeader("X-Refresh-Token")
		if refreshToken == "" {
			mdauth.ApplyAuthBackoffOnFailure(ctx)
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "refresh token is required"})
			return
		}

		// Parse refresh token
		token, err := jwt.ParseWithClaims(refreshToken, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}

			return []byte(jwtConfig.GetSecretKey()), nil
		})

		if err != nil || !token.Valid {
			mdauth.ApplyAuthBackoffOnFailure(ctx)
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
			return
		}

		// Get claims
		claims, ok := token.Claims.(*jwt.RegisteredClaims)
		if !ok {
			mdauth.ApplyAuthBackoffOnFailure(ctx)
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token claims"})
			return
		}

		// If Redis storage is enabled, verify that the refresh token exists in Redis
		if jwtConfig.IsStoreInRedisEnabled() {
			repl := deps
			repl.Cfg = cfg

			storedRefreshToken, err := GetRefreshTokenFromRedisWithDeps(ctx, claims.Subject, repl)
			if err != nil {
				util.DebugModule(
					definitions.DbgJWT,
					definitions.LogKeyMsg, "Refresh token not found in Redis",
					"error", err,
					"username", claims.Subject,
				)
				mdauth.ApplyAuthBackoffOnFailure(ctx)
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "refresh token not found in Redis"})
				return
			}

			// Verify that the refresh token matches the one in Redis
			if storedRefreshToken != refreshToken {
				util.DebugModule(
					definitions.DbgJWT,
					definitions.LogKeyMsg, "Refresh token does not match the one in Redis",
					"username", claims.Subject,
				)
				mdauth.ApplyAuthBackoffOnFailure(ctx)
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "refresh token does not match the one in Redis"})
				return
			}
		}

		// Get GUID for logging
		guid := ctx.GetString(definitions.CtxGUIDKey)

		// Check if we have configured JWT users
		var roles []string
		if len(jwtConfig.GetUsers()) > 0 {
			// Try to find the user in the configured JWT users
			userFound := false
			for _, user := range jwtConfig.GetUsers() {
				if user.GetUsername() == claims.Subject {
					roles = user.GetRoles()
					userFound = true
					break
				}
			}

			if !userFound {
				level.Error(logger).Log(
					definitions.LogKeyGUID, guid,
					definitions.LogKeyUsername, claims.Subject,
					definitions.LogKeyClientIP, ctx.ClientIP(),
					definitions.LogKeyMsg, "JWT token refresh failed: user not found in configuration",
					definitions.LogKeyError, "user not found in configuration",
				)
				mdauth.ApplyAuthBackoffOnFailure(ctx)
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
				return
			}
		}

		// Generate new JWT token
		newToken, expiresAt, err := GenerateJWTToken(claims.Subject, roles)
		if err != nil {
			level.Error(logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyUsername, claims.Subject,
				definitions.LogKeyClientIP, ctx.ClientIP(),
				definitions.LogKeyMsg, "JWT token refresh failed",
				definitions.LogKeyError, err,
			)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to generate new token"})
			return
		}

		// Generate new refresh token
		newRefreshToken, err := GenerateRefreshToken(claims.Subject)
		if err != nil {
			level.Error(logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyUsername, claims.Subject,
				definitions.LogKeyClientIP, ctx.ClientIP(),
				definitions.LogKeyMsg, "JWT refresh token generation failed",
				definitions.LogKeyError, err,
			)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to generate new refresh token"})
			return
		}

		// Store tokens in Redis if enabled
		if jwtConfig.IsStoreInRedisEnabled() {
			repl := deps
			repl.Cfg = cfg

			if err := StoreTokenInRedisWithDeps(ctx, claims.Subject, newToken, expiresAt, repl); err != nil {
				level.Error(logger).Log(
					definitions.LogKeyGUID, guid,
					definitions.LogKeyUsername, claims.Subject,
					definitions.LogKeyClientIP, ctx.ClientIP(),
					definitions.LogKeyMsg, "Failed to store JWT token in Redis",
					definitions.LogKeyError, err,
				)
			}

			if err := StoreRefreshTokenInRedisWithDeps(ctx, claims.Subject, newRefreshToken, repl); err != nil {
				level.Error(logger).Log(
					definitions.LogKeyGUID, guid,
					definitions.LogKeyUsername, claims.Subject,
					definitions.LogKeyClientIP, ctx.ClientIP(),
					definitions.LogKeyMsg, "Failed to store JWT refresh token in Redis",
					definitions.LogKeyError, err,
				)
			}
		}

		level.Info(logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyUsername, claims.Subject,
			definitions.LogKeyClientIP, ctx.ClientIP(),
			definitions.LogKeyMsg, "JWT token refreshed successfully",
		)

		ctx.JSON(http.StatusOK, jwtapi.Response{Token: newToken, RefreshToken: newRefreshToken, ExpiresAt: expiresAt})
	}
}

// HandleJWTTokenGeneration handles the JWT token generation endpoint
func HandleJWTTokenGeneration(ctx *gin.Context) {
	jwtConfig := config.GetFile().GetServer().GetJWTAuth()

	if !jwtConfig.IsEnabled() {
		ctx.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "JWT authentication is not enabled"})

		return
	}

	var request jwtapi.Request
	if err := ctx.ShouldBindJSON(&request); err != nil {
		// Treat malformed input similar to an auth failure to avoid side channels
		if mdauth.MaybeThrottleAuthByIP(ctx) {
			return
		}

		mdauth.ApplyAuthBackoffOnFailure(ctx)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})

		return
	}

	// Blocked IPs get fast-fail 429
	if mdauth.MaybeThrottleAuthByIP(ctx) {
		return
	}

	// Get GUID for logging
	guid := ctx.GetString(definitions.CtxGUIDKey)

	// Check if we have configured JWT users
	if len(jwtConfig.GetUsers()) > 0 {
		// Try to authenticate against configured JWT users
		authenticated := false
		var userRoles []string

		for _, user := range jwtConfig.GetUsers() {
			if user.GetUsername() == request.Username && user.GetPassword() == request.Password {
				authenticated = true
				userRoles = user.GetRoles()

				break
			}
		}

		if !authenticated {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyUsername, request.Username,
				definitions.LogKeyClientIP, ctx.ClientIP(),
				definitions.LogKeyMsg, "JWT token generation failed: authentication failed",
				definitions.LogKeyError, "username or password is incorrect",
			)
			mdauth.ApplyAuthBackoffOnFailure(ctx)
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication failed"})

			return
		}

		// Generate JWT token
		token, expiresAt, err := GenerateJWTToken(request.Username, userRoles)
		if err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyUsername, request.Username,
				definitions.LogKeyClientIP, ctx.ClientIP(),
				definitions.LogKeyMsg, "JWT token generation failed",
				definitions.LogKeyError, err,
			)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})

			return
		}

		response := jwtapi.Response{
			Token:     token,
			ExpiresAt: expiresAt,
		}

		// Generate refresh token if enabled
		if jwtConfig.IsRefreshTokenEnabled() {
			refreshToken, err := GenerateRefreshToken(request.Username)
			if err != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyGUID, guid,
					definitions.LogKeyUsername, request.Username,
					definitions.LogKeyClientIP, ctx.ClientIP(),
					definitions.LogKeyMsg, "JWT refresh token generation failed",
					definitions.LogKeyError, err,
				)
			} else {
				response.RefreshToken = refreshToken
			}
		}

		// Store tokens in Redis if enabled
		if jwtConfig.IsStoreInRedisEnabled() {
			if err := StoreTokenInRedis(ctx, request.Username, token, expiresAt); err != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyGUID, guid,
					definitions.LogKeyUsername, request.Username,
					definitions.LogKeyClientIP, ctx.ClientIP(),
					definitions.LogKeyMsg, "Failed to store JWT token in Redis",
					definitions.LogKeyError, err,
				)
			}

			if jwtConfig.IsRefreshTokenEnabled() && response.RefreshToken != "" {
				if err := StoreRefreshTokenInRedis(ctx, request.Username, response.RefreshToken); err != nil {
					level.Error(log.Logger).Log(
						definitions.LogKeyGUID, guid,
						definitions.LogKeyUsername, request.Username,
						definitions.LogKeyClientIP, ctx.ClientIP(),
						definitions.LogKeyMsg, "Failed to store JWT refresh token in Redis",
						definitions.LogKeyError, err,
					)
				}
			}
		}

		level.Info(log.Logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyUsername, request.Username,
			definitions.LogKeyClientIP, ctx.ClientIP(),
			definitions.LogKeyMsg, "JWT token generated successfully",
		)

		ctx.JSON(http.StatusOK, response)

		return
	}

	// If no JWT users are configured, fall back to existing authentication backends

	// Create auth state for authentication
	auth := NewAuthStateWithSetup(ctx)
	if auth == nil {
		ctx.AbortWithStatus(http.StatusBadRequest)

		return
	}

	// Set username and password
	auth.SetUsername(request.Username)
	auth.SetPassword(request.Password)

	// Authenticate user
	authResult := auth.HandlePassword(ctx)
	if authResult != definitions.AuthResultOK {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, auth.GetGUID(),
			definitions.LogKeyUsername, auth.GetUsername(),
			definitions.LogKeyClientIP, auth.GetClientIP(),
			definitions.LogKeyMsg, "JWT token generation failed: authentication failed",
			definitions.LogKeyError, "username or password is incorrect",
		)
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication failed"})

		return
	}

	// Determine user roles - default is empty
	var roles []string

	// Add user info role if NoAuth is true
	if auth.(*AuthState).NoAuth {
		roles = append(roles, definitions.RoleUserInfo)
	}

	// Add list accounts role if the user can list accounts
	accountList := auth.(*AuthState).ListUserAccounts()
	if len(accountList) > 0 {
		roles = append(roles, definitions.RoleListAccounts)
	}

	// Generate JWT token
	token, expiresAt, err := GenerateJWTToken(request.Username, roles)
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, auth.GetGUID(),
			definitions.LogKeyUsername, auth.GetUsername(),
			definitions.LogKeyClientIP, auth.GetClientIP(),
			definitions.LogKeyMsg, "JWT token generation failed",
			definitions.LogKeyError, err,
		)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})

		return
	}

	response := jwtapi.Response{
		Token:     token,
		ExpiresAt: expiresAt,
	}

	// Generate refresh token if enabled
	if jwtConfig.IsRefreshTokenEnabled() {
		refreshToken, err := GenerateRefreshToken(request.Username)
		if err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, auth.GetGUID(),
				definitions.LogKeyUsername, auth.GetUsername(),
				definitions.LogKeyClientIP, auth.GetClientIP(),
				definitions.LogKeyMsg, "JWT refresh token generation failed",
				definitions.LogKeyError, err,
			)
		} else {
			response.RefreshToken = refreshToken
		}
	}

	// Store tokens in Redis if enabled
	if jwtConfig.IsStoreInRedisEnabled() {
		if err := StoreTokenInRedis(ctx, request.Username, token, expiresAt); err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, auth.GetGUID(),
				definitions.LogKeyUsername, auth.GetUsername(),
				definitions.LogKeyClientIP, auth.GetClientIP(),
				definitions.LogKeyMsg, "Failed to store JWT token in Redis",
				definitions.LogKeyError, err,
			)
		}

		if jwtConfig.IsRefreshTokenEnabled() && response.RefreshToken != "" {
			if err := StoreRefreshTokenInRedis(ctx, request.Username, response.RefreshToken); err != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyGUID, auth.GetGUID(),
					definitions.LogKeyUsername, auth.GetUsername(),
					definitions.LogKeyClientIP, auth.GetClientIP(),
					definitions.LogKeyMsg, "Failed to store JWT refresh token in Redis",
					definitions.LogKeyError, err,
				)
			}
		}
	}

	level.Info(log.Logger).Log(
		definitions.LogKeyGUID, auth.GetGUID(),
		definitions.LogKeyUsername, auth.GetUsername(),
		definitions.LogKeyClientIP, auth.GetClientIP(),
		definitions.LogKeyMsg, "JWT token generated successfully",
	)

	ctx.JSON(http.StatusOK, response)
}

// HandleJWTTokenRefresh handles the JWT token refresh endpoint
func HandleJWTTokenRefresh(ctx *gin.Context) {
	jwtConfig := config.GetFile().GetServer().GetJWTAuth()

	if !jwtConfig.IsEnabled() || !jwtConfig.IsRefreshTokenEnabled() {
		ctx.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "JWT refresh tokens are not enabled"})

		return
	}

	// Blocked IPs get fast-fail 429
	if mdauth.MaybeThrottleAuthByIP(ctx) {
		return
	}

	// Extract refresh token
	refreshToken := ctx.GetHeader("X-Refresh-Token")
	if refreshToken == "" {
		mdauth.ApplyAuthBackoffOnFailure(ctx)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "refresh token is required"})

		return
	}

	// Parse refresh token
	token, err := jwt.ParseWithClaims(refreshToken, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}

		return []byte(jwtConfig.GetSecretKey()), nil
	})

	if err != nil || !token.Valid {
		mdauth.ApplyAuthBackoffOnFailure(ctx)
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})

		return
	}

	// Get claims
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		mdauth.ApplyAuthBackoffOnFailure(ctx)
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token claims"})

		return
	}

	// If Redis storage is enabled, verify that the refresh token exists in Redis
	if jwtConfig.IsStoreInRedisEnabled() {
		storedRefreshToken, err := GetRefreshTokenFromRedis(ctx, claims.Subject)
		if err != nil {
			util.DebugModule(
				definitions.DbgJWT,
				definitions.LogKeyMsg, "Refresh token not found in Redis",
				"error", err,
				"username", claims.Subject,
			)
			mdauth.ApplyAuthBackoffOnFailure(ctx)
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "refresh token not found in Redis"})

			return
		}

		// Verify that the refresh token matches the one in Redis
		if storedRefreshToken != refreshToken {
			util.DebugModule(
				definitions.DbgJWT,
				definitions.LogKeyMsg, "Refresh token does not match the one in Redis",
				"username", claims.Subject,
			)
			mdauth.ApplyAuthBackoffOnFailure(ctx)
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "refresh token does not match the one in Redis"})

			return
		}
	}

	// Get GUID for logging
	guid := ctx.GetString(definitions.CtxGUIDKey)

	// Check if we have configured JWT users
	var roles []string
	if len(jwtConfig.GetUsers()) > 0 {
		// Try to find the user in the configured JWT users
		userFound := false
		for _, user := range jwtConfig.GetUsers() {
			if user.GetUsername() == claims.Subject {
				roles = user.GetRoles()
				userFound = true
				break
			}
		}

		if !userFound {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyUsername, claims.Subject,
				definitions.LogKeyClientIP, ctx.ClientIP(),
				definitions.LogKeyMsg, "JWT token refresh failed: user not found in configuration",
				definitions.LogKeyError, "user not found in configuration",
			)
			mdauth.ApplyAuthBackoffOnFailure(ctx)
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "user not found"})

			return
		}
	}

	// Generate new JWT token
	newToken, expiresAt, err := GenerateJWTToken(claims.Subject, roles)
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyUsername, claims.Subject,
			definitions.LogKeyClientIP, ctx.ClientIP(),
			definitions.LogKeyMsg, "JWT token refresh failed",
			definitions.LogKeyError, err,
		)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to generate new token"})

		return
	}

	// Generate new refresh token
	newRefreshToken, err := GenerateRefreshToken(claims.Subject)
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyUsername, claims.Subject,
			definitions.LogKeyClientIP, ctx.ClientIP(),
			definitions.LogKeyMsg, "JWT refresh token generation failed",
			definitions.LogKeyError, err,
		)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to generate new refresh token"})

		return
	}

	// Store tokens in Redis if enabled
	if jwtConfig.IsStoreInRedisEnabled() {
		if err := StoreTokenInRedis(ctx, claims.Subject, newToken, expiresAt); err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyUsername, claims.Subject,
				definitions.LogKeyClientIP, ctx.ClientIP(),
				definitions.LogKeyMsg, "Failed to store JWT token in Redis",
				definitions.LogKeyError, err,
			)
		}

		if err := StoreRefreshTokenInRedis(ctx, claims.Subject, newRefreshToken); err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyUsername, claims.Subject,
				definitions.LogKeyClientIP, ctx.ClientIP(),
				definitions.LogKeyMsg, "Failed to store JWT refresh token in Redis",
				definitions.LogKeyError, err,
			)
		}
	}

	level.Info(log.Logger).Log(
		definitions.LogKeyGUID, guid,
		definitions.LogKeyUsername, claims.Subject,
		definitions.LogKeyClientIP, ctx.ClientIP(),
		definitions.LogKeyMsg, "JWT token refreshed successfully",
	)

	ctx.JSON(http.StatusOK, jwtapi.Response{
		Token:        newToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    expiresAt,
	})
}
