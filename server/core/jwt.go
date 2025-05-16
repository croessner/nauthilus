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
	"net/http"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/jwtclaims"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

// JWTClaims is an alias for jwtclaims.JWTClaims
type JWTClaims = jwtclaims.JWTClaims

// JWTRequest represents the request body for JWT token generation
type JWTRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// JWTResponse represents the response body for JWT token generation
type JWTResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresAt    int64  `json:"expires_at"`
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
	claims := JWTClaims{
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
func StoreTokenInRedis(username, token string, expiresAt int64) error {
	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	if !config.GetFile().GetServer().GetJWTAuth().IsStoreInRedisEnabled() {
		return nil
	}

	// Calculate TTL based on expiry time
	ttl := time.Until(time.Unix(expiresAt, 0))
	if ttl <= 0 {
		return errors.New("token has already expired")
	}

	// Create Redis key
	key := fmt.Sprintf("jwt:token:%s", username)

	// Store token in Redis with expiry
	ctx := context.Background()
	redisClient := rediscli.GetClient().GetWriteHandle()

	return redisClient.Set(ctx, key, token, ttl).Err()
}

// StoreRefreshTokenInRedis stores a JWT refresh token in Redis for multi-instance compatibility
func StoreRefreshTokenInRedis(username, refreshToken string) error {
	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	jwtConfig := config.GetFile().GetServer().GetJWTAuth()
	if !jwtConfig.IsStoreInRedisEnabled() {
		return nil
	}

	// Create Redis key
	key := fmt.Sprintf("jwt:refresh:%s", username)

	// Determine expiry time
	expiry := jwtConfig.GetRefreshTokenExpiry()
	if expiry == 0 {
		// Default to 24 hours if not specified
		expiry = 24 * time.Hour
	}

	// Store refresh token in Redis with configured expiry
	ctx := context.Background()
	redisClient := rediscli.GetClient().GetWriteHandle()

	return redisClient.Set(ctx, key, refreshToken, expiry).Err()
}

// GetTokenFromRedis retrieves a JWT token from Redis
func GetTokenFromRedis(username string) (string, error) {
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	if !config.GetFile().GetServer().GetJWTAuth().IsStoreInRedisEnabled() {
		return "", errors.New("redis storage is not enabled for JWT tokens")
	}

	// Create Redis key
	key := fmt.Sprintf("jwt:token:%s", username)

	// Get token from Redis
	ctx := context.Background()
	redisClient := rediscli.GetClient().GetReadHandle()

	token, err := redisClient.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", errors.New("token not found in Redis")
		}

		return "", err
	}

	return token, nil
}

// GetRefreshTokenFromRedis retrieves a JWT refresh token from Redis
func GetRefreshTokenFromRedis(username string) (string, error) {
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	if !config.GetFile().GetServer().GetJWTAuth().IsStoreInRedisEnabled() {
		return "", errors.New("redis storage is not enabled for JWT tokens")
	}

	// Create Redis key
	key := fmt.Sprintf("jwt:refresh:%s", username)

	// Get refresh token from Redis
	ctx := context.Background()
	redisClient := rediscli.GetClient().GetReadHandle()

	token, err := redisClient.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", errors.New("refresh token not found in Redis")
		}

		return "", err
	}

	return token, nil
}

// ValidateJWTToken validates a JWT token and returns the claims
func ValidateJWTToken(tokenString string) (*JWTClaims, error) {
	jwtConfig := config.GetFile().GetServer().GetJWTAuth()

	if !jwtConfig.IsEnabled() {
		return nil, errors.New("JWT authentication is not enabled")
	}

	// Parse token
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
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
	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	// If Redis storage is enabled, verify that the token exists in Redis
	if jwtConfig.IsStoreInRedisEnabled() {
		storedToken, err := GetTokenFromRedis(claims.Username)
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

// ExtractJWTToken extracts the JWT token from the Authorization header
func ExtractJWTToken(ctx *gin.Context) (string, error) {
	// Check if JWT auth is enabled
	if !config.GetFile().GetServer().GetJWTAuth().IsEnabled() {
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
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})

			return
		}

		// Validate token
		claims, err := ValidateJWTToken(tokenString)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})

			return
		}

		// Set claims in context
		ctx.Set(definitions.CtxJWTClaimsKey, claims)

		// Check if the user has the "authenticated" role when NoAuth is false
		// NoAuth==false mode requires the "authenticated" role
		if ctx.Query("mode") != "no-auth" {
			hasAuthenticatedRole := false
			for _, role := range claims.Roles {
				if role == "authenticated" {
					hasAuthenticatedRole = true

					break
				}
			}

			if !hasAuthenticatedRole {
				level.Warn(log.Logger).Log(
					definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
					definitions.LogKeyUsername, claims.Username,
					definitions.LogKeyClientIP, ctx.ClientIP(),
					definitions.LogKeyMsg, "JWT user does not have the 'authenticated' role required for authentication",
				)
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing required role: authenticated"})

				return
			}
		}

		ctx.Next()
	}
}

// HandleJWTTokenGeneration handles the JWT token generation endpoint
func HandleJWTTokenGeneration(ctx *gin.Context) {
	jwtConfig := config.GetFile().GetServer().GetJWTAuth()

	if !jwtConfig.IsEnabled() {
		ctx.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "JWT authentication is not enabled"})

		return
	}

	var request JWTRequest
	if err := ctx.ShouldBindJSON(&request); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})

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
			)
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
				"error", err,
			)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})

			return
		}

		response := JWTResponse{
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
					"error", err,
				)
			} else {
				response.RefreshToken = refreshToken
			}
		}

		// Store tokens in Redis if enabled
		if jwtConfig.IsStoreInRedisEnabled() {
			if err := StoreTokenInRedis(request.Username, token, expiresAt); err != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyGUID, guid,
					definitions.LogKeyUsername, request.Username,
					definitions.LogKeyClientIP, ctx.ClientIP(),
					definitions.LogKeyMsg, "Failed to store JWT token in Redis",
					"error", err,
				)
			}

			if jwtConfig.IsRefreshTokenEnabled() && response.RefreshToken != "" {
				if err := StoreRefreshTokenInRedis(request.Username, response.RefreshToken); err != nil {
					level.Error(log.Logger).Log(
						definitions.LogKeyGUID, guid,
						definitions.LogKeyUsername, request.Username,
						definitions.LogKeyClientIP, ctx.ClientIP(),
						definitions.LogKeyMsg, "Failed to store JWT refresh token in Redis",
						"error", err,
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
		)
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication failed"})

		return
	}

	// Determine user roles - default is empty
	var roles []string

	// Add user info role if NoAuth is true
	if auth.(*AuthState).NoAuth {
		roles = append(roles, "user_info")
	}

	// Add list accounts role if the user can list accounts
	accountList := auth.(*AuthState).ListUserAccounts()
	if len(accountList) > 0 {
		roles = append(roles, "list_accounts")
	}

	// Generate JWT token
	token, expiresAt, err := GenerateJWTToken(request.Username, roles)
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, auth.GetGUID(),
			definitions.LogKeyUsername, auth.GetUsername(),
			definitions.LogKeyClientIP, auth.GetClientIP(),
			definitions.LogKeyMsg, "JWT token generation failed",
			"error", err,
		)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})

		return
	}

	response := JWTResponse{
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
				"error", err,
			)
		} else {
			response.RefreshToken = refreshToken
		}
	}

	// Store tokens in Redis if enabled
	if jwtConfig.IsStoreInRedisEnabled() {
		if err := StoreTokenInRedis(request.Username, token, expiresAt); err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, auth.GetGUID(),
				definitions.LogKeyUsername, auth.GetUsername(),
				definitions.LogKeyClientIP, auth.GetClientIP(),
				definitions.LogKeyMsg, "Failed to store JWT token in Redis",
				"error", err,
			)
		}

		if jwtConfig.IsRefreshTokenEnabled() && response.RefreshToken != "" {
			if err := StoreRefreshTokenInRedis(request.Username, response.RefreshToken); err != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyGUID, auth.GetGUID(),
					definitions.LogKeyUsername, auth.GetUsername(),
					definitions.LogKeyClientIP, auth.GetClientIP(),
					definitions.LogKeyMsg, "Failed to store JWT refresh token in Redis",
					"error", err,
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

	// Extract refresh token
	refreshToken := ctx.GetHeader("X-Refresh-Token")
	if refreshToken == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "refresh token is required"})

		return
	}

	// Parse refresh token
	token, err := jwt.ParseWithClaims(refreshToken, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}

		return []byte(jwtConfig.GetSecretKey()), nil
	})

	if err != nil || !token.Valid {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})

		return
	}

	// Get claims
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token claims"})

		return
	}

	// If Redis storage is enabled, verify that the refresh token exists in Redis
	if jwtConfig.IsStoreInRedisEnabled() {
		storedRefreshToken, err := GetRefreshTokenFromRedis(claims.Subject)
		if err != nil {
			util.DebugModule(
				definitions.DbgJWT,
				definitions.LogKeyMsg, "Refresh token not found in Redis",
				"error", err,
				"username", claims.Subject,
			)
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
			)
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
			"error", err,
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
			"error", err,
		)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to generate new refresh token"})

		return
	}

	// Store tokens in Redis if enabled
	if jwtConfig.IsStoreInRedisEnabled() {
		if err := StoreTokenInRedis(claims.Subject, newToken, expiresAt); err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyUsername, claims.Subject,
				definitions.LogKeyClientIP, ctx.ClientIP(),
				definitions.LogKeyMsg, "Failed to store JWT token in Redis",
				"error", err,
			)
		}

		if err := StoreRefreshTokenInRedis(claims.Subject, newRefreshToken); err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyUsername, claims.Subject,
				definitions.LogKeyClientIP, ctx.ClientIP(),
				definitions.LogKeyMsg, "Failed to store JWT refresh token in Redis",
				"error", err,
			)
		}
	}

	level.Info(log.Logger).Log(
		definitions.LogKeyGUID, guid,
		definitions.LogKeyUsername, claims.Subject,
		definitions.LogKeyClientIP, ctx.ClientIP(),
		definitions.LogKeyMsg, "JWT token refreshed successfully",
	)

	ctx.JSON(http.StatusOK, JWTResponse{
		Token:        newToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    expiresAt,
	})
}
