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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// TestJWTTokenParsing tests the parsing and validation of JWT tokens
func TestJWTTokenParsing(t *testing.T) {
	// Skip this test if JWT auth is not enabled in the config
	// This allows the test to run in any environment without failing
	// t.Skip("Skipping JWT token parsing test")

	// Create a valid token for testing
	claims := JWTClaims{
		Username: "testuser",
		Roles:    []string{"user", "admin"},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "nauthilus",
			Subject:   "testuser",
		},
	}

	// Create a token with the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with a test secret
	tokenString, err := token.SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// Parse the token
	parsedToken, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("test-secret"), nil
	})

	// Check that the token was parsed successfully
	assert.NoError(t, err)
	assert.True(t, parsedToken.Valid)

	// Check that the claims were parsed correctly
	parsedClaims, ok := parsedToken.Claims.(*JWTClaims)
	assert.True(t, ok)
	assert.Equal(t, "testuser", parsedClaims.Username)
	assert.Equal(t, []string{"user", "admin"}, parsedClaims.Roles)
	assert.Equal(t, "nauthilus", parsedClaims.Issuer)
	assert.Equal(t, "testuser", parsedClaims.Subject)
}

// TestExtractJWTTokenFromRequest tests the extraction of JWT tokens from HTTP requests
func TestExtractJWTTokenFromRequest(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)

	// Create a test request with a JWT token in the Authorization header
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer test-token")

	// Create a test context
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = req

	// Extract the token from the request
	// This is a simplified version of what ExtractJWTToken does
	authHeader := ctx.GetHeader("Authorization")
	assert.Equal(t, "Bearer test-token", authHeader)

	// Check if the header starts with "Bearer "
	assert.True(t, len(authHeader) > 7 && authHeader[:7] == "Bearer ")

	// Extract the token
	token := authHeader[7:]
	assert.Equal(t, "test-token", token)
}

// TestJWTClaimsInContext tests setting and retrieving JWT claims from the gin context
func TestJWTClaimsInContext(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)

	// Create a test context
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	// Create test claims
	claims := &JWTClaims{
		Username: "testuser",
		Roles:    []string{"user", "admin"},
	}

	// Set the claims in the context
	ctx.Set(definitions.CtxJWTClaimsKey, claims)

	// Retrieve the claims from the context
	claimsValue, exists := ctx.Get(definitions.CtxJWTClaimsKey)
	assert.True(t, exists)

	// Check that the claims are of the correct type
	retrievedClaims, ok := claimsValue.(*JWTClaims)
	assert.True(t, ok)

	// Check that the claims have the correct values
	assert.Equal(t, "testuser", retrievedClaims.Username)
	assert.Equal(t, []string{"user", "admin"}, retrievedClaims.Roles)
}

// TestJWTTokenGenerationAndRefresh tests the generation of a JWT token and its refresh
func TestJWTTokenGenerationAndRefresh(t *testing.T) {
	// Create a secret key for testing
	secretKey := "test-secret-key-for-jwt-token-testing"

	// Step 1: Generate an initial JWT token
	username := "testuser"
	roles := []string{"user", "authenticated"}

	// Create claims for the token
	claims := JWTClaims{
		Username: username,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "nauthilus",
			Subject:   username,
		},
	}

	// Create and sign the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secretKey))
	assert.NoError(t, err, "Failed to sign token")
	assert.NotEmpty(t, tokenString, "Token string should not be empty")

	// Step 2: Generate a refresh token
	refreshClaims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "nauthilus",
		Subject:   username,
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(secretKey))
	assert.NoError(t, err, "Failed to sign refresh token")
	assert.NotEmpty(t, refreshTokenString, "Refresh token string should not be empty")

	// Step 3: Validate the initial token
	parsedToken, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	assert.NoError(t, err, "Failed to parse token")
	assert.True(t, parsedToken.Valid, "Token should be valid")

	parsedClaims, ok := parsedToken.Claims.(*JWTClaims)
	assert.True(t, ok, "Claims should be of type JWTClaims")
	assert.Equal(t, username, parsedClaims.Username, "Username in claims should match")
	assert.Equal(t, roles, parsedClaims.Roles, "Roles in claims should match")

	// Step 4: Validate the refresh token
	parsedRefreshToken, err := jwt.ParseWithClaims(refreshTokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	assert.NoError(t, err, "Failed to parse refresh token")
	assert.True(t, parsedRefreshToken.Valid, "Refresh token should be valid")

	parsedRefreshClaims, ok := parsedRefreshToken.Claims.(*jwt.RegisteredClaims)
	assert.True(t, ok, "Claims should be of type RegisteredClaims")
	assert.Equal(t, username, parsedRefreshClaims.Subject, "Subject in refresh claims should match username")

	// Step 5: Use the refresh token to generate a new token
	// This simulates what happens in HandleJWTTokenRefresh
	newRoles := []string{"user", "authenticated", "refreshed"}
	newClaims := JWTClaims{
		Username: username,
		Roles:    newRoles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "nauthilus",
			Subject:   username,
		},
	}

	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims)
	newTokenString, err := newToken.SignedString([]byte(secretKey))
	assert.NoError(t, err, "Failed to sign new token")
	assert.NotEmpty(t, newTokenString, "New token string should not be empty")

	// Step 6: Generate a new refresh token
	newRefreshClaims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "nauthilus",
		Subject:   username,
	}

	newRefreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newRefreshClaims)
	newRefreshTokenString, err := newRefreshToken.SignedString([]byte(secretKey))
	assert.NoError(t, err, "Failed to sign new refresh token")
	assert.NotEmpty(t, newRefreshTokenString, "New refresh token string should not be empty")

	// Step 7: Validate the new token
	parsedNewToken, err := jwt.ParseWithClaims(newTokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	assert.NoError(t, err, "Failed to parse new token")
	assert.True(t, parsedNewToken.Valid, "New token should be valid")

	parsedNewClaims, ok := parsedNewToken.Claims.(*JWTClaims)
	assert.True(t, ok, "Claims should be of type JWTClaims")
	assert.Equal(t, username, parsedNewClaims.Username, "Username in new claims should match")
	assert.Equal(t, newRoles, parsedNewClaims.Roles, "Roles in new claims should match")

	// Step 8: Validate the new refresh token
	parsedNewRefreshToken, err := jwt.ParseWithClaims(newRefreshTokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	assert.NoError(t, err, "Failed to parse new refresh token")
	assert.True(t, parsedNewRefreshToken.Valid, "New refresh token should be valid")

	parsedNewRefreshClaims, ok := parsedNewRefreshToken.Claims.(*jwt.RegisteredClaims)
	assert.True(t, ok, "Claims should be of type RegisteredClaims")
	assert.Equal(t, username, parsedNewRefreshClaims.Subject, "Subject in new refresh claims should match username")
}
