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
