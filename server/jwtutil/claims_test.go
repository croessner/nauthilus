package jwtutil

import (
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/jwtclaims"
	"github.com/croessner/nauthilus/server/log"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestHasRole(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)

	// Set up test configuration to avoid "FileSettings not loaded" error
	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())
	config.SetTestFile(&config.FileSettings{
		Server: &config.ServerSection{},
	})

	// Set up logging
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	tests := []struct {
		name     string
		setup    func() *gin.Context
		role     string
		expected bool
	}{
		{
			name: "No claims in context",
			setup: func() *gin.Context {
				ctx := gin.Context{}
				ctx.Set(definitions.CtxGUIDKey, "test-guid")
				return &ctx
			},
			role:     "admin",
			expected: false,
		},
		{
			name: "Claims as *jwtclaims.Claims with matching role",
			setup: func() *gin.Context {
				ctx := gin.Context{}
				ctx.Set(definitions.CtxGUIDKey, "test-guid")
				ctx.Set(definitions.CtxJWTClaimsKey, &jwtclaims.Claims{
					Username: "testuser",
					Roles:    []string{"user", "admin"},
				})
				return &ctx
			},
			role:     "admin",
			expected: true,
		},
		{
			name: "Claims as *jwtclaims.Claims with non-matching role",
			setup: func() *gin.Context {
				ctx := gin.Context{}
				ctx.Set(definitions.CtxGUIDKey, "test-guid")
				ctx.Set(definitions.CtxJWTClaimsKey, &jwtclaims.Claims{
					Username: "testuser",
					Roles:    []string{"user"},
				})
				return &ctx
			},
			role:     "admin",
			expected: false,
		},
		{
			name: "Claims in unexpected format",
			setup: func() *gin.Context {
				ctx := gin.Context{}
				ctx.Set(definitions.CtxGUIDKey, "test-guid")
				ctx.Set(definitions.CtxJWTClaimsKey, "invalid-claims")
				return &ctx
			},
			role:     "admin",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setup()
			result := HasRole(ctx, tt.role)

			assert.Equal(t, tt.expected, result)
		})
	}
}
