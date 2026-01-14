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

package jwtutil

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/jwtclaims"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestHasRole(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)

	// Set up test configuration to avoid "FileSettings not loaded" error
	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())
	testFile := &config.FileSettings{
		Server: &config.ServerSection{},
	}
	config.SetTestFile(testFile)
	util.SetDefaultConfigFile(testFile)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

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
				ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
				ctx.Request = httptest.NewRequest(http.MethodPost, "/", nil)
				ctx.Set(definitions.CtxGUIDKey, "test-guid")
				return ctx
			},
			role:     "admin",
			expected: false,
		},
		{
			name: "Claims as *jwtclaims.Claims with matching role",
			setup: func() *gin.Context {
				ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
				ctx.Request = httptest.NewRequest(http.MethodPost, "/", nil)
				ctx.Set(definitions.CtxGUIDKey, "test-guid")
				ctx.Set(definitions.CtxJWTClaimsKey, &jwtclaims.Claims{
					Username: "testuser",
					Roles:    []string{"user", "admin"},
				})
				return ctx
			},
			role:     "admin",
			expected: true,
		},
		{
			name: "Claims as *jwtclaims.Claims with non-matching role",
			setup: func() *gin.Context {
				ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
				ctx.Request = httptest.NewRequest(http.MethodPost, "/", nil)
				ctx.Set(definitions.CtxGUIDKey, "test-guid")
				ctx.Set(definitions.CtxJWTClaimsKey, &jwtclaims.Claims{
					Username: "testuser",
					Roles:    []string{"user"},
				})
				return ctx
			},
			role:     "admin",
			expected: false,
		},
		{
			name: "Claims in unexpected format",
			setup: func() *gin.Context {
				ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
				ctx.Request = httptest.NewRequest(http.MethodPost, "/", nil)
				ctx.Set(definitions.CtxGUIDKey, "test-guid")
				ctx.Set(definitions.CtxJWTClaimsKey, "invalid-claims")
				return ctx
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
