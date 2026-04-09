// Copyright (C) 2026 Christian Rößner
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

package cors

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// TestMiddleware_AddsCORSHeadersForAllowedOrigin verifies that an allowed origin
// receives the expected CORS response headers on a normal request.
func TestMiddleware_AddsCORSHeadersForAllowedOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := testConfig()
	mw := New(MiddlewareConfig{Config: cfg})

	r := gin.New()
	r.Use(mw.Handler())
	r.GET("/.well-known/openid-configuration", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Header.Set("Origin", "https://oc.roessner.cloud")

	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "https://oc.roessner.cloud", resp.Header().Get("Access-Control-Allow-Origin"))
}

// TestMiddleware_HandlesPreflightWithoutRoute verifies that preflight requests are
// handled by the middleware even when no explicit OPTIONS route exists.
func TestMiddleware_HandlesPreflightWithoutRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := testConfig()
	mw := New(MiddlewareConfig{Config: cfg})

	r := gin.New()
	r.Use(mw.Handler())

	req := httptest.NewRequest(http.MethodOptions, "/.well-known/openid-configuration", nil)
	req.Header.Set("Origin", "https://oc.roessner.cloud")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "Authorization")

	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusNoContent, resp.Code)
	assert.Equal(t, "https://oc.roessner.cloud", resp.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "GET, OPTIONS", resp.Header().Get("Access-Control-Allow-Methods"))
	assert.Equal(t, "Authorization, Content-Type", resp.Header().Get("Access-Control-Allow-Headers"))
}

// TestMiddleware_RejectsPreflightFromUnlistedOrigin verifies that preflight
// requests from origins outside the allow list are rejected.
func TestMiddleware_RejectsPreflightFromUnlistedOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := testConfig()
	mw := New(MiddlewareConfig{Config: cfg})

	r := gin.New()
	r.Use(mw.Handler())

	req := httptest.NewRequest(http.MethodOptions, "/.well-known/openid-configuration", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")

	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusForbidden, resp.Code)
}

// testConfig returns a minimal CORS-enabled test configuration.
func testConfig() *config.FileSettings {
	enabled := true

	return &config.FileSettings{
		Server: &config.ServerSection{
			CORS: config.CORS{
				Enabled: &enabled,
				Policies: []config.CORSPolicy{
					{
						Name:         "oidc_discovery",
						PathPrefixes: []string{"/.well-known/"},
						AllowOrigins: []string{"https://oc.roessner.cloud"},
						AllowMethods: []string{"GET", "OPTIONS"},
						AllowHeaders: []string{"Authorization", "Content-Type"},
						MaxAge:       600,
					},
				},
			},
		},
	}
}
