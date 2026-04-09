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

package core

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// TestDefaultRouterComposer_ApplyCoreMiddlewares_AppliesCORS verifies that the
// centralized CORS middleware is attached in the core middleware chain.
func TestDefaultRouterComposer_ApplyCoreMiddlewares_AppliesCORS(t *testing.T) {
	gin.SetMode(gin.TestMode)

	enabled := true
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			CORS: config.CORS{
				Enabled: &enabled,
				Policies: []config.CORSPolicy{
					{
						Name:         "oidc_discovery",
						Enabled:      &enabled,
						PathPrefixes: []string{"/.well-known/"},
						AllowOrigins: []string{"https://oc.roessner.cloud"},
						AllowMethods: []string{"GET", "OPTIONS"},
						AllowHeaders: []string{"Authorization", "Content-Type"},
					},
				},
			},
		},
	}

	composer := NewDefaultRouterComposer(HTTPDeps{
		Cfg:    cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	r := composer.ComposeEngine()
	composer.ApplyCoreMiddlewares(r)
	r.GET("/.well-known/openid-configuration", func(ctx *gin.Context) {
		ctx.Status(http.StatusOK)
	})

	getReq := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	getReq.Header.Set("Origin", "https://oc.roessner.cloud")

	getResp := httptest.NewRecorder()
	r.ServeHTTP(getResp, getReq)

	assert.Equal(t, http.StatusOK, getResp.Code)
	assert.Equal(t, "https://oc.roessner.cloud", getResp.Header().Get("Access-Control-Allow-Origin"))

	optionsReq := httptest.NewRequest(http.MethodOptions, "/.well-known/openid-configuration", nil)
	optionsReq.Header.Set("Origin", "https://oc.roessner.cloud")
	optionsReq.Header.Set("Access-Control-Request-Method", "GET")

	optionsResp := httptest.NewRecorder()
	r.ServeHTTP(optionsResp, optionsReq)

	assert.Equal(t, http.StatusNoContent, optionsResp.Code)
	assert.Equal(t, "https://oc.roessner.cloud", optionsResp.Header().Get("Access-Control-Allow-Origin"))
}
