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

	"github.com/croessner/nauthilus/v4/server/config"
	mdlimit "github.com/croessner/nauthilus/v4/server/middleware/limit"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// TestDefaultRouterComposer_ApplyEarlyMiddlewares_UsesInjectedRateLimiter pins that the global per-IP middleware
// uses the injected limiter, so the backchannel caller authentication shares its per-IP state and route exemptions.
func TestDefaultRouterComposer_ApplyEarlyMiddlewares_UsesInjectedRateLimiter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	disabled := false
	cfg := &config.FileSettings{Server: &config.ServerSection{
		Middlewares: config.Middlewares{Logging: &disabled, Limit: &disabled},
	}}
	limiter := mdlimit.NewIPRateLimiter(0.001, 1)

	composer := NewDefaultRouterComposer(HTTPDeps{
		Cfg:       cfg,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		RateLimit: limiter,
	})

	router := composer.ComposeEngine()
	composer.ApplyEarlyMiddlewares(router)

	for _, path := range []string{"/exempt", "/other"} {
		router.GET(path, func(ctx *gin.Context) {
			ctx.Status(http.StatusNoContent)
		})
	}

	limiter.ExemptRoute(http.MethodGet, "/exempt")

	serve := func(path string) int {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))

		return response.Code
	}

	assert.Equal(t, []int{http.StatusNoContent, http.StatusNoContent, http.StatusNoContent}, []int{serve("/exempt"), serve("/exempt"), serve("/exempt")})
	assert.Equal(t, []int{http.StatusNoContent, http.StatusTooManyRequests}, []int{serve("/other"), serve("/other")})
}
