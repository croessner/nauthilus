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

package limit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// probeBypassPaths lists the routes that must pass a saturated limiter.
var probeBypassPaths = []string{"/ping", "/livez", "/healthz", "/metrics"}

// serveLimitedRoutes serves one GET per path through the given middleware and returns the status codes.
func serveLimitedRoutes(middleware gin.HandlerFunc, paths ...string) map[string]int {
	engine := gin.New()
	engine.Use(middleware)

	for _, path := range paths {
		engine.GET(path, func(c *gin.Context) {
			c.Status(http.StatusOK)
		})
	}

	codes := make(map[string]int, len(paths))

	for _, path := range paths {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.RemoteAddr = "192.0.2.10:1234"

		engine.ServeHTTP(recorder, request)

		codes[path] = recorder.Code
	}

	return codes
}

// TestLimitCounterBypassesProbeRoutes pins that probes and metrics scrapes pass a full concurrency limiter
// while ordinary routes are rejected.
func TestLimitCounterBypassesProbeRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	codes := serveLimitedRoutes(NewLimitCounter(0).Middleware(), append([]string{"/other"}, probeBypassPaths...)...)

	for _, path := range probeBypassPaths {
		assert.Equal(t, http.StatusOK, codes[path], path)
	}

	assert.Equal(t, http.StatusTooManyRequests, codes["/other"])
}

// TestIPRateLimiterBypassesProbeRoutes pins that probes and metrics scrapes pass an exhausted rate limiter
// while ordinary routes are rejected.
func TestIPRateLimiterBypassesProbeRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	codes := serveLimitedRoutes(NewIPRateLimiter(0, 0).Middleware(), append([]string{"/other"}, probeBypassPaths...)...)

	for _, path := range probeBypassPaths {
		assert.Equal(t, http.StatusOK, codes[path], path)
	}

	assert.Equal(t, http.StatusTooManyRequests, codes["/other"])
}
