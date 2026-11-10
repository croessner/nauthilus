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
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/croessner/nauthilus/v4/server/conncause"
	"github.com/croessner/nauthilus/v4/server/definitions"

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

func TestLimitCounterNeverAdmitsMoreThanTheMaximum(t *testing.T) {
	const (
		maximum = 8
		callers = 64
	)

	counter := NewLimitCounter(maximum)

	var (
		wait     sync.WaitGroup
		peak     atomic.Int32
		admitted atomic.Int32
	)

	for range callers {
		wait.Go(func() {
			for range 200 {
				current, ok := counter.TryAcquire()
				if !ok {
					continue
				}

				admitted.Add(1)

				for {
					seen := peak.Load()
					if current <= seen || peak.CompareAndSwap(seen, current) {
						break
					}
				}

				counter.Release()
			}
		})
	}

	wait.Wait()

	if peak.Load() > maximum || admitted.Load() == 0 || counter.CurrentConnections != 0 {
		t.Fatalf("peak = %d, admitted = %d, left = %d; want peak <= %d and a drained counter",
			peak.Load(), admitted.Load(), counter.CurrentConnections, maximum)
	}
}

// TestLimitCounterLogsTerminatedRequestsByCause pins that client disconnects are logged at INFO with
// status 499, while server-side connection terminations are logged at WARN with their cause.
func TestLimitCounterLogsTerminatedRequestsByCause(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		cause      error
		name       string
		wantLevel  string
		wantMsg    string
		wantStatus int
	}{
		{name: "client disconnected", cause: conncause.ErrClientDisconnected, wantLevel: `"level":"INFO"`, wantMsg: definitions.MsgClientClosedRequest, wantStatus: definitions.StatusClientClosedRequest},
		{name: "stream reset without cause", cause: context.Canceled, wantLevel: `"level":"INFO"`, wantMsg: definitions.MsgClientClosedRequest, wantStatus: definitions.StatusClientClosedRequest},
		{name: "server timeout", cause: conncause.ErrConnectionTimeout, wantLevel: `"level":"WARN"`, wantMsg: msgRequestConnectionTerminated, wantStatus: http.StatusOK},
		{name: "closed locally", cause: conncause.ErrConnectionClosedLocally, wantLevel: `"level":"WARN"`, wantMsg: msgRequestConnectionTerminated, wantStatus: http.StatusOK},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer

			logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
			engine := gin.New()
			engine.Use(NewLimitCounter(4).MiddlewareWithLogger(logger))
			engine.GET("/other", func(*gin.Context) {})

			ctx, cancel := context.WithCancelCause(context.Background())
			cancel(test.cause)

			recorder := httptest.NewRecorder()
			request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/other", nil)

			engine.ServeHTTP(recorder, request)

			assert.Contains(t, output.String(), test.wantLevel)
			assert.Contains(t, output.String(), test.wantMsg)
			assert.Equal(t, test.wantStatus, recorder.Code)
		})
	}
}
