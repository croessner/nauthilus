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

package limit

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/stats"

	"github.com/gin-gonic/gin"
	"github.com/segmentio/ksuid"
)

// LimitCounter tracks the current number of active connections and limits them based on a specified maximum.
type LimitCounter struct {
	// MaxConnections defines the maximum number of concurrent connections allowed.
	MaxConnections int32

	// CurrentConnections tracks the current number of active connections in the LimitCounter middleware.
	CurrentConnections int32
}

// NewLimitCounter creates a new LimitCounter instance with the specified maximum number of concurrent connections.
func NewLimitCounter(maxConnections int32) *LimitCounter {
	return &LimitCounter{
		MaxConnections: maxConnections,
	}
}

// Middleware limits the number of concurrent connections handled by the server based on MaxConnections.
// It is context-aware and prioritizes certain types of requests.
func (lc *LimitCounter) Middleware() gin.HandlerFunc {
	return lc.MiddlewareWithLogger(slog.Default())
}

// MiddlewareWithLogger is the logger-injected variant of Middleware.
func (lc *LimitCounter) MiddlewareWithLogger(logger *slog.Logger) gin.HandlerFunc {
	if logger == nil {
		logger = slog.Default()
	}

	return func(ctx *gin.Context) {
		// Always allow health check and metrics endpoints regardless of connection limits
		if ctx.FullPath() == "/ping" || ctx.FullPath() == "/metrics" {
			ctx.Next()

			return
		}

		// Check if we're at the connection limit
		currentConnections := atomic.LoadInt32(&lc.CurrentConnections)
		if currentConnections >= lc.MaxConnections {
			ctx.Set(definitions.CtxRateLimitReasonKey, "concurrency")

			// For API requests, return 429 status code
			ctx.JSON(http.StatusTooManyRequests, gin.H{
				definitions.LogKeyMsg: "Too many requests",
				"scope":               "concurrency",
				"current":             currentConnections,
				"max":                 lc.MaxConnections,
			})

			ctx.Abort()

			return
		}

		// Store the request start time in the context for performance tracking
		startTime := time.Now()
		ctx.Set(definitions.CtxRequestStartTimeKey, startTime)

		// Increment the connection counter
		atomic.AddInt32(&lc.CurrentConnections, 1)
		currentConnections = atomic.LoadInt32(&lc.CurrentConnections)

		// Update metrics
		stats.GetMetrics().GetCurrentRequests().Set(float64(currentConnections))

		// Add connection info to the context
		ctx.Set(definitions.CtxCurrentConnectionsKey, currentConnections)
		ctx.Set(definitions.CtxMaxConnectionsKey, lc.MaxConnections)

		// Process the request and decrement the counter when done
		defer func() {
			atomic.AddInt32(&lc.CurrentConnections, -1)

			// Detect client-canceled requests (context canceled) and mark/log as 499 if possible
			canceled := errors.Is(ctx.Request.Context().Err(), context.Canceled)
			if canceled {
				// Log cancellation; use GUID if present
				guid, exists := ctx.Get(definitions.CtxGUIDKey)
				if !exists {
					guid = ksuid.New().String()
				}

				level.Warn(logger).Log(
					definitions.LogKeyGUID, guid,
					definitions.LogKeyMsg, definitions.MsgClientClosedRequest,
					"path", ctx.FullPath(),
					"status", definitions.StatusClientClosedRequest,
				)

				// If nothing was written yet and handler didn't abort, respond with 499
				if !ctx.Writer.Written() && !ctx.IsAborted() {
					ctx.AbortWithStatus(definitions.StatusClientClosedRequest)
				}
			}

			// Calculate and log request duration for performance monitoring
			if startTimeValue, exists := ctx.Get(definitions.CtxRequestStartTimeKey); exists {
				if startTime, ok := startTimeValue.(time.Time); ok {
					duration := time.Since(startTime)
					ctx.Set(definitions.CtxRequestDurationKey, duration)

					// Log long-running requests for further optimization (skip if client canceled)
					if !canceled && duration > 1500*time.Millisecond {
						// Get GUID from context if available, otherwise generate a new one
						guid, exists := ctx.Get(definitions.CtxGUIDKey)
						if !exists {
							guid = ksuid.New().String()
						}

						level.Warn(logger).Log(
							definitions.LogKeyGUID, guid,
							definitions.LogKeyMsg, "Long-running request detected",
							"path", ctx.FullPath(),
							"duration_ms", duration.Milliseconds(),
						)
					}
				}
			}
		}()

		ctx.Next()
	}
}
