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

// Package limit provides limit functionality.
package limit

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"github.com/croessner/nauthilus/v4/server/stats"

	"github.com/gin-gonic/gin"
	"github.com/segmentio/ksuid"
)

const (
	limitBypassHealthPath   = "/healthz"
	limitBypassLivenessPath = "/livez"
	limitBypassMetricsPath  = "/metrics"
	limitBypassPingPath     = "/ping"
	limitResponseKeyScope   = "scope"
	limitScopeConcurrency   = "concurrency"
)

// Counter tracks the current number of active connections and limits them based on a specified maximum.
type Counter struct {
	// MaxConnections defines the maximum number of concurrent connections allowed.
	MaxConnections int32

	// CurrentConnections tracks the current number of active connections in the Counter middleware.
	CurrentConnections int32
}

// NewLimitCounter creates a new Counter instance with the specified maximum number of concurrent connections.
func NewLimitCounter(maxConnections int32) *Counter {
	return &Counter{
		MaxConnections: maxConnections,
	}
}

// Middleware limits the number of concurrent connections handled by the server based on MaxConnections.
// It is context-aware and prioritizes certain types of requests.
func (lc *Counter) Middleware() gin.HandlerFunc {
	return lc.MiddlewareWithLogger(slog.Default())
}

// MiddlewareWithLogger is the logger-injected variant of Middleware.
func (lc *Counter) MiddlewareWithLogger(logger *slog.Logger) gin.HandlerFunc {
	if logger == nil {
		logger = slog.Default()
	}

	return func(ctx *gin.Context) {
		if isLimitBypassPath(ctx.FullPath()) {
			ctx.Next()

			return
		}

		currentConnections, acquired := lc.TryAcquire()
		if !acquired {
			lc.rejectOverLimit(ctx, currentConnections)

			return
		}

		lc.trackRequestStart(ctx, currentConnections)
		defer lc.finishRequest(ctx, logger)

		ctx.Next()
	}
}

// isLimitBypassPath reports whether a route bypasses the concurrency and rate limits. Probes and
// metrics scrapes must keep answering while the server is saturated.
func isLimitBypassPath(path string) bool {
	switch path {
	case limitBypassPingPath, limitBypassLivenessPath, limitBypassHealthPath, limitBypassMetricsPath:
		return true
	default:
		return false
	}
}

// TryAcquire reserves one request slot and returns the number of active requests. It reserves nothing and
// reports false when the counter is full. The counter may be shared by several transports, so the HTTP API and
// the gRPC authority draw on one budget for the memory of the same process.
func (lc *Counter) TryAcquire() (int32, bool) {
	current := atomic.AddInt32(&lc.CurrentConnections, 1)
	if current > lc.MaxConnections {
		atomic.AddInt32(&lc.CurrentConnections, -1)

		return current - 1, false
	}

	stats.GetMetrics().GetCurrentRequests().Set(float64(current))

	return current, true
}

// Release frees one slot reserved by TryAcquire.
func (lc *Counter) Release() {
	current := atomic.AddInt32(&lc.CurrentConnections, -1)
	stats.GetMetrics().GetCurrentRequests().Set(float64(current))
}

// rejectOverLimit writes the concurrency-limit response for a request that found the counter full.
func (lc *Counter) rejectOverLimit(ctx *gin.Context, currentConnections int32) {
	ctx.Set(definitions.CtxRateLimitReasonKey, limitScopeConcurrency)
	ctx.JSON(http.StatusTooManyRequests, gin.H{
		definitions.LogKeyMsg: "Too many requests",
		limitResponseKeyScope: limitScopeConcurrency,
		"current":             currentConnections,
		"max":                 lc.MaxConnections,
	})
	ctx.Abort()
}

// trackRequestStart records the metadata of a request that holds a slot.
func (lc *Counter) trackRequestStart(ctx *gin.Context, currentConnections int32) {
	ctx.Set(definitions.CtxRequestStartTimeKey, time.Now())
	ctx.Set(definitions.CtxCurrentConnectionsKey, currentConnections)
	ctx.Set(definitions.CtxMaxConnectionsKey, lc.MaxConnections)
}

// finishRequest records completion details and decrements active connections.
func (lc *Counter) finishRequest(ctx *gin.Context, logger *slog.Logger) {
	lc.Release()

	canceled := errors.Is(ctx.Request.Context().Err(), context.Canceled)
	if canceled {
		logClientCanceledRequest(ctx, logger)
	}

	recordRequestDuration(ctx, logger, canceled)
}

// logClientCanceledRequest logs and marks requests canceled by the client.
func logClientCanceledRequest(ctx *gin.Context, logger *slog.Logger) {
	level.Warn(logger).Log(
		definitions.LogKeyGUID, limitRequestGUID(ctx),
		definitions.LogKeyMsg, definitions.MsgClientClosedRequest,
		"path", ctx.FullPath(),
		"status", definitions.StatusClientClosedRequest,
	)

	if !ctx.Writer.Written() && !ctx.IsAborted() {
		ctx.AbortWithStatus(definitions.StatusClientClosedRequest)
	}
}

// recordRequestDuration stores the request duration and logs slow requests.
func recordRequestDuration(ctx *gin.Context, logger *slog.Logger, canceled bool) {
	startTimeValue, exists := ctx.Get(definitions.CtxRequestStartTimeKey)
	if !exists {
		return
	}

	startTime, ok := startTimeValue.(time.Time)
	if !ok {
		return
	}

	duration := time.Since(startTime)
	ctx.Set(definitions.CtxRequestDurationKey, duration)

	if !canceled && duration > 1500*time.Millisecond {
		logLongRunningRequest(ctx, logger, duration)
	}
}

// logLongRunningRequest logs requests exceeding the middleware duration threshold.
func logLongRunningRequest(ctx *gin.Context, logger *slog.Logger, duration time.Duration) {
	level.Warn(logger).Log(
		definitions.LogKeyGUID, limitRequestGUID(ctx),
		definitions.LogKeyMsg, "Long-running request detected",
		"path", ctx.FullPath(),
		"duration_ms", duration.Milliseconds(),
	)
}

// limitRequestGUID returns the request GUID or creates a fallback value.
func limitRequestGUID(ctx *gin.Context) any {
	guid, exists := ctx.Get(definitions.CtxGUIDKey)
	if !exists {
		return ksuid.New().String()
	}

	return guid
}
