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

package metrics

import (
	"fmt"
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

// PrometheusMiddleware is a Gin middleware for tracking HTTP request metrics using Prometheus timers and counters.
// It records request counts and response times based on the request path and mode query parameter.
// Metrics include the total number of requests and the duration of HTTP responses.
// The middleware respects configuration settings for enabling Prometheus timers and uses predefined labels for tracking.
func PrometheusMiddleware() gin.HandlerFunc {
	return PrometheusMiddlewareWithCfg(nil)
}

func PrometheusMiddlewareWithCfg(cfg config.File) gin.HandlerFunc {
	enableTimer := false
	if cfg != nil {
		enableTimer = cfg.GetServer().GetPrometheusTimer().IsEnabled()
	}

	return func(ctx *gin.Context) {
		var timer *prometheus.Timer

		mode := ctx.Query("mode")
		if mode == "" {
			mode = "auth"
		}

		stopTimer := stats.PrometheusTimer(cfg, definitions.PromRequest, fmt.Sprintf("request_%s_total", strings.ReplaceAll(mode, "-", "_")))
		path := ctx.FullPath()

		if enableTimer {
			timer = prometheus.NewTimer(stats.GetMetrics().GetHttpResponseTimeSeconds().WithLabelValues(path))
		}

		ctx.Next()

		stats.GetMetrics().GetHttpRequestsTotal().WithLabelValues(path).Inc()

		if enableTimer && timer != nil {
			timer.ObserveDuration()
		}

		if stopTimer != nil {
			stopTimer()
		}
	}
}
