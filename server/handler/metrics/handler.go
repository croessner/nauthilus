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
	"log/slog"
	"net/http"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/rediscli"

	mdauth "github.com/croessner/nauthilus/server/middleware/auth"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Handler registers the metrics endpoint.
type Handler struct {
	cfg    config.File
	logger *slog.Logger
	redis  rediscli.Client
}

func New(cfg config.File, logger *slog.Logger, redis rediscli.Client) *Handler {
	return &Handler{cfg: cfg, logger: logger, redis: redis}
}

func (h *Handler) Register(router gin.IRouter) {
	router.GET("/metrics", func(ctx *gin.Context) {
		if !h.authorize(ctx) {
			return
		}

		servePrometheusMetrics(ctx)
	})
}

func (h *Handler) authorize(ctx *gin.Context) bool {
	basicAuth := metricsEndpointBasicAuth(h.cfg)
	if !basicAuth.IsEnabled() {
		return true
	}

	username, password, ok := ctx.Request.BasicAuth()
	if ok && mdauth.ValidateBasicAuthCredentials(basicAuth, username, password) {
		ctx.Set(definitions.CtxBasicAuthValidatedKey, true)
		ctx.Set(definitions.CtxAuthMethodKey, "basic_auth")

		return true
	}

	mdauth.ApplyAuthBackoffOnFailureWithCfg(ctx, h.cfg)
	ctx.Header("WWW-Authenticate", "Basic realm=\"metrics\", charset=\"UTF-8\"")
	ctx.AbortWithStatus(http.StatusUnauthorized)

	return false
}

func metricsEndpointBasicAuth(cfg config.File) *config.BasicAuth {
	if cfg == nil {
		return &config.BasicAuth{}
	}

	return cfg.GetServer().GetMetricsEndpointAuth().GetBasicAuth()
}

func servePrometheusMetrics(ctx *gin.Context) {
	promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		promhttp.HandlerOpts{DisableCompression: true},
	).ServeHTTP(ctx.Writer, ctx.Request)
}
