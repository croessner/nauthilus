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
	"github.com/croessner/nauthilus/server/middleware/oidcbearer"
	"github.com/croessner/nauthilus/server/rediscli"

	mdauth "github.com/croessner/nauthilus/server/middleware/auth"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Handler registers the metrics endpoint with identical auth semantics as before.
type Handler struct {
	cfg    config.File
	logger *slog.Logger
	redis  rediscli.Client
}

func NewWithDeps(cfg config.File, logger *slog.Logger, redis rediscli.Client) *Handler {
	return &Handler{cfg: cfg, logger: logger, redis: redis}
}

func (h *Handler) Register(router gin.IRouter) {
	router.GET("/metrics", func(ctx *gin.Context) {
		cfg := h.cfg

		// If OIDC Bearer token is present, allow only tokens with ScopeSecurity
		claims := oidcbearer.GetClaimsFromContext(ctx)

		if claims != nil {
			if oidcbearer.HasScope(claims, definitions.ScopeSecurity) {
				promhttp.HandlerFor(
					prometheus.DefaultGatherer,
					promhttp.HandlerOpts{DisableCompression: true},
				).ServeHTTP(ctx.Writer, ctx.Request)

				return
			}
		}

		// Fallback to Basic Auth if enabled
		if mdauth.CheckAndRequireBasicAuth(ctx, cfg) {
			promhttp.HandlerFor(
				prometheus.DefaultGatherer,
				promhttp.HandlerOpts{DisableCompression: true},
			).ServeHTTP(ctx.Writer, ctx.Request)

			return
		}

		// If neither auth allowed request, return 401 to be safe
		ctx.AbortWithStatus(http.StatusUnauthorized)
	})
}
