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
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
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

func New() *Handler {
	return &Handler{}
}

func NewWithDeps(cfg config.File, logger *slog.Logger, redis rediscli.Client) *Handler {
	return &Handler{cfg: cfg, logger: logger, redis: redis}
}

func (h *Handler) Register(router gin.IRouter) {
	router.GET("/metrics", func(ctx *gin.Context) {
		cfg := h.cfg
		if cfg == nil {
			cfg = config.GetFile()
		}

		logger := h.logger
		if logger == nil {
			logger = slog.Default()
		}

		redisClient := h.redis
		if redisClient == nil {
			redisClient = rediscli.GetClient()
		}

		// If JWT is enabled, allow only users with RoleSecurity
		if cfg.GetServer().GetJWTAuth().IsEnabled() {
			tokenString, err := core.ExtractJWTTokenWithCfg(ctx, cfg)
			if err == nil {
				if claims, err := core.ValidateJWTToken(ctx, tokenString, core.JWTDeps{Cfg: cfg, Logger: logger, Redis: redisClient}); err == nil {
					for _, role := range claims.Roles {
						if role == definitions.RoleSecurity {
							promHandler := promhttp.HandlerFor(
								prometheus.DefaultGatherer,
								promhttp.HandlerOpts{DisableCompression: true},
							)

							promHandler.ServeHTTP(ctx.Writer, ctx.Request)

							return
						}
					}
				}
			}
		}

		// Fallback to Basic Auth if enabled
		if mdauth.CheckAndRequireBasicAuthWithCfg(ctx, cfg) {
			promHandler := promhttp.HandlerFor(
				prometheus.DefaultGatherer,
				promhttp.HandlerOpts{DisableCompression: true},
			)

			promHandler.ServeHTTP(ctx.Writer, ctx.Request)

			return
		}

		// If neither auth allowed request, return 401 to be safe
		ctx.AbortWithStatus(http.StatusUnauthorized)
	})
}
