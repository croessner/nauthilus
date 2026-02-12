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

package health

import (
	"log/slog"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/gin-gonic/gin"

	approuter "github.com/croessner/nauthilus/server/router"
)

// Handler registers the health endpoints.
type Handler struct {
	cfg    config.File
	logger *slog.Logger
	redis  rediscli.Client
}

func New(cfg config.File, logger *slog.Logger, redis rediscli.Client) *Handler {
	return &Handler{cfg: cfg, logger: logger, redis: redis}
}

func (h *Handler) Register(router gin.IRouter) {
	deps := HealthzDeps{Cfg: h.cfg, Logger: h.logger, Redis: h.redis}

	router.GET("/ping", approuter.HealthCheck)
	router.GET("/healthz", func(ctx *gin.Context) {
		ReadinessCheck(ctx, deps)
	})
}
