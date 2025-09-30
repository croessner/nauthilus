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

package cache

import (
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-gonic/gin"
)

// Handler exposes cache-related routes.
// It mirrors the legacy behavior and delegates logic to core while honoring endpoint feature flags.
type Handler struct {
	cfg config.File
}

func New(cfg config.File) *Handler {
	return &Handler{cfg: cfg}
}

func (h *Handler) Register(router gin.IRouter) {
	cg := router.Group("/" + definitions.CatCache)

	cg.DELETE("/"+definitions.ServFlush, h.flush)
}

func (h *Handler) flush(ctx *gin.Context) {
	core.HandleUserFlush(ctx)
}
