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

package confighandler

import (
	"net/http"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	cfg config.File
}

func New(cfg config.File) *Handler {
	return &Handler{cfg: cfg}
}

func (h *Handler) Register(r gin.IRouter) {
	cg := r.Group("/" + definitions.CatConfig)

	cg.GET("/"+definitions.ServLoad, h.load)
	cg.POST("/"+definitions.ServLoad, h.load)
}

func (h *Handler) load(c *gin.Context) {
	if h.cfg.GetServer().GetEndpoint().IsConfigurationDisabled() {
		c.AbortWithStatus(http.StatusNotFound)

		return
	}

	core.HandleConfigLoad(c)
}
