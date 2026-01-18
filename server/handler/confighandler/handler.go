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
	handlerdeps "github.com/croessner/nauthilus/server/handler/deps"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	cfg  config.File
	deps *handlerdeps.Deps
}

// NewWithDeps constructs the config handler with injected dependencies.
//
// Enables deps-based endpoints (avoid globals in request path).
func NewWithDeps(deps *handlerdeps.Deps) *Handler {
	if deps == nil {
		return &Handler{}
	}

	return &Handler{cfg: deps.Cfg, deps: deps}
}

func (h *Handler) Register(r gin.IRouter) {
	cg := r.Group("/" + definitions.CatConfig)

	cg.GET("/"+definitions.ServLoad, h.load)
}

func (h *Handler) load(c *gin.Context) {
	if h.cfg == nil {
		c.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	if h.cfg.GetServer().GetEndpoint().IsConfigurationDisabled() {
		c.AbortWithStatus(http.StatusNotFound)

		return
	}

	core.NewConfigLoadHandler(h.cfg, h.deps.Logger, h.deps.Redis)(c)
}
