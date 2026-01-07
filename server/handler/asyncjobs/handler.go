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

package asyncjobs

import (
	"net/http"

	"github.com/croessner/nauthilus/server/core"
	handlerdeps "github.com/croessner/nauthilus/server/handler/deps"

	"github.com/gin-gonic/gin"
)

// Handler registers the async jobs status endpoint.
type Handler struct {
	deps *handlerdeps.Deps
}

func New() *Handler { return &Handler{} }

func NewWithDeps(deps *handlerdeps.Deps) *Handler { return &Handler{deps: deps} }

func (h *Handler) Register(router gin.IRouter) {
	ag := router.Group("/async")

	if h.deps == nil || h.deps.Cfg == nil || h.deps.Logger == nil || h.deps.Redis == nil {
		// Strict DI: this endpoint requires explicit dependencies.
		ag.GET("/jobs/:jobId", func(c *gin.Context) { c.AbortWithStatus(http.StatusInternalServerError) })

		return
	}

	ag.GET("/jobs/:jobId", core.NewAsyncJobStatusHandler(h.deps.Cfg, h.deps.Logger, h.deps.Redis))
}
