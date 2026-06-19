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

// Package asyncjobs provides asyncjobs functionality.
package asyncjobs

import (
	"github.com/croessner/nauthilus/v3/server/core"
	handlerdeps "github.com/croessner/nauthilus/v3/server/handler/deps"

	"github.com/gin-gonic/gin"
)

// Handler registers the async jobs status endpoint.
type Handler struct {
	deps *handlerdeps.Deps
}

// New constructs the async jobs handler with injected dependencies.
func New(deps *handlerdeps.Deps) *Handler { return &Handler{deps: deps} }

// Register provides the exported Register method.
func (h *Handler) Register(router gin.IRouter) {
	ag := router.Group("/async")

	ag.GET("/jobs/:jobId", core.NewAsyncJobStatusHandler(h.deps.Cfg, h.deps.Logger, h.deps.Redis))
}
