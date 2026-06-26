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

// Package cache provides cache functionality.
package cache

import (
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	handlerdeps "github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/middleware/oidcbearer"
	"github.com/gin-gonic/gin"
)

// Handler exposes cache-related routes.
type Handler struct {
	deps *handlerdeps.Deps
}

// New constructs the cache handler with injected dependencies.
func New(deps *handlerdeps.Deps) *Handler {
	if deps == nil {
		return &Handler{}
	}

	return &Handler{deps: deps}
}

// Register provides the exported Register method.
func (h *Handler) Register(router gin.IRouter) {
	cg := router.Group(
		"/"+definitions.CatCache,
		oidcbearer.RequireAnyScope(definitions.ScopeSecurity, definitions.ScopeAdmin),
	)

	var flushOpts []core.TokenFlusher

	if h.deps.TokenFlusher != nil {
		flushOpts = append(flushOpts, h.deps.TokenFlusher)
	}

	cg.DELETE("/"+definitions.ServFlush, core.NewUserFlushHandler(h.deps.Cfg, h.deps.Logger, h.deps.Redis, flushOpts...))
	cg.DELETE("/"+definitions.ServFlush+"/async", core.NewUserFlushAsyncHandler(h.deps.Cfg, h.deps.Logger, h.deps.Redis, flushOpts...))
}
