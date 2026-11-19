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
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	handlerdeps "github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/middleware/oidcbearer"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
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

// Register mounts the cache routes. Every one of them flushes state and needs a security write scope.
func (h *Handler) Register(router gin.IRouter) {
	cg := router.Group(
		"/"+definitions.CatCache,
		oidcbearer.RequireAnyScope(definitions.SecurityWriteScopes()...),
	)

	var flushOpts []core.TokenFlusher

	if h.deps.TokenFlusher != nil {
		flushOpts = append(flushOpts, h.deps.TokenFlusher)
	}

	cg.DELETE("/"+definitions.ServFlush, core.NewUserFlushHandlerWithEvents(h.deps.Cfg, h.deps.Logger, h.deps.Redis, pluginruntime.BruteForceEventEmitter(h.deps.PluginRunner), flushOpts...))
	cg.DELETE("/"+definitions.ServFlush+"/async", core.NewUserFlushAsyncHandlerWithEvents(h.deps.Cfg, h.deps.Logger, h.deps.Redis, pluginruntime.BruteForceEventEmitter(h.deps.PluginRunner), flushOpts...))
}
