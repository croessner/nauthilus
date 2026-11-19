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

// Package bruteforce provides bruteforce functionality.
package bruteforce

import (
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	handlerdeps "github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/middleware/oidcbearer"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	"github.com/gin-gonic/gin"
)

// Handler describes the exported Handler type.
type Handler struct {
	deps *handlerdeps.Deps
}

// New provides the exported New function.
func New(deps *handlerdeps.Deps) *Handler {
	return &Handler{deps: deps}
}

// Register mounts the brute-force routes. Listing needs a security read scope, whatever the HTTP method of the
// filtered listing; flushing needs a security write scope.
func (h *Handler) Register(router gin.IRouter) {
	bg := router.Group("/" + definitions.CatBruteForce)
	read := oidcbearer.RequireAnyScope(definitions.SecurityReadScopes()...)
	write := oidcbearer.RequireAnyScope(definitions.SecurityWriteScopes()...)

	bg.GET("/"+definitions.ServList, read, core.NewBruteForceListHandler(h.deps.Cfg, h.deps.Logger, h.deps.Redis))
	bg.POST("/"+definitions.ServList, read, core.NewBruteForceListHandler(h.deps.Cfg, h.deps.Logger, h.deps.Redis))
	bg.DELETE("/"+definitions.ServFlush, write, core.NewBruteForceFlushHandlerWithEvents(h.deps.Cfg, h.deps.Logger, h.deps.Redis, pluginruntime.BruteForceEventEmitter(h.deps.PluginRunner)))
	bg.DELETE("/"+definitions.ServFlush+"/async", write, core.NewBruteForceFlushAsyncHandlerWithEvents(h.deps.Cfg, h.deps.Logger, h.deps.Redis, pluginruntime.BruteForceEventEmitter(h.deps.PluginRunner)))
}
