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
	handlerdeps "github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/gin-gonic/gin"
)

// Handler exposes cache-related routes.
// It mirrors the legacy behavior and delegates logic to core while honoring endpoint feature flags.
type Handler struct {
	cfg  config.File
	deps *handlerdeps.Deps
}

func New(cfg config.File) *Handler {
	return &Handler{cfg: cfg}
}

// NewWithDeps constructs the cache handler with injected dependencies.
//
// Enables deps-based cache flush endpoints (avoid globals in request path).
func NewWithDeps(deps *handlerdeps.Deps) *Handler {
	if deps == nil {
		return &Handler{}
	}

	return &Handler{cfg: deps.Cfg, deps: deps}
}

func (h *Handler) Register(router gin.IRouter) {
	cg := router.Group("/" + definitions.CatCache)

	// Prefer deps-based handlers so Redis is injected.
	if h.deps != nil && h.deps.Cfg != nil {
		cg.DELETE("/"+definitions.ServFlush, core.NewUserFlushHandler(h.deps.Cfg, h.deps.Logger, h.deps.Redis))
		cg.DELETE("/"+definitions.ServFlush+"/async", core.NewUserFlushAsyncHandler(h.deps.Cfg, h.deps.Logger, h.deps.Redis))

		return
	}

	// Legacy path (will eventually be removed when all call sites migrate to NewWithDeps)
	deps := core.AuthDeps{
		Cfg:    core.GetDefaultConfigFile(),
		Logger: log.GetLogger(),
		Redis:  rediscli.GetClient(),
	}
	// core.restAdminDeps is compatible with core.AuthDeps's fields needed for these handlers
	adminDeps := core.NewRestAdminDeps(deps.Cfg, deps.Logger, deps.Redis)

	cg.DELETE("/"+definitions.ServFlush, core.HandleUserFlush(adminDeps))
	cg.DELETE("/"+definitions.ServFlush+"/async", core.HandleUserFlushAsync(adminDeps))
}
