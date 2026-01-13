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

package notify

import (
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"

	mdauth "github.com/croessner/nauthilus/server/middleware/auth"
	mdlua "github.com/croessner/nauthilus/server/middleware/lua"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

type Handler struct {
	Store sessions.Store
	Deps  *deps.Deps
}

func New(store sessions.Store, d *deps.Deps) *Handler {
	return &Handler{Store: store, Deps: d}
}

func (h *Handler) Register(router gin.IRouter) {
	group := router.Group(viper.GetString("notify_page"))

	group.Use(sessions.Sessions(definitions.SessionName, h.Store))
	group.GET("/", mdlua.LuaContextMiddleware(), mdauth.ProtectEndpointMiddleware(h.Deps.Cfg, h.Deps.Logger), core.WithLanguageMiddleware(core.AuthDeps{Cfg: h.Deps.Cfg, Logger: h.Deps.Logger, Redis: h.Deps.Redis}), h.Deps.Svc.NotifyGETHandler())
	group.GET("/:languageTag", mdlua.LuaContextMiddleware(), mdauth.ProtectEndpointMiddleware(h.Deps.Cfg, h.Deps.Logger), core.WithLanguageMiddleware(core.AuthDeps{Cfg: h.Deps.Cfg, Logger: h.Deps.Logger, Redis: h.Deps.Redis}), h.Deps.Svc.NotifyGETHandler())
}
