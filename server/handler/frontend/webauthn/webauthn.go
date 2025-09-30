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

package webauthn

import (
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/tags"

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

func (h *Handler) Register(r gin.IRouter) {
	if !tags.IsDevelopment {
		return
	}

	group := r.Group(definitions.TwoFAv1Root)

	regGroup := group.Group(viper.GetString("webauthn_page"))
	regGroup.Use(sessions.Sessions(definitions.SessionName, h.Store))
	regGroup.GET("/register/begin", h.Deps.Svc.BeginRegistration())
	regGroup.POST("/register/finish", h.Deps.Svc.FinishRegistration())
}
