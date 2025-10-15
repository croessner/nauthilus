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

//go:build hydra
// +build hydra

package twofa

import (
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/common"
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

func (h *Handler) Register(router gin.IRouter) {
	if !tags.Register2FA {
		return
	}

	// Register 2FA routes under TwoFAv1Root
	group := router.Group(definitions.TwoFAv1Root)

	// This page handles the user login request to do a two-factor authentication
	twoFactorGroup := common.RouterGroup(viper.GetString("login_2fa_page"), group, h.Store, h.Deps.Svc.LoginGET2FAHandler(), h.Deps.Svc.LoginPOST2FAHandler())

	twoFactorGroup.GET("/home", h.Deps.Svc.Register2FAHomeHandler())
	twoFactorGroup.GET("/home/:languageTag", h.Deps.Svc.Register2FAHomeHandler())

	// This page handles the TOTP registration
	common.RouterGroup(viper.GetString("totp_page"), group, h.Store, h.Deps.Svc.RegisterTotpGETHandler(), h.Deps.Svc.RegisterTotpPOSTHandler())
}
