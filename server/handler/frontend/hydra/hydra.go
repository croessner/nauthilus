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

package hydra

import (
	"path/filepath"
	"strings"

	"github.com/croessner/nauthilus/server/handler/common"
	"github.com/croessner/nauthilus/server/handler/deps"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

// Handler registers the Hydra-related frontend endpoints (login, device, consent, logout)
// using the same middleware chain and paths as before.
type Handler struct {
	Store sessions.Store
	Deps  *deps.Deps
}

func New(store sessions.Store, d *deps.Deps) *Handler {
	return &Handler{Store: store, Deps: d}
}

func (h *Handler) Register(router gin.IRouter) {
	staticPath := filepath.Clean(h.Deps.Cfg.GetServer().Frontend.GetHTMLStaticContentPath())
	assetBase := staticPath

	if filepath.Base(staticPath) == "templates" {
		assetBase = filepath.Dir(staticPath)
	}

	// Static assets (favicon, css, js, img, fonts) for Hydra frontend
	g := router.Group("/")

	g.StaticFile("/favicon.ico", filepath.Join(assetBase, "img", "favicon.ico"))
	g.Static("/static/css", filepath.Join(assetBase, "css"))
	g.Static("/static/js", filepath.Join(assetBase, "js"))
	g.Static("/static/img", filepath.Join(assetBase, "img"))
	g.Static("/static/fonts", filepath.Join(assetBase, "fonts"))

	// Login page
	common.RouterGroup(h.Deps.Cfg, h.Deps.Logger, h.Deps.Redis, h.Deps.AccountCache, viper.GetString("login_page"), router, h.Store, h.Deps.Svc.LoginGETHandler(), h.Deps.Svc.LoginPOSTHandler())

	// Device/U2F/FIDO2 login page
	common.RouterGroup(h.Deps.Cfg, h.Deps.Logger, h.Deps.Redis, h.Deps.AccountCache, viper.GetString("device_page"), router, h.Store, h.Deps.Svc.DeviceGETHandler(), h.Deps.Svc.DevicePOSTHandler())

	// Consent page
	common.RouterGroup(h.Deps.Cfg, h.Deps.Logger, h.Deps.Redis, h.Deps.AccountCache, viper.GetString("consent_page"), router, h.Store, h.Deps.Svc.ConsentGETHandler(), h.Deps.Svc.ConsentPOSTHandler())

	// Logout page
	common.RouterGroup(h.Deps.Cfg, h.Deps.Logger, h.Deps.Redis, h.Deps.AccountCache, viper.GetString("logout_page"), router, h.Store, h.Deps.Svc.LogoutGETHandler(), h.Deps.Svc.LogoutPOSTHandler())
}
