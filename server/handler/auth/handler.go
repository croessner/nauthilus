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

package auth

import (
	"net/http"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	cfg config.File
}

func New(cfg config.File) *Handler {
	return &Handler{cfg: cfg}
}

func (h *Handler) Register(router gin.IRouter) {
	authGroup := router.Group("/" + definitions.CatAuth)

	withService := func(service string, next gin.HandlerFunc) gin.HandlerFunc {
		return func(ctx *gin.Context) {
			ctx.Set(definitions.CtxCategoryKey, definitions.CatAuth)
			ctx.Set(definitions.CtxServiceKey, service)

			next(ctx)
		}
	}

	authGroup.GET("/"+definitions.ServBasic, withService(definitions.ServBasic, h.basic))
	authGroup.GET("/"+definitions.ServJSON, withService(definitions.ServJSON, h.json))
	authGroup.POST("/"+definitions.ServJSON, withService(definitions.ServJSON, h.json))
	authGroup.GET("/"+definitions.ServHeader, withService(definitions.ServHeader, h.header))
	authGroup.POST("/"+definitions.ServHeader, withService(definitions.ServHeader, h.header))
	authGroup.GET("/"+definitions.ServNginx, withService(definitions.ServNginx, h.nginx))
	authGroup.POST("/"+definitions.ServNginx, withService(definitions.ServNginx, h.nginx))
	authGroup.POST("/"+definitions.ServSaslauthd, withService(definitions.ServSaslauthd, h.saslAuthd))
}

func (h *Handler) basic(ctx *gin.Context) {
	if h.cfg.GetServer().GetEndpoint().IsAuthBasicDisabled() {
		ctx.AbortWithStatus(http.StatusNotFound)

		return
	}

	h.process(ctx)
}

func (h *Handler) json(ctx *gin.Context) {
	if h.cfg.GetServer().GetEndpoint().IsAuthJSONDisabled() {
		ctx.AbortWithStatus(http.StatusNotFound)

		return
	}

	h.process(ctx)
}

func (h *Handler) header(ctx *gin.Context) {
	if h.cfg.GetServer().GetEndpoint().IsAuthHeaderDisabled() {
		ctx.AbortWithStatus(http.StatusNotFound)

		return
	}

	h.process(ctx)
}

func (h *Handler) nginx(ctx *gin.Context) {
	if h.cfg.GetServer().GetEndpoint().IsAuthNginxDisabled() {
		ctx.AbortWithStatus(http.StatusNotFound)

		return
	}

	h.process(ctx)
}

func (h *Handler) saslAuthd(ctx *gin.Context) {
	if h.cfg.GetServer().GetEndpoint().IsAuthSASLAuthdDisabled() {
		ctx.AbortWithStatus(http.StatusNotFound)

		return
	}

	// Same pre-processing flow but use the specific SASL handler
	auth := core.NewAuthStateWithSetup(ctx)
	if auth == nil {
		ctx.AbortWithStatus(http.StatusBadRequest)

		return
	}

	if reject := auth.PreproccessAuthRequest(ctx); reject { //nolint:gosimple // match existing signature
		return
	}

	auth.ProcessAuthentication(ctx)
}

func (h *Handler) process(ctx *gin.Context) {
	auth := core.NewAuthStateWithSetup(ctx)

	if auth == nil {
		ctx.AbortWithStatus(http.StatusBadRequest)

		return
	}

	if reject := auth.PreproccessAuthRequest(ctx); reject {
		return
	}

	auth.HandleAuthentication(ctx)
}
