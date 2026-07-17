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

	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	handlerdeps "github.com/croessner/nauthilus/v3/server/handler/deps"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
)

// Handler registers authentication-related routes.
type Handler struct {
	deps *handlerdeps.Deps
}

// New constructs the auth handler with injected dependencies.
func New(deps *handlerdeps.Deps) *Handler {
	if deps == nil {
		return &Handler{}
	}

	return &Handler{deps: deps}
}

// Register provides the exported Register method.
func (h *Handler) Register(router gin.IRouter) {
	authGroup := router.Group("/" + definitions.CatAuth)

	withService := func(service string, next gin.HandlerFunc) gin.HandlerFunc {
		return func(ctx *gin.Context) {
			ctx.Set(definitions.CtxCategoryKey, definitions.CatAuth)
			ctx.Set(definitions.CtxServiceKey, service)

			next(ctx)
		}
	}

	h.registerBasicEndpoint(authGroup, withService)
	authGroup.GET("/"+definitions.ServJSON, withService(definitions.ServJSON, h.json))
	authGroup.POST("/"+definitions.ServJSON, withService(definitions.ServJSON, h.json))
	authGroup.GET("/"+definitions.ServCBOR, withService(definitions.ServCBOR, h.cbor))
	authGroup.POST("/"+definitions.ServCBOR, withService(definitions.ServCBOR, h.cbor))
	authGroup.GET("/"+definitions.ServHeader, withService(definitions.ServHeader, h.header))
	authGroup.POST("/"+definitions.ServHeader, withService(definitions.ServHeader, h.header))
	authGroup.GET("/"+definitions.ServNginx, withService(definitions.ServNginx, h.nginx))
	authGroup.POST("/"+definitions.ServNginx, withService(definitions.ServNginx, h.nginx))
}

func (h *Handler) json(ctx *gin.Context) {
	h.handleWithTrace(ctx, h.deps.Cfg.GetServer().GetEndpoint().IsAuthJSONDisabled, "rest.auth_json")
}

func (h *Handler) cbor(ctx *gin.Context) {
	h.handleWithTrace(ctx, h.deps.Cfg.GetServer().GetEndpoint().IsAuthCBORDisabled, "rest.auth_cbor")
}

func (h *Handler) header(ctx *gin.Context) {
	h.handleWithTrace(ctx, h.deps.Cfg.GetServer().GetEndpoint().IsAuthHeaderDisabled, "rest.auth_header")
}

func (h *Handler) nginx(ctx *gin.Context) {
	h.handleWithTrace(ctx, h.deps.Cfg.GetServer().GetEndpoint().IsAuthNginxDisabled, "rest.auth_nginx")
}

// handleWithTrace runs an auth endpoint with the endpoint-specific disabled check and tracing span.
func (h *Handler) handleWithTrace(ctx *gin.Context, disabled func() bool, spanName string) {
	if disabled() {
		ctx.AbortWithStatus(http.StatusNotFound)

		return
	}

	tr := monittrace.New("nauthilus/rest")

	spanCtx, sp := tr.Start(ctx.Request.Context(), spanName)
	defer sp.End()

	requestScope := util.NewHTTPRequestContextScope(spanCtx, &ctx.Request)

	defer requestScope.Restore()

	h.process(ctx)
}

func (h *Handler) process(ctx *gin.Context) {
	auth := h.newAuthState(ctx)

	if auth == nil {
		ctx.AbortWithStatus(http.StatusBadRequest)

		return
	}

	ctx.Set(definitions.CtxAuthProtocolKey, auth.GetProtocol().Get())

	if reject := auth.PreproccessAuthRequest(ctx); reject {
		return
	}

	auth.HandleAuthentication(ctx)
}

func (h *Handler) newAuthState(ctx *gin.Context) core.State {
	return core.NewAuthStateWithSetupWithDeps(ctx, h.deps.Auth())
}
