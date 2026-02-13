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

	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	handlerdeps "github.com/croessner/nauthilus/server/handler/deps"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
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
	if h.deps.Cfg.GetServer().GetEndpoint().IsAuthBasicDisabled() {
		ctx.AbortWithStatus(http.StatusNotFound)

		return
	}

	// Minimal custom span analogous to JSON handler
	tr := monittrace.New("nauthilus/rest")
	spanCtx, sp := tr.Start(ctx.Request.Context(), "rest.auth_basic")
	defer sp.End()

	// Propagate tracing context
	ctx.Request = ctx.Request.WithContext(spanCtx)

	h.process(ctx)
}

func (h *Handler) json(ctx *gin.Context) {
	if h.deps.Cfg.GetServer().GetEndpoint().IsAuthJSONDisabled() {
		ctx.AbortWithStatus(http.StatusNotFound)

		return
	}

	// Minimal custom span to verify end-to-end tracing for the JSON auth path.
	// This span appears as a child of the otelgin server span when tracing is enabled.
	tr := monittrace.New("nauthilus/rest")

	spanCtx, sp := tr.Start(ctx.Request.Context(), "rest.auth_json")
	defer sp.End()

	// Propagate the new context down the call chain so child operations
	// (e.g., Redis, outbound HTTP) attach under this span when possible.
	ctx.Request = ctx.Request.WithContext(spanCtx)

	h.process(ctx)
}

func (h *Handler) header(ctx *gin.Context) {
	if h.deps.Cfg.GetServer().GetEndpoint().IsAuthHeaderDisabled() {
		ctx.AbortWithStatus(http.StatusNotFound)

		return
	}

	// Minimal custom span analogous to JSON handler
	tr := monittrace.New("nauthilus/rest")
	spanCtx, sp := tr.Start(ctx.Request.Context(), "rest.auth_header")
	defer sp.End()

	// Propagate tracing context
	ctx.Request = ctx.Request.WithContext(spanCtx)

	h.process(ctx)
}

func (h *Handler) nginx(ctx *gin.Context) {
	if h.deps.Cfg.GetServer().GetEndpoint().IsAuthNginxDisabled() {
		ctx.AbortWithStatus(http.StatusNotFound)

		return
	}

	// Minimal custom span analogous to JSON handler
	tr := monittrace.New("nauthilus/rest")
	spanCtx, sp := tr.Start(ctx.Request.Context(), "rest.auth_nginx")
	defer sp.End()

	// Propagate tracing context
	ctx.Request = ctx.Request.WithContext(spanCtx)

	h.process(ctx)
}

func (h *Handler) saslAuthd(ctx *gin.Context) {
	if h.deps.Cfg.GetServer().GetEndpoint().IsAuthSASLAuthdDisabled() {
		ctx.AbortWithStatus(http.StatusNotFound)

		return
	}

	// Minimal custom span for SASL/Authd path
	tr := monittrace.New("nauthilus/rest")
	spanCtx, sp := tr.Start(ctx.Request.Context(), "rest.auth_saslauthd")
	defer sp.End()

	// Propagate tracing context
	ctx.Request = ctx.Request.WithContext(spanCtx)

	// Same pre-processing flow but use the specific SASL handler
	auth := h.newAuthState(ctx)
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
	auth := h.newAuthState(ctx)

	if auth == nil {
		ctx.AbortWithStatus(http.StatusBadRequest)

		return
	}

	if reject := auth.PreproccessAuthRequest(ctx); reject {
		return
	}

	auth.HandleAuthentication(ctx)
}

func (h *Handler) newAuthState(ctx *gin.Context) core.State {
	return core.NewAuthStateWithSetupWithDeps(ctx, core.AuthDeps{
		Cfg:          h.deps.Cfg,
		Env:          h.deps.Env,
		Logger:       h.deps.Logger,
		Redis:        h.deps.Redis,
		AccountCache: h.deps.AccountCache,
		Channel:      h.deps.Channel,
	})
}
