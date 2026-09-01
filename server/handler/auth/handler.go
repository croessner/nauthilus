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
	"context"
	stderrors "errors"
	"net/http"

	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	handlerdeps "github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/log/level"
	monittrace "github.com/croessner/nauthilus/v4/server/monitoring/trace"
	"github.com/croessner/nauthilus/v4/server/util"
	"github.com/gin-gonic/gin"
)

// Handler registers authentication-related routes.
type Handler struct {
	deps        *handlerdeps.Deps
	application core.AuthApplicationService
}

// New constructs the auth handler with injected dependencies.
func New(deps *handlerdeps.Deps) *Handler {
	if deps == nil {
		return &Handler{}
	}

	return NewWithApplicationService(deps, deps.AuthApplication)
}

// NewWithApplicationService constructs an auth handler with an explicit application boundary.
func NewWithApplicationService(deps *handlerdeps.Deps, application core.AuthApplicationService) *Handler {
	return &Handler{deps: deps, application: application}
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
	h.handleWithTraceAndProcess(ctx, disabled, spanName, h.process)
}

// handleWithTraceAndProcess runs one transport processor within the established request trace scope.
func (h *Handler) handleWithTraceAndProcess(
	ctx *gin.Context,
	disabled func() bool,
	spanName string,
	process gin.HandlerFunc,
) {
	if disabled() {
		ctx.AbortWithStatus(http.StatusNotFound)

		return
	}

	tr := monittrace.New("nauthilus/rest")

	spanCtx, sp := tr.Start(ctx.Request.Context(), spanName)
	defer sp.End()

	requestScope := util.NewHTTPRequestContextScope(spanCtx, &ctx.Request)

	defer requestScope.Restore()

	process(ctx)
}

// process converts an HTTP request, dispatches one application operation, and renders its outcome.
func (h *Handler) process(ctx *gin.Context) {
	if h == nil || h.deps == nil || h.application == nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	input, ok := newHTTPAuthInputBuilder(h.deps).Build(ctx)
	if !ok {
		return
	}

	ctx.Set(definitions.CtxAuthProtocolKey, input.Context.Protocol)
	applicationContext := h.applicationContext(ctx)
	renderer := core.NewHTTPAuthResponseRenderer(h.responseDeps())

	if input.Mode == core.AuthModeListAccounts {
		outcome, err := h.application.ListAccounts(applicationContext, input)
		if err != nil {
			h.renderApplicationError(ctx, renderer, input, err)

			return
		}

		if outcome == nil {
			ctx.AbortWithStatus(http.StatusInternalServerError)

			return
		}

		renderer.RenderListAccounts(ctx, input, outcome)

		return
	}

	var (
		outcome *core.AuthOutcome
		err     error
	)

	if input.Mode == core.AuthModeLookupIdentity {
		outcome, err = h.application.LookupIdentity(applicationContext, input)
	} else {
		outcome, err = h.application.Authenticate(applicationContext, input)
	}

	if err != nil {
		h.renderApplicationError(ctx, renderer, input, err)

		return
	}

	h.renderAuthOutcome(ctx, renderer, input, outcome)
}

// applicationContext carries validated bearer claims into the transport-neutral scope check.
func (h *Handler) applicationContext(ctx *gin.Context) context.Context {
	applicationContext := ctx.Request.Context()
	if claims, exists := ctx.Get(definitions.CtxOIDCClaimsKey); exists {
		applicationContext = core.ContextWithOIDCClaims(applicationContext, claims)
	}

	return applicationContext
}

// responseDeps resolves the request-bound configuration used by the pure HTTP renderer.
func (h *Handler) responseDeps() core.ResponseDeps {
	authDeps := h.deps.Auth()

	return core.ResponseDeps{
		Cfg:       authDeps.Cfg,
		Env:       authDeps.Env,
		Logger:    authDeps.Logger,
		Resolver:  h.deps.MessageResolver,
		WaitDelay: authDeps.HostServices.WaitDelay,
	}
}

// renderApplicationError maps typed application failures without invoking domain logic in the handler.
func (h *Handler) renderApplicationError(
	ctx *gin.Context,
	renderer *core.HTTPAuthResponseRenderer,
	input core.AuthInput,
	err error,
) {
	var preprocessError *core.AuthPreprocessRejectedError
	if stderrors.As(err, &preprocessError) && preprocessError.Outcome != nil {
		h.renderAuthOutcome(ctx, renderer, input, preprocessError.Outcome)

		return
	}

	var inputError *core.AuthInputError
	if stderrors.As(err, &inputError) {
		ctx.AbortWithStatus(http.StatusBadRequest)

		return
	}

	var permissionError *core.AuthPermissionDeniedError
	if stderrors.As(err, &permissionError) {
		ctx.AbortWithStatus(http.StatusForbidden)

		return
	}

	h.logInternalApplicationError(ctx, err)

	ctx.AbortWithStatus(http.StatusInternalServerError)
}

// logInternalApplicationError preserves the exact fail-closed cause and request correlation.
func (h *Handler) logInternalApplicationError(ctx *gin.Context, err error) {
	if h == nil || h.deps == nil || h.deps.Logger == nil || ctx == nil || err == nil {
		return
	}

	level.Error(h.deps.Logger).Log(
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "Authentication application failed",
		definitions.LogKeyError, err,
	)
}

// renderAuthOutcome publishes terminal metric metadata before rendering the HTTP response.
func (h *Handler) renderAuthOutcome(
	ctx *gin.Context,
	renderer *core.HTTPAuthResponseRenderer,
	input core.AuthInput,
	outcome *core.AuthOutcome,
) {
	if outcome == nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	ctx.Set(definitions.CtxAuthOutcomeKey, string(outcome.Decision))

	if outcome.Protocol != "" {
		ctx.Set(definitions.CtxAuthProtocolKey, outcome.Protocol)
	}

	renderer.RenderAuth(ctx, input, projectAuthOutcomeForHTTP(input, outcome))
}

// projectAuthOutcomeForHTTP applies surface-specific representation rules without changing the application decision.
func projectAuthOutcomeForHTTP(input core.AuthInput, outcome *core.AuthOutcome) *core.AuthOutcome {
	projected := *outcome

	if input.Service == definitions.ServNginx {
		projected.HTTPStatus = http.StatusOK
	}

	if projected.Decision == core.AuthDecisionOK &&
		(input.Service == definitions.ServJSON || input.Service == definitions.ServCBOR) &&
		projected.Attributes == nil {
		projected.Attributes = make(bktype.AttributeMapping)
	}

	return &projected
}
