// Copyright (C) 2026 Christian Rößner
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

// Package support is the management HTTP adapter of the read-only support operations (historical authentication
// diagnosis and operational diagnostics). It only translates the transport: bearer facts become a verified
// credential and JSON bodies become operation arguments. The operations, their decoding, authorization, limits, and
// rendered bytes come from server/supportapi, which the MCP endpoint uses as well.
package support

import (
	"context"
	"io"
	"log/slog"
	"strings"

	"github.com/croessner/nauthilus/v4/server/definitions"
	handlerdeps "github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/middleware/oidcbearer"
	"github.com/croessner/nauthilus/v4/server/supportaccess"
	"github.com/croessner/nauthilus/v4/server/supportapi"
	"github.com/gin-gonic/gin"
)

const (
	// maxBodyBytes bounds one request body.
	maxBodyBytes = 16 << 10

	jsonContentType = "application/json; charset=utf-8"
)

// Handler registers the support routes.
type Handler struct {
	logger   *slog.Logger
	services supportapi.Services
}

// New creates the handler; a nil service answers NOT_CONFIGURED for its operations.
func New(deps *handlerdeps.Deps) *Handler {
	return &Handler{logger: deps.Logger,
		services: supportapi.Services{History: deps.SupportHistory, Operations: deps.SupportOperations}}
}

// Register mounts one POST route per support operation below the authenticated /api/v1 group.
func (h *Handler) Register(router gin.IRouter) {
	for _, operation := range supportapi.Operations() {
		router.POST(operation.HTTPPath, noStore, h.handle(operation))
	}
}

// noStore forbids caching of every support response, including errors.
func noStore(ctx *gin.Context) {
	ctx.Header("Cache-Control", "no-store")
	ctx.Next()
}

// handle answers one operation: transport checks, then the shared execution and rendering.
func (h *Handler) handle(operation supportapi.Operation) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		raw, ok := readBody(ctx)
		if !ok {
			h.write(ctx, supportapi.InvalidRequest(operation))

			return
		}

		h.write(ctx, h.services.Execute(ctx.Request.Context(), operation, verifiedCredential(ctx), raw))
	}
}

// verifiedCredential turns the bearer claims the backchannel middleware validated into a verified service
// credential carrying only support scopes. Basic credentials and unauthenticated requests yield no credential.
func verifiedCredential(ctx *gin.Context) supportaccess.VerifiedCredential {
	claims := oidcbearer.GetClaimsFromContext(ctx)
	if claims == nil {
		return supportaccess.VerifiedCredential{}
	}

	credential := supportaccess.VerifiedCredential{Method: supportaccess.CredentialOIDCBearer}
	credential.ClientID, _ = claims[definitions.ClaimClientID].(string)
	credential.Subject, _ = claims["sub"].(string)

	for _, scope := range supportapi.SupportScopes() {
		if oidcbearer.HasScope(claims, scope) {
			credential.Scopes = append(credential.Scopes, scope)
		}
	}

	return credential
}

// readBody reads one bounded JSON body; query parameters are refused so filters never reach access logs.
func readBody(ctx *gin.Context) ([]byte, bool) {
	if ctx.Request.URL.RawQuery != "" ||
		!strings.HasPrefix(strings.ToLower(ctx.GetHeader("Content-Type")), "application/json") {
		return nil, false
	}

	raw, err := io.ReadAll(io.LimitReader(ctx.Request.Body, maxBodyBytes+1))
	if err != nil || len(raw) > maxBodyBytes {
		return nil, false
	}

	return raw, true
}

// write renders the shared response bytes; internal causes are logged, never returned.
func (h *Handler) write(ctx *gin.Context, response supportapi.Response) {
	if cause := response.Cause(); cause != nil && h.logger != nil {
		h.logger.LogAttrs(context.WithoutCancel(ctx.Request.Context()), slog.LevelWarn, "support request failed",
			slog.String(definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey)),
			slog.String("code", string(response.Code)), slog.String("cause", cause.Error()))
	}

	if response.IsError() {
		ctx.Abort()
	}

	ctx.Data(response.Status, jsonContentType, response.Body)
}
