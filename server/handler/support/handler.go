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

// Package support is the HTTP adapter of the historical support diagnosis. It only translates the transport: bearer
// facts become a verified credential, JSON bodies become service requests, and service DTOs and error codes become
// responses. All diagnosis, authorization, limits, and projection live in server/supporthistory.
package support

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/croessner/nauthilus/v4/server/definitions"
	handlerdeps "github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/middleware/oidcbearer"
	"github.com/croessner/nauthilus/v4/server/supporthistory"
	"github.com/gin-gonic/gin"
)

const (
	// maxBodyBytes bounds one request body.
	maxBodyBytes = 16 << 10

	pathAttemptSearch = "/authentication-attempts/search"
	pathAttemptDetail = "/authentication-attempts/detail"
	pathBanSearch     = "/bruteforce-bans/search"
)

// errorStatus maps stable service codes to HTTP statuses.
var errorStatus = map[supporthistory.ErrorCode]int{
	supporthistory.CodeInvalidRequest:    http.StatusBadRequest,
	supporthistory.CodeWindowTooLarge:    http.StatusBadRequest,
	supporthistory.CodeInvalidCursor:     http.StatusBadRequest,
	supporthistory.CodeInvalidAttemptID:  http.StatusBadRequest,
	supporthistory.CodeForbidden:         http.StatusForbidden,
	supporthistory.CodeQueryTooBroad:     http.StatusUnprocessableEntity,
	supporthistory.CodeBusy:              http.StatusTooManyRequests,
	supporthistory.CodeNotConfigured:     http.StatusServiceUnavailable,
	supporthistory.CodeSourceUnavailable: http.StatusServiceUnavailable,
	supporthistory.CodeReaderUnsafe:      http.StatusServiceUnavailable,
	supporthistory.CodeTimeout:           http.StatusServiceUnavailable,
	supporthistory.CodeInternal:          http.StatusInternalServerError,
}

// Handler registers the support history routes.
type Handler struct {
	service *supporthistory.Service
	logger  *slog.Logger
}

// New creates the handler; a nil service answers HISTORY_NOT_CONFIGURED.
func New(deps *handlerdeps.Deps) *Handler {
	return &Handler{service: deps.SupportHistory, logger: deps.Logger}
}

// Register mounts the routes below the authenticated /api/v1 group.
func (h *Handler) Register(router gin.IRouter) {
	group := router.Group("/support", noStore)

	group.POST(pathAttemptSearch, h.searchAttempts)
	group.POST(pathAttemptDetail, h.attemptDetail)
	group.POST(pathBanSearch, h.searchBans)
}

// noStore forbids caching of every support history response, including errors.
func noStore(ctx *gin.Context) {
	ctx.Header("Cache-Control", "no-store")
	ctx.Next()
}

// verifiedCaller turns the bearer claims the backchannel middleware validated into a service caller. Basic
// credentials and unauthenticated requests yield a caller without permissions.
func verifiedCaller(ctx *gin.Context) supporthistory.Caller {
	claims := oidcbearer.GetClaimsFromContext(ctx)
	if claims == nil {
		return supporthistory.Caller{}
	}

	credential := supporthistory.VerifiedCredential{Method: supporthistory.CredentialOIDCBearer}
	credential.ClientID, _ = claims[definitions.ClaimClientID].(string)
	credential.Subject, _ = claims["sub"].(string)

	for _, scope := range []string{definitions.ScopeHistoryRead, definitions.ScopeHistoryDetail} {
		if oidcbearer.HasScope(claims, scope) {
			credential.Scopes = append(credential.Scopes, scope)
		}
	}

	return supporthistory.NewCaller(credential)
}

// decodeBody reads one strict JSON object; query parameters are refused so filters never reach access logs.
func decodeBody(ctx *gin.Context, target any) bool {
	if ctx.Request.URL.RawQuery != "" ||
		!strings.HasPrefix(strings.ToLower(ctx.GetHeader("Content-Type")), "application/json") {
		writeError(ctx, supporthistory.CodeInvalidRequest)

		return false
	}

	raw, err := io.ReadAll(io.LimitReader(ctx.Request.Body, maxBodyBytes+1))
	if err != nil || len(raw) > maxBodyBytes {
		writeError(ctx, supporthistory.CodeInvalidRequest)

		return false
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()

	if err = decoder.Decode(target); err != nil || decoder.More() {
		writeError(ctx, supporthistory.CodeInvalidRequest)

		return false
	}

	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		writeError(ctx, supporthistory.CodeInvalidRequest)

		return false
	}

	return true
}

// errorBody is the fixed error envelope.
type errorBody struct {
	Error         errorDetail `json:"error"`
	SchemaVersion string      `json:"schema_version"`
}

// errorDetail carries the stable code and its fixed message.
type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// writeError renders a fixed error code.
func writeError(ctx *gin.Context, code supporthistory.ErrorCode) {
	serviceErr := &supporthistory.Error{Code: code}
	status, ok := errorStatus[code]

	if !ok {
		status = http.StatusInternalServerError
	}

	ctx.AbortWithStatusJSON(status, errorBody{SchemaVersion: supporthistory.SchemaVersion,
		Error: errorDetail{Code: string(code), Message: serviceErr.Message()}})
}

// respond writes a processed answer or maps a service error; internal causes are logged, never returned.
func (h *Handler) respond(ctx *gin.Context, result any, err error) {
	if err == nil {
		ctx.JSON(http.StatusOK, result)

		return
	}

	serviceErr := supporthistory.AsError(err)
	if cause := errors.Unwrap(serviceErr); cause != nil && h.logger != nil {
		h.logger.LogAttrs(context.WithoutCancel(ctx.Request.Context()), slog.LevelWarn, "support history request failed",
			slog.String(definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey)),
			slog.String("code", string(serviceErr.Code)), slog.String("cause", cause.Error()))
	}

	writeError(ctx, serviceErr.Code)
}

// searchAttempts handles POST /api/v1/support/authentication-attempts/search.
func (h *Handler) searchAttempts(ctx *gin.Context) {
	var request supporthistory.AttemptSearchRequest
	if !decodeBody(ctx, &request) {
		return
	}

	result, err := h.service.SearchAttempts(ctx.Request.Context(), verifiedCaller(ctx), request)
	h.respond(ctx, result, err)
}

// attemptDetail handles POST /api/v1/support/authentication-attempts/detail.
func (h *Handler) attemptDetail(ctx *gin.Context) {
	var request supporthistory.AttemptDetailRequest
	if !decodeBody(ctx, &request) {
		return
	}

	result, err := h.service.GetAttempt(ctx.Request.Context(), verifiedCaller(ctx), request)
	h.respond(ctx, result, err)
}

// searchBans handles POST /api/v1/support/bruteforce-bans/search.
func (h *Handler) searchBans(ctx *gin.Context) {
	var request supporthistory.BanSearchRequest
	if !decodeBody(ctx, &request) {
		return
	}

	result, err := h.service.SearchBans(ctx.Request.Context(), verifiedCaller(ctx), request)
	h.respond(ctx, result, err)
}
