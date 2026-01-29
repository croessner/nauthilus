// Copyright (C) 2025 Christian Rößner
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

package v1

import (
	"net/http"

	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/idp"
	"github.com/gin-gonic/gin"
)

// OIDCSessionsAPI handles backchannel API requests for OIDC sessions.
type OIDCSessionsAPI struct {
	deps    *deps.Deps
	storage *idp.RedisTokenStorage
}

// NewOIDCSessionsAPI creates a new OIDCSessionsAPI.
func NewOIDCSessionsAPI(d *deps.Deps, storage *idp.RedisTokenStorage) *OIDCSessionsAPI {
	return &OIDCSessionsAPI{
		deps:    d,
		storage: storage,
	}
}

// Register registers the API routes.
func (a *OIDCSessionsAPI) Register(router gin.IRouter) {
	v1 := router.Group("/v1/oidc")
	{
		v1.GET("/sessions/:user_id", a.ListSessions)
		v1.DELETE("/sessions/:user_id", a.DeleteAllSessions)
		v1.DELETE("/sessions/:user_id/:token", a.DeleteSession)
	}
}

// ListSessions returns all active OIDC sessions for a user.
func (a *OIDCSessionsAPI) ListSessions(ctx *gin.Context) {
	userID := ctx.Param("user_id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	sessions, err := a.storage.ListUserSessions(ctx.Request.Context(), userID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, sessions)
}

// DeleteAllSessions deletes all OIDC sessions for a user.
func (a *OIDCSessionsAPI) DeleteAllSessions(ctx *gin.Context) {
	userID := ctx.Param("user_id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	// Also delete refresh tokens as they are part of the "session" in a broader sense
	err := a.storage.DeleteUserRefreshTokens(ctx.Request.Context(), userID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	sessions, err := a.storage.ListUserSessions(ctx.Request.Context(), userID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	for token := range sessions {
		_ = a.storage.DeleteAccessToken(ctx.Request.Context(), token)
	}

	ctx.Status(http.StatusNoContent)
}

// DeleteSession deletes a specific OIDC session for a user.
func (a *OIDCSessionsAPI) DeleteSession(ctx *gin.Context) {
	token := ctx.Param("token")
	if token == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
		return
	}

	err := a.storage.DeleteAccessToken(ctx.Request.Context(), token)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.Status(http.StatusNoContent)
}
