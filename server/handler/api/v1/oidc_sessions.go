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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"time"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/idp"
	"github.com/croessner/nauthilus/v3/server/middleware/oidcbearer"
	"github.com/gin-gonic/gin"
)

// OIDCSessionStore is the narrow session-management storage contract used by
// the management API boundary.
type OIDCSessionStore interface {
	ListUserSessions(ctx context.Context, userID string) (map[string]*idp.OIDCSession, error)
	GetAccessToken(ctx context.Context, token string) (*idp.OIDCSession, error)
	DeleteAccessToken(ctx context.Context, token string) error
	FlushUserTokens(ctx context.Context, userID string) error
}

// OIDCSessionsAPI handles backchannel API requests for OIDC sessions.
type OIDCSessionsAPI struct {
	deps    *deps.Deps
	storage OIDCSessionStore
}

// NewOIDCSessionsAPI creates a new OIDCSessionsAPI.
func NewOIDCSessionsAPI(d *deps.Deps, storage OIDCSessionStore) *OIDCSessionsAPI {
	return &OIDCSessionsAPI{
		deps:    d,
		storage: storage,
	}
}

// Register registers the API routes.
func (a *OIDCSessionsAPI) Register(router gin.IRouter) {
	v1 := router.Group(
		"/oidc",
		oidcbearer.RequireAnyScope(definitions.ScopeSecurity, definitions.ScopeAdmin),
	)
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
		ctx.JSON(http.StatusBadRequest, gin.H{apiResponseKeyError: apiResponseUserIDRequired})
		return
	}

	if !a.requireStorage(ctx) {
		return
	}

	sessions, err := a.storage.ListUserSessions(ctx.Request.Context(), userID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{apiResponseKeyError: err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, newOIDCSessionListResponse(sessions))
}

// DeleteAllSessions deletes all OIDC sessions for a user.
func (a *OIDCSessionsAPI) DeleteAllSessions(ctx *gin.Context) {
	userID := ctx.Param("user_id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{apiResponseKeyError: apiResponseUserIDRequired})
		return
	}

	if !a.requireStorage(ctx) {
		return
	}

	if err := a.storage.FlushUserTokens(ctx.Request.Context(), userID); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{apiResponseKeyError: err.Error()})
		return
	}

	ctx.Status(http.StatusNoContent)
}

// DeleteSession deletes a specific OIDC session for a user.
func (a *OIDCSessionsAPI) DeleteSession(ctx *gin.Context) {
	userID := ctx.Param("user_id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{apiResponseKeyError: apiResponseUserIDRequired})
		return
	}

	token := ctx.Param("token")
	if token == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{apiResponseKeyError: "token is required"})
		return
	}

	if !a.requireStorage(ctx) {
		return
	}

	session, err := a.storage.GetAccessToken(ctx.Request.Context(), token)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{apiResponseKeyError: err.Error()})
		return
	}

	if session == nil || session.UserID != userID {
		ctx.JSON(http.StatusForbidden, gin.H{apiResponseKeyError: "session does not belong to user"})
		return
	}

	if err := a.storage.DeleteAccessToken(ctx.Request.Context(), token); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{apiResponseKeyError: err.Error()})
		return
	}

	ctx.Status(http.StatusNoContent)
}

type oidcSessionListResponse struct {
	Sessions []oidcSessionSummary `json:"sessions"`
}

type oidcSessionSummary struct {
	ID           string    `json:"id"`
	ClientID     string    `json:"client_id"`
	UserID       string    `json:"user_id"`
	Username     string    `json:"username,omitempty"`
	DisplayName  string    `json:"display_name,omitempty"`
	RedirectURI  string    `json:"redirect_uri,omitempty"`
	MFAMethod    string    `json:"mfa_method,omitempty"`
	Scopes       []string  `json:"scopes,omitempty"`
	AuthTime     time.Time `json:"auth_time"`
	MFACompleted bool      `json:"mfa_completed,omitempty"`
}

// requireStorage aborts management requests when no token storage is available.
func (a *OIDCSessionsAPI) requireStorage(ctx *gin.Context) bool {
	if a.storage != nil {
		return true
	}

	ctx.JSON(http.StatusInternalServerError, gin.H{apiResponseKeyError: "OIDC token storage is unavailable"})

	return false
}

// newOIDCSessionListResponse builds a token-safe response from stored sessions.
func newOIDCSessionListResponse(sessions map[string]*idp.OIDCSession) oidcSessionListResponse {
	items := make([]oidcSessionSummary, 0, len(sessions))

	for token, session := range sessions {
		if session == nil {
			continue
		}

		items = append(items, newOIDCSessionSummary(token, session))
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].ID < items[j].ID
	})

	return oidcSessionListResponse{Sessions: items}
}

// newOIDCSessionSummary copies non-secret session metadata into the API DTO.
func newOIDCSessionSummary(token string, session *idp.OIDCSession) oidcSessionSummary {
	return oidcSessionSummary{
		ID:           oidcSessionID(token),
		ClientID:     session.ClientID,
		UserID:       session.UserID,
		Username:     session.Username,
		DisplayName:  session.DisplayName,
		Scopes:       append([]string(nil), session.Scopes...),
		RedirectURI:  session.RedirectURI,
		AuthTime:     session.AuthTime,
		MFACompleted: session.MFACompleted,
		MFAMethod:    session.MFAMethod,
	}
}

// oidcSessionID derives a stable non-secret identifier from the stored token.
func oidcSessionID(token string) string {
	sum := sha256.Sum256([]byte(token))

	return hex.EncodeToString(sum[:])
}
