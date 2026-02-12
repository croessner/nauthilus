// Copyright (C) 2024 Christian Roessner
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

package mfa_backchannel

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	handlerdeps "github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/model/mfa"
	"github.com/gin-gonic/gin"
)

// Handler exposes MFA and WebAuthn backchannel endpoints for the Lua proxy backend.
// These endpoints are protected by the backchannel auth middleware (Basic/JWT).
type Handler struct {
	deps *handlerdeps.Deps
}

// New constructs the backchannel handler with injected dependencies.
func New(deps *handlerdeps.Deps) *Handler {
	return &Handler{deps: deps}
}

func (h *Handler) Register(router gin.IRouter) {
	group := router.Group("/mfa-backchannel")

	group.POST("/totp", h.AddTOTP)
	group.DELETE("/totp", h.DeleteTOTP)
	group.POST("/totp/recovery-codes", h.AddRecoveryCodes)
	group.DELETE("/totp/recovery-codes", h.DeleteRecoveryCodes)

	group.GET("/webauthn/credential", h.GetWebAuthnCredential)
	group.POST("/webauthn/credential", h.SaveWebAuthnCredential)
	group.PUT("/webauthn/credential", h.UpdateWebAuthnCredential)
	group.DELETE("/webauthn/credential", h.DeleteWebAuthnCredential)
}

type backendRequest struct {
	Backend     string `json:"backend"`
	BackendName string `json:"backend_name"`
}

type totpRequest struct {
	backendRequest
	Username   string `json:"username"`
	TOTPSecret string `json:"totp_secret"`
}

type recoveryCodesRequest struct {
	backendRequest
	Username string   `json:"username"`
	Codes    []string `json:"codes"`
}

type webauthnRequest struct {
	backendRequest
	Username      string `json:"username"`
	Credential    string `json:"credential"`
	OldCredential string `json:"old_credential"`
}

func (h *Handler) buildAuthState(ctx *gin.Context, username string) (*core.AuthState, error) {
	if h.deps == nil {
		return nil, errors.New("handler dependencies are missing")
	}

	if ctx.GetString(definitions.CtxServiceKey) == "" {
		ctx.Set(definitions.CtxServiceKey, definitions.ServBasic)
	}

	state := core.NewAuthStateFromContextWithDeps(ctx, h.deps.Auth())
	authState := state.(*core.AuthState)

	svc := ctx.GetString(definitions.CtxServiceKey)
	if svc == "" {
		svc = definitions.ServBasic
	}

	authState.SetStatusCodes(svc)
	authState.WithClientInfo(ctx)
	authState.WithLocalInfo(ctx)
	authState.WithUserAgent(ctx)
	authState.WithXSSL(ctx)
	authState.InitMethodAndUserAgent()
	authState.WithDefaults(ctx)
	authState.SetUsername(username)

	return authState, nil
}

func (h *Handler) resolveBackend(ctx *gin.Context, backendType string, backendName string, username string) (core.BackendManager, *core.AuthState, error) {
	authState, err := h.buildAuthState(ctx, username)
	if err != nil {
		return nil, nil, err
	}

	if backendName == "" {
		backendName = definitions.DefaultBackendName
	}

	backendType = strings.ToLower(strings.TrimSpace(backendType))

	authDeps := h.deps.Auth()

	switch backendType {
	case "", "lua":
		return core.NewLuaManager(backendName, authDeps), authState, nil
	case "ldap":
		return core.NewLDAPManager(backendName, authDeps), authState, nil
	default:
		return nil, nil, errors.New("unsupported backend")
	}
}

func parseCredential(raw string) (*mfa.PersistentCredential, error) {
	var credential mfa.PersistentCredential
	if err := json.Unmarshal([]byte(raw), &credential); err != nil {
		return nil, err
	}

	return &credential, nil
}

func (h *Handler) AddTOTP(ctx *gin.Context) {
	var payload totpRequest
	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON payload"})

		return
	}

	if payload.Username == "" || payload.TOTPSecret == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "username and totp_secret are required"})

		return
	}

	mgr, authState, err := h.resolveBackend(ctx, payload.Backend, payload.BackendName, payload.Username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	if err := mgr.AddTOTPSecret(authState, core.NewTOTPSecret(payload.TOTPSecret)); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) DeleteTOTP(ctx *gin.Context) {
	var payload totpRequest
	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON payload"})

		return
	}

	if payload.Username == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})

		return
	}

	mgr, authState, err := h.resolveBackend(ctx, payload.Backend, payload.BackendName, payload.Username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	if err := mgr.DeleteTOTPSecret(authState); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) AddRecoveryCodes(ctx *gin.Context) {
	var payload recoveryCodesRequest
	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON payload"})

		return
	}

	if payload.Username == "" || len(payload.Codes) == 0 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "username and codes are required"})

		return
	}

	mgr, authState, err := h.resolveBackend(ctx, payload.Backend, payload.BackendName, payload.Username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	if err := mgr.AddTOTPRecoveryCodes(authState, mfa.NewTOTPRecovery(payload.Codes)); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) DeleteRecoveryCodes(ctx *gin.Context) {
	var payload recoveryCodesRequest
	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON payload"})

		return
	}

	if payload.Username == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})

		return
	}

	mgr, authState, err := h.resolveBackend(ctx, payload.Backend, payload.BackendName, payload.Username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	if err := mgr.DeleteTOTPRecoveryCodes(authState); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) GetWebAuthnCredential(ctx *gin.Context) {
	username := ctx.Query("username")
	if username == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})

		return
	}

	mgr, authState, err := h.resolveBackend(ctx, ctx.Query("backend"), ctx.Query("backend_name"), username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	credentials, err := mgr.GetWebAuthnCredentials(authState)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	encoded := make([]string, 0, len(credentials))
	for _, credential := range credentials {
		credBytes, err := json.Marshal(credential)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

			return
		}

		encoded = append(encoded, string(credBytes))
	}

	ctx.JSON(http.StatusOK, gin.H{"credentials": encoded})
}

func (h *Handler) SaveWebAuthnCredential(ctx *gin.Context) {
	var payload webauthnRequest
	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON payload"})

		return
	}

	if payload.Username == "" || payload.Credential == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "username and credential are required"})

		return
	}

	mgr, authState, err := h.resolveBackend(ctx, payload.Backend, payload.BackendName, payload.Username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	credential, err := parseCredential(payload.Credential)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "credential must be valid JSON"})

		return
	}

	if err := mgr.SaveWebAuthnCredential(authState, credential); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) UpdateWebAuthnCredential(ctx *gin.Context) {
	var payload webauthnRequest
	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON payload"})

		return
	}

	if payload.Username == "" || payload.Credential == "" || payload.OldCredential == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "username, credential, and old_credential are required"})

		return
	}

	mgr, authState, err := h.resolveBackend(ctx, payload.Backend, payload.BackendName, payload.Username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	credential, err := parseCredential(payload.Credential)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "credential must be valid JSON"})

		return
	}

	oldCredential, err := parseCredential(payload.OldCredential)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "old_credential must be valid JSON"})

		return
	}

	if err := mgr.UpdateWebAuthnCredential(authState, oldCredential, credential); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) DeleteWebAuthnCredential(ctx *gin.Context) {
	var payload webauthnRequest
	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON payload"})

		return
	}

	if payload.Username == "" || payload.Credential == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "username and credential are required"})

		return
	}

	mgr, authState, err := h.resolveBackend(ctx, payload.Backend, payload.BackendName, payload.Username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	credential, err := parseCredential(payload.Credential)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "credential must be valid JSON"})

		return
	}

	if err := mgr.DeleteWebAuthnCredential(authState, credential); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}
