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
	executeMFAOp(h, ctx,
		func(p totpRequest) string {
			if p.Username == "" || p.TOTPSecret == "" {
				return "username and totp_secret are required"
			}

			return ""
		},
		func(mgr core.BackendManager, auth *core.AuthState, p totpRequest) error {
			return mgr.AddTOTPSecret(auth, core.NewTOTPSecret(p.TOTPSecret))
		},
	)
}

// mfaPayload is implemented by request types that carry backend routing and username information.
type mfaPayload interface {
	getBackend() string
	getBackendName() string
	getUsername() string
}

func (r totpRequest) getBackend() string              { return r.Backend }
func (r totpRequest) getBackendName() string          { return r.BackendName }
func (r totpRequest) getUsername() string             { return r.Username }
func (r recoveryCodesRequest) getBackend() string     { return r.Backend }
func (r recoveryCodesRequest) getBackendName() string { return r.BackendName }
func (r recoveryCodesRequest) getUsername() string    { return r.Username }
func (r webauthnRequest) getBackend() string          { return r.Backend }
func (r webauthnRequest) getBackendName() string      { return r.BackendName }
func (r webauthnRequest) getUsername() string         { return r.Username }

// executeMFAOp binds JSON, validates the payload, resolves the backend, and executes the operation.
// The validate function performs payload-specific checks (return error message or empty string).
// The operate function receives the resolved backend manager, auth state, and the original payload.
func executeMFAOp[T mfaPayload](
	h *Handler,
	ctx *gin.Context,
	validate func(T) string,
	operate func(core.BackendManager, *core.AuthState, T) error,
) {
	var payload T

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON payload"})

		return
	}

	if msg := validate(payload); msg != "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": msg})

		return
	}

	mgr, authState, err := h.resolveBackend(ctx, payload.getBackend(), payload.getBackendName(), payload.getUsername())
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	if err := operate(mgr, authState, payload); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// requireUsername validates that the username field is present.
func requireUsername[T mfaPayload](p T) string {
	if p.getUsername() == "" {
		return "username is required"
	}

	return ""
}

// executeWebAuthnOp is a specialization of executeMFAOp for WebAuthn operations that
// need to parse a credential from the payload before calling the backend operation.
func executeWebAuthnOp(
	h *Handler,
	ctx *gin.Context,
	validate func(webauthnRequest) string,
	operate func(core.BackendManager, *core.AuthState, *mfa.PersistentCredential) error,
) {
	executeMFAOp(h, ctx, validate,
		func(mgr core.BackendManager, auth *core.AuthState, p webauthnRequest) error {
			credential, err := parseCredential(p.Credential)
			if err != nil {
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "credential must be valid JSON"})

				return nil
			}

			return operate(mgr, auth, credential)
		},
	)
}

func (h *Handler) DeleteTOTP(ctx *gin.Context) {
	executeMFAOp(h, ctx,
		requireUsername[totpRequest],
		func(mgr core.BackendManager, auth *core.AuthState, _ totpRequest) error {
			return mgr.DeleteTOTPSecret(auth)
		},
	)
}

func (h *Handler) AddRecoveryCodes(ctx *gin.Context) {
	executeMFAOp(h, ctx,
		func(p recoveryCodesRequest) string {
			if p.Username == "" || len(p.Codes) == 0 {
				return "username and codes are required"
			}

			return ""
		},
		func(mgr core.BackendManager, auth *core.AuthState, p recoveryCodesRequest) error {
			return mgr.AddTOTPRecoveryCodes(auth, mfa.NewTOTPRecovery(p.Codes))
		},
	)
}

func (h *Handler) DeleteRecoveryCodes(ctx *gin.Context) {
	executeMFAOp(h, ctx,
		requireUsername[recoveryCodesRequest],
		func(mgr core.BackendManager, auth *core.AuthState, _ recoveryCodesRequest) error {
			return mgr.DeleteTOTPRecoveryCodes(auth)
		},
	)
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
	executeWebAuthnOp(h, ctx,
		func(p webauthnRequest) string {
			if p.Username == "" || p.Credential == "" {
				return "username and credential are required"
			}

			return ""
		},
		func(mgr core.BackendManager, auth *core.AuthState, cred *mfa.PersistentCredential) error {
			return mgr.SaveWebAuthnCredential(auth, cred)
		},
	)
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
	executeWebAuthnOp(h, ctx,
		func(p webauthnRequest) string {
			if p.Username == "" || p.Credential == "" {
				return "username and credential are required"
			}

			return ""
		},
		func(mgr core.BackendManager, auth *core.AuthState, cred *mfa.PersistentCredential) error {
			return mgr.DeleteWebAuthnCredential(auth, cred)
		},
	)
}
