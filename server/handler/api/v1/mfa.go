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
	"strings"

	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/core/cookie"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/idp"
	"github.com/gin-gonic/gin"
)

// MFAAPI provides a JSON API for MFA management.
type MFAAPI struct {
	deps *deps.Deps
	mfa  idp.MFAProvider
}

// NewMFAAPI creates a new MFAAPI.
func NewMFAAPI(d *deps.Deps) *MFAAPI {
	return &MFAAPI{
		deps: d,
		mfa:  idp.NewMFAService(d),
	}
}

// Register adds MFA API routes to the router.
func (a *MFAAPI) Register(router gin.IRouter) {
	mfaGroup := router.Group("/api/v1/mfa", a.mfaManageMiddleware())
	{
		totpGroup := mfaGroup.Group("/totp")
		{
			totpGroup.GET("/setup", a.SetupTOTP)
			totpGroup.POST("/register", a.RegisterTOTP)
			totpGroup.DELETE("", a.DeleteTOTP)
		}

		mfaGroup.POST("/recovery-codes/generate", a.GenerateRecoveryCodes)

		webauthnGroup := mfaGroup.Group("/webauthn")
		{
			webauthnGroup.GET("/register/begin", core.BeginRegistration(a.deps.Auth()))
			webauthnGroup.POST("/register/finish", core.FinishRegistration(a.deps.Auth()))
			webauthnGroup.DELETE("/:credentialID", a.DeleteWebAuthn)
		}
	}
}

// SetupTOTP initializes TOTP registration.
func (a *MFAAPI) SetupTOTP(ctx *gin.Context) {
	mgr := cookie.GetManager(ctx)
	if mgr == nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})

		return
	}

	username := mgr.GetString(definitions.SessionKeyAccount, "")
	if username == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})

		return
	}

	secret, qrCodeURL, err := a.mfa.GenerateTOTPSecret(ctx, username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	mgr.Set(definitions.SessionKeyTOTPSecret, secret)

	if err := mgr.Save(ctx); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})

		return
	}

	mgr.Debug(ctx, a.deps.Logger, "TOTP setup - secret stored in session")

	ctx.JSON(http.StatusOK, gin.H{
		"secret":      secret,
		"qr_code_url": qrCodeURL,
	})
}

// RegisterTOTP completes TOTP registration.
func (a *MFAAPI) RegisterTOTP(ctx *gin.Context) {
	mgr := cookie.GetManager(ctx)
	if mgr == nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})

		return
	}

	username := mgr.GetString(definitions.SessionKeyAccount, "")
	secret := mgr.GetString(definitions.SessionKeyTOTPSecret, "")

	var input struct {
		Code string `json:"code" binding:"required"`
	}

	if err := ctx.ShouldBindJSON(&input); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})

		return
	}

	if username == "" || secret == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})

		return
	}

	sourceBackend := mgr.GetUint8(definitions.SessionKeyUserBackend, uint8(definitions.BackendLDAP))

	if err := a.mfa.VerifyAndSaveTOTP(ctx, username, secret, input.Code, sourceBackend); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})

		return
	}

	mgr.Set(definitions.SessionKeyHaveTOTP, true)
	mgr.Delete(definitions.SessionKeyTOTPSecret)
	_ = mgr.Save(ctx)

	mgr.Debug(ctx, a.deps.Logger, "TOTP registered - session updated")

	ctx.JSON(http.StatusOK, gin.H{"status": "success", "message": "TOTP registered successfully"})
}

// DeleteTOTP removes TOTP.
func (a *MFAAPI) DeleteTOTP(ctx *gin.Context) {
	mgr := cookie.GetManager(ctx)
	if mgr == nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})

		return
	}

	username := mgr.GetString(definitions.SessionKeyAccount, "")
	if username == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})

		return
	}

	sourceBackend := mgr.GetUint8(definitions.SessionKeyUserBackend, uint8(definitions.BackendLDAP))

	if err := a.mfa.DeleteTOTP(ctx, username, sourceBackend); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	mgr.Delete(definitions.SessionKeyHaveTOTP)
	_ = mgr.Save(ctx)

	mgr.Debug(ctx, a.deps.Logger, "TOTP deleted - session updated")

	ctx.JSON(http.StatusOK, gin.H{"status": "success", "message": "TOTP deleted successfully"})
}

// GenerateRecoveryCodes generates new recovery codes.
func (a *MFAAPI) GenerateRecoveryCodes(ctx *gin.Context) {
	mgr := cookie.GetManager(ctx)
	if mgr == nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})

		return
	}

	username := mgr.GetString(definitions.SessionKeyAccount, "")
	if username == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})

		return
	}

	sourceBackend := mgr.GetUint8(definitions.SessionKeyUserBackend, uint8(definitions.BackendLDAP))

	codes, err := a.mfa.GenerateRecoveryCodes(ctx, username, sourceBackend)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	ctx.JSON(http.StatusOK, gin.H{"codes": codes})
}

// mfaManageMiddleware verifies that the current session has MFA management permission.
// For OIDC flows, the nauthilus:mfa:manage scope must be present.
// For SAML flows, the service provider entity ID must be whitelisted in the configuration.
func (a *MFAAPI) mfaManageMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		mgr := cookie.GetManager(ctx)
		if mgr == nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			ctx.Abort()

			return
		}

		account := mgr.GetString(definitions.SessionKeyAccount, "")

		if account == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			ctx.Abort()

			return
		}

		if !a.hasMFAManagePermission(mgr) {
			ctx.JSON(http.StatusForbidden, gin.H{"error": "Missing required permission for MFA management"})
			ctx.Abort()

			return
		}

		ctx.Next()
	}
}

// hasMFAManagePermission checks whether the current session grants MFA management access.
func (a *MFAAPI) hasMFAManagePermission(mgr cookie.Manager) bool {
	flowType := mgr.GetString(definitions.SessionKeyIdPFlowType, "")

	switch flowType {
	case definitions.ProtoOIDC:
		scope := mgr.GetString(definitions.SessionKeyIdPScope, "")

		return hasSessionScope(scope, definitions.ScopeMFAManage)

	case definitions.ProtoSAML:
		entityID := mgr.GetString(definitions.SessionKeyIdPSAMLEntityID, "")

		return a.deps.Cfg.GetIdP().SAML2.IsMFAManageAllowed(entityID)

	default:
		return false
	}
}

// hasSessionScope checks whether a space-separated scope string contains the target scope.
func hasSessionScope(scopeStr, target string) bool {
	for s := range strings.SplitSeq(scopeStr, " ") {
		if s == target {
			return true
		}
	}

	return false
}

// DeleteWebAuthn removes a WebAuthn credential.
func (a *MFAAPI) DeleteWebAuthn(ctx *gin.Context) {
	mgr := cookie.GetManager(ctx)
	if mgr == nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})

		return
	}

	username := mgr.GetString(definitions.SessionKeyAccount, "")
	if username == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})

		return
	}

	credentialID := ctx.Param("credentialID")
	if credentialID == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Missing credential ID"})

		return
	}

	sourceBackend := mgr.GetUint8(definitions.SessionKeyUserBackend, uint8(definitions.BackendLDAP))

	if err := a.mfa.DeleteWebAuthnCredential(ctx, username, credentialID, sourceBackend); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})

		return
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "success", "message": "WebAuthn credential deleted successfully"})
}
