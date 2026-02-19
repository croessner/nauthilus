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

package idp

import (
	"net/http"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/frontend"
	"github.com/croessner/nauthilus/server/idp"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/middleware/csrf"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/segmentio/ksuid"
	"go.opentelemetry.io/otel/attribute"
)

// DeviceAuthorization handles the device authorization request (RFC 8628 §3.1).
// The client requests a device code and user code for the user to authorize.
func (h *OIDCHandler) DeviceAuthorization(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "oidc.device_authorization")
	defer sp.End()

	clientID := ctx.PostForm("client_id")

	if clientID == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "client_id is required"})

		return
	}

	client, ok := h.idp.FindClient(clientID)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})

		return
	}

	if !client.SupportsGrantType(definitions.OIDCGrantTypeDeviceCode) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "unauthorized_client", "error_description": "client does not support device code grant"})

		return
	}

	sp.SetAttributes(attribute.String("client_id", clientID))

	oidcCfg := h.deps.Cfg.GetIdP().OIDC
	requestedScopes := strings.Fields(ctx.PostForm("scope"))
	filteredScopes := h.idp.FilterScopes(client, requestedScopes)

	userCode, deviceCode, deviceRequest, err := h.createDeviceCodeRequest(ctx, client, &oidcCfg, filteredScopes)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})

		return
	}

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "Device authorization request",
		"client_id", clientID,
		"user_code", userCode,
	)

	issuer := oidcCfg.Issuer
	verificationURI := issuer + "/oidc/device/verify"

	ctx.JSON(http.StatusOK, gin.H{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURI + "?user_code=" + userCode,
		"expires_in":                int(time.Until(deviceRequest.ExpiresAt).Seconds()),
		"interval":                  deviceRequest.Interval,
	})
}

// createDeviceCodeRequest generates and stores a new device code request.
func (h *OIDCHandler) createDeviceCodeRequest(
	ctx *gin.Context,
	client *config.OIDCClient,
	oidcCfg *config.OIDCConfig,
	scopes []string,
) (string, string, *idp.DeviceCodeRequest, error) {
	userCodeLength := oidcCfg.GetDeviceCodeUserCodeLength()

	userCode, err := h.userCodeGen.GenerateUserCode(userCodeLength)
	if err != nil {
		return "", "", nil, err
	}

	deviceCode := ksuid.New().String()
	expiry := oidcCfg.GetDeviceCodeExpiry()
	interval := oidcCfg.GetDeviceCodePollingInterval()

	request := &idp.DeviceCodeRequest{
		ClientID:  client.ClientID,
		Scopes:    scopes,
		UserCode:  userCode,
		Status:    idp.DeviceCodeStatusPending,
		ExpiresAt: time.Now().Add(expiry),
		Interval:  interval,
	}

	if err := h.deviceStore.StoreDeviceCode(ctx.Request.Context(), deviceCode, request, expiry); err != nil {
		return "", "", nil, err
	}

	return userCode, deviceCode, request, nil
}

// handleDeviceCodeTokenExchange handles the token exchange for the device code grant (RFC 8628 §3.4).
// The client polls this endpoint until the user authorizes or denies the request.
func (h *OIDCHandler) handleDeviceCodeTokenExchange(ctx *gin.Context, client *config.OIDCClient) {
	deviceCode := ctx.PostForm("device_code")

	if deviceCode == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "device_code is required"})

		return
	}

	request, err := h.deviceStore.GetDeviceCode(ctx.Request.Context(), deviceCode)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "expired_token", "error_description": "device code has expired"})

		return
	}

	// Verify client_id matches
	if request.ClientID != client.ClientID {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})

		return
	}

	// Check expiration
	if time.Now().After(request.ExpiresAt) {
		_ = h.deviceStore.DeleteDeviceCode(ctx.Request.Context(), deviceCode)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "expired_token"})

		return
	}

	// Enforce polling interval (slow_down per RFC 8628 §3.5)
	if !request.LastPoll.IsZero() && time.Since(request.LastPoll) < time.Duration(request.Interval)*time.Second {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "slow_down"})

		return
	}

	// Update last poll time
	request.LastPoll = time.Now()
	_ = h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request)

	switch request.Status {
	case idp.DeviceCodeStatusPending:
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "authorization_pending"})

	case idp.DeviceCodeStatusDenied:
		_ = h.deviceStore.DeleteDeviceCode(ctx.Request.Context(), deviceCode)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "access_denied"})

	case idp.DeviceCodeStatusAuthorized:
		h.issueDeviceCodeTokens(ctx, deviceCode, request, client)

	default:
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "Device code token exchange: unexpected status",
			"device_code", deviceCode,
			"status", request.Status,
		)

		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
	}
}

// issueDeviceCodeTokens generates and returns tokens after successful device authorization.
func (h *OIDCHandler) issueDeviceCodeTokens(ctx *gin.Context, deviceCode string, request *idp.DeviceCodeRequest, client *config.OIDCClient) {
	// Build an OIDC session from the authorized device code request
	session := &idp.OIDCSession{
		ClientID: request.ClientID,
		UserID:   request.UserID,
		Scopes:   request.Scopes,
		AuthTime: time.Now(),
	}

	// Get claims for the user – the token endpoint context lacks middleware
	// keys (Lua data-exchange, service tag) that GetUserByUsername requires,
	// so we set them explicitly on the copy.
	ginCtx := ctx.Copy()

	if _, exists := ginCtx.Get(definitions.CtxDataExchangeKey); !exists {
		ginCtx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())
	}

	if ginCtx.GetString(definitions.CtxServiceKey) == "" {
		ginCtx.Set(definitions.CtxServiceKey, definitions.ServIdP)
	}

	user, err := h.idp.GetUserByUsername(ginCtx, request.UserID, request.ClientID, "")
	if err != nil {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "Device code token: failed to get user by username",
			"user_id", request.UserID,
			"client_id", request.ClientID,
			"error", err,
		)
	}

	if err == nil && user != nil {
		idTokenClaims, accessTokenClaims, claimsErr := h.idp.GetClaims(ginCtx, user, client, request.Scopes)
		if claimsErr != nil {
			util.DebugModuleWithCfg(
				ctx.Request.Context(),
				h.deps.Cfg,
				h.deps.Logger,
				definitions.DbgIdp,
				definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
				definitions.LogKeyMsg, "Device code token: failed to get claims",
				"user_id", request.UserID,
				"client_id", request.ClientID,
				"error", claimsErr,
			)
		} else {
			session.IdTokenClaims = idTokenClaims
			session.AccessTokenClaims = accessTokenClaims
		}

		if user.DisplayName != "" {
			session.DisplayName = user.DisplayName
		}

		if user.Name != "" {
			session.Username = user.Name
		}
	} else if user == nil && err == nil {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "Device code token: user not found (nil) without error",
			"user_id", request.UserID,
			"client_id", request.ClientID,
		)
	}

	idToken, accessToken, refreshToken, expiresIn, err := h.idp.IssueTokens(ctx.Request.Context(), session)
	if err != nil {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "Device code token: IssueTokens failed",
			"device_code", deviceCode,
			"user_id", request.UserID,
			"client_id", request.ClientID,
			"error", err,
		)

		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})

		return
	}

	// Clean up the device code
	_ = h.deviceStore.DeleteDeviceCode(ctx.Request.Context(), deviceCode)

	stats.GetMetrics().GetIdpTokensIssuedTotal().WithLabelValues("oidc", request.ClientID, definitions.OIDCGrantTypeDeviceCode).Inc()

	resp := gin.H{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(expiresIn.Seconds()),
	}

	if idToken != "" {
		resp["id_token"] = idToken
	}

	if refreshToken != "" {
		resp["refresh_token"] = refreshToken
	}

	ctx.JSON(http.StatusOK, resp)
}

// DeviceVerifyPage renders the device code verification page (RFC 8628 §3.3).
// The user visits this page to enter the user code and authenticate.
func (h *OIDCHandler) DeviceVerifyPage(ctx *gin.Context) {
	data := h.buildDeviceVerifyPageData(ctx)

	// Pre-fill user_code from query parameter (verification_uri_complete support)
	data["UserCode"] = ctx.Query("user_code")

	ctx.HTML(http.StatusOK, "idp_device_verify.html", data)
}

// DeviceVerify handles the user verification of a device code (RFC 8628 §3.3).
// The user submits the user code along with their credentials to authorize or deny the device.
func (h *OIDCHandler) DeviceVerify(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "oidc.device_verify")
	defer sp.End()

	userCode := ctx.PostForm("user_code")

	if userCode == "" {
		h.renderDeviceVerifyError(ctx, "", "User code is required")

		return
	}

	username := ctx.PostForm("username")
	password := ctx.PostForm("password")

	if username == "" || password == "" {
		h.renderDeviceVerifyError(ctx, userCode, "Username and password are required")

		return
	}

	deviceCode, request, err := h.deviceStore.GetDeviceCodeByUserCode(ctx.Request.Context(), userCode)
	if err != nil {
		h.renderDeviceVerifyError(ctx, userCode, "Invalid or expired user code")

		return
	}

	// Check expiration
	if time.Now().After(request.ExpiresAt) {
		_ = h.deviceStore.DeleteDeviceCode(ctx.Request.Context(), deviceCode)

		h.renderDeviceVerifyError(ctx, userCode, "Device code has expired")

		return
	}

	// Verify the request is still pending
	if request.Status != idp.DeviceCodeStatusPending {
		h.renderDeviceVerifyError(ctx, userCode, "Device code has already been processed")

		return
	}

	sp.SetAttributes(
		attribute.String("client_id", request.ClientID),
		attribute.String("username", username),
	)

	// Authenticate the user
	user, err := h.idp.Authenticate(ctx, username, password, request.ClientID, "")
	if err != nil {
		request.Status = idp.DeviceCodeStatusDenied
		_ = h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request)

		h.renderDeviceVerifyError(ctx, userCode, "Authentication failed")

		return
	}

	// Authorization successful - update device code with user info
	request.Status = idp.DeviceCodeStatusAuthorized
	request.UserID = user.Id

	if err := h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request); err != nil {
		h.renderDeviceVerifyError(ctx, userCode, "Internal server error")

		return
	}

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "Device code authorized",
		"client_id", request.ClientID,
		"user_id", user.Id,
		"user_code", request.UserCode,
	)

	h.renderDeviceVerifySuccess(ctx)
}

// buildDeviceVerifyPageData returns the common template data for the device verify page.
func (h *OIDCHandler) buildDeviceVerifyPageData(ctx *gin.Context) gin.H {
	data := BasePageData(ctx, h.deps.Cfg, h.deps.LangManager)

	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Device Authorization")
	data["DeviceVerifyDescription"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Enter the code displayed on your device and sign in to authorize it.")
	data["UserCodeLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Device Code")
	data["UserCodePlaceholder"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "ABCD-EFGH")
	data["UsernameLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Username")
	data["UsernamePlaceholder"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Username")
	data["PasswordLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Password")
	data["PasswordPlaceholder"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Password")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Authorize Device")
	data["PostDeviceVerifyEndpoint"] = "/oidc/device/verify"
	data["CSRFToken"] = csrf.Token(ctx)
	data["HaveError"] = false

	return data
}

// renderDeviceVerifyError re-renders the device verify page with an error message.
func (h *OIDCHandler) renderDeviceVerifyError(ctx *gin.Context, userCode string, errorMsg string) {
	data := h.buildDeviceVerifyPageData(ctx)

	data["HaveError"] = true
	data["ErrorMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, errorMsg)
	data["UserCode"] = userCode

	ctx.HTML(http.StatusOK, "idp_device_verify.html", data)
}

// renderDeviceVerifySuccess renders the success page after device authorization.
func (h *OIDCHandler) renderDeviceVerifySuccess(ctx *gin.Context) {
	data := BasePageData(ctx, h.deps.Cfg, h.deps.LangManager)

	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Device Authorized")
	data["DeviceVerifySuccessMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Your device has been successfully authorized.")
	data["DeviceVerifySuccessHint"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "You can close this window and return to your device.")

	ctx.HTML(http.StatusOK, "idp_device_verify_success.html", data)
}
