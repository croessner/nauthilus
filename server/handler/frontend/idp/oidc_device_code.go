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
	"github.com/croessner/nauthilus/server/core/cookie"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/frontend"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/idp"
	flowdomain "github.com/croessner/nauthilus/server/idp/flow"
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
	deviceCode := formValue(ctx, "device_code")

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
	setOIDCTokenPostActionMFAOverrides(ctx, request.MFACompleted, request.MFAMethod)

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

// DeviceVerifyFailedPage renders a terminal failure page for processed device codes.
func (h *OIDCHandler) DeviceVerifyFailedPage(ctx *gin.Context) {
	if mgr := cookie.GetManager(ctx); mgr != nil {
		if deviceCode := mgr.GetString(definitions.SessionKeyDeviceCode, ""); deviceCode != "" {
			request, err := h.deviceStore.GetDeviceCode(ctx.Request.Context(), deviceCode)
			if err == nil && request != nil {
				request.Status = idp.DeviceCodeStatusDenied
				_ = h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request)
			}
		}

		abortFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())
	}

	errorMessage := "Invalid login or password"
	if mgr := cookie.GetManager(ctx); mgr != nil {
		if loginError := mgr.GetString(definitions.SessionKeyLoginError, ""); loginError != "" {
			errorMessage = loginError
			mgr.Delete(definitions.SessionKeyLoginError)
		}
	}

	h.renderDeviceVerifyFailed(ctx, errorMessage)
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
		h.renderDeviceVerifyFailed(ctx, "Device code has already been processed")

		return
	}

	// Single-use verification semantics: once first-factor evaluation started
	// for this device code, no additional verify attempts are allowed.
	if request.VerificationLocked {
		h.renderDeviceVerifyFailed(ctx, "Device code has already been processed")

		return
	}

	sp.SetAttributes(
		attribute.String("client_id", request.ClientID),
		attribute.String("username", username),
	)

	mgr := cookie.GetManager(ctx)
	redisPrefix := h.deps.Cfg.GetServer().GetRedis().GetPrefix()
	if outcome, ok := getFlowAuthOutcome(ctx.Request.Context(), mgr, h.deps.Redis, redisPrefix); ok && outcome == flowdomain.AuthOutcomeFailLatched {
		request.Status = idp.DeviceCodeStatusDenied
		_ = h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request)
		abortFlow(ctx.Request.Context(), mgr, h.deps.Redis, redisPrefix)

		h.renderDeviceVerifyFailed(ctx, "Invalid login or password")

		return
	}

	// Authenticate the user.
	// For delayed_response clients, mirror the authorization-code behavior:
	// if password auth fails but MFA is available, continue with MFA and defer
	// the final decision until flow completion.
	authResult := definitions.AuthResultOK
	user, err := h.idp.Authenticate(ctx, username, password, request.ClientID, "")
	if err != nil {
		authResult = definitions.AuthResultFail
		user = nil

		if h.idp.IsDelayedResponse(request.ClientID, "") {
			if delayedUser, userErr := h.idp.GetUserByUsername(ctx, username, request.ClientID, ""); userErr == nil && delayedUser != nil {
				protocol := definitions.ProtoOIDC
				availability := h.frontend.getMFAAvailability(ctx, delayedUser, protocol, cookie.GetManager(ctx))
				if availability.count > 0 {
					user = delayedUser
				}
			}
		}

		if user == nil {
			request.Status = idp.DeviceCodeStatusDenied
			_ = h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request)
			abortFlow(ctx.Request.Context(), mgr, h.deps.Redis, redisPrefix)

			h.renderDeviceVerifyFailed(ctx, "Invalid login or password")

			return
		}
	}

	// Check if user has MFA configured
	protocol := definitions.ProtoOIDC
	availability := h.frontend.getMFAAvailability(ctx, user, protocol, cookie.GetManager(ctx))

	if availability.count > 0 {
		// MFA is required - store session state and redirect to MFA flow
		if mgr == nil {
			h.renderDeviceVerifyError(ctx, userCode, "Internal server error")

			return
		}

		if authResult == definitions.AuthResultFail {
			_ = setFlowAuthOutcome(ctx.Request.Context(), mgr, h.deps.Redis, redisPrefix, flowdomain.AuthOutcomeFailLatched)
		} else {
			_ = setFlowAuthOutcome(ctx.Request.Context(), mgr, h.deps.Redis, redisPrefix, flowdomain.AuthOutcomeOK)
		}

		request.VerificationLocked = true
		if err = h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request); err != nil {
			h.renderDeviceVerifyError(ctx, userCode, "Internal server error")

			return
		}

		controller := newFlowController(mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())
		oidcFlowContext := newOIDCDeviceFlowContext(mgr)
		existingFlowID := mgr.GetString(definitions.SessionKeyIdPFlowID, "")
		existingFlowType := mgr.GetString(definitions.SessionKeyIdPFlowType, "")
		existingGrantType := mgr.GetString(definitions.SessionKeyOIDCGrantType, "")
		createdFlowID := ksuid.New().String()

		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "OIDC device flow creating flow state",
			"flow_branch", "device_verify_mfa",
			"http_method", ctx.Request.Method,
			"request_uri", ctx.Request.RequestURI,
			"request_host", ctx.Request.Host,
			"origin", ctx.GetHeader("Origin"),
			"referer", ctx.GetHeader("Referer"),
			"user_agent", ctx.GetHeader("User-Agent"),
			"x_forwarded_host", ctx.GetHeader("X-Forwarded-Host"),
			"x_forwarded_proto", ctx.GetHeader("X-Forwarded-Proto"),
			"account_present", mgr.GetString(definitions.SessionKeyAccount, "") != "",
			"existing_flow_id", existingFlowID,
			"existing_flow_type", existingFlowType,
			"existing_grant_type", existingGrantType,
			"new_flow_id", createdFlowID,
			"client_id", request.ClientID,
			"device_code", deviceCode,
		)

		decision, err := controller.Start(ctx.Request.Context(), &flowdomain.State{
			FlowID:       createdFlowID,
			FlowType:     flowdomain.FlowTypeOIDCDeviceCode,
			Protocol:     flowdomain.FlowProtocolOIDC,
			CurrentStep:  flowdomain.FlowStepStart,
			GrantType:    definitions.OIDCFlowDeviceCode,
			ReturnTarget: h.frontend.getMFASelectPath(ctx),
			Metadata: map[string]string{
				flowdomain.FlowMetadataClientID:     request.ClientID,
				flowdomain.FlowMetadataDeviceCode:   deviceCode,
				flowdomain.FlowMetadataResumeTarget: flowdomain.FlowMetadataResumeTargetDeviceCodeComplete,
			},
		}, time.Now())
		if err != nil {
			util.DebugModuleWithCfg(
				ctx.Request.Context(),
				h.deps.Cfg,
				h.deps.Logger,
				definitions.DbgIdp,
				definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
				definitions.LogKeyMsg, "OIDC device flow creation failed",
				"flow_branch", "device_verify_mfa",
				"new_flow_id", createdFlowID,
				"error", err,
			)

			h.renderDeviceVerifyError(ctx, userCode, "Internal server error")

			return
		}

		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "OIDC device flow creation completed",
			"flow_branch", "device_verify_mfa",
			"new_flow_id", createdFlowID,
			"redirect_target", decision.RedirectURI,
		)

		oidcFlowContext.StoreMFAContext(
			username,
			user.Id,
			deviceCode,
			request.ClientID,
			protocol,
			authResult,
			availability.count > 1,
		)

		advanceFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix(), flowdomain.FlowStepDeviceVerification)
		advanceFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix(), flowdomain.FlowStepLogin)
		advanceFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix(), flowdomain.FlowStepMFA)

		mgr.Debug(ctx, h.deps.Logger, "Device code MFA required - session data stored")

		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "Device code flow requires MFA",
			"client_id", request.ClientID,
			"username", username,
			"mfa_count", availability.count,
		)

		redirectTarget := decision.RedirectURI

		// Redirect to the appropriate MFA page
		if redirectURL, ok := h.frontend.getMFARedirectURLFromCookie(ctx, user); ok {
			redirectTarget = redirectURL
		}

		ctx.Redirect(http.StatusFound, redirectTarget)

		return
	}

	// No MFA required - check if consent is needed before authorizing
	if h.deviceCodeNeedsConsent(ctx, request.ClientID, request.Scopes) {
		if mgr == nil {
			h.renderDeviceVerifyError(ctx, userCode, "Internal server error")

			return
		}

		controller := newFlowController(mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())
		existingFlowID := mgr.GetString(definitions.SessionKeyIdPFlowID, "")
		existingFlowType := mgr.GetString(definitions.SessionKeyIdPFlowType, "")
		existingGrantType := mgr.GetString(definitions.SessionKeyOIDCGrantType, "")
		createdFlowID := ksuid.New().String()

		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "OIDC device flow creating flow state",
			"flow_branch", "device_verify_consent",
			"http_method", ctx.Request.Method,
			"request_uri", ctx.Request.RequestURI,
			"request_host", ctx.Request.Host,
			"origin", ctx.GetHeader("Origin"),
			"referer", ctx.GetHeader("Referer"),
			"user_agent", ctx.GetHeader("User-Agent"),
			"x_forwarded_host", ctx.GetHeader("X-Forwarded-Host"),
			"x_forwarded_proto", ctx.GetHeader("X-Forwarded-Proto"),
			"account_present", mgr.GetString(definitions.SessionKeyAccount, "") != "",
			"existing_flow_id", existingFlowID,
			"existing_flow_type", existingFlowType,
			"existing_grant_type", existingGrantType,
			"new_flow_id", createdFlowID,
			"client_id", request.ClientID,
			"device_code", deviceCode,
		)

		decision, err := controller.Start(ctx.Request.Context(), &flowdomain.State{
			FlowID:       createdFlowID,
			FlowType:     flowdomain.FlowTypeOIDCDeviceCode,
			Protocol:     flowdomain.FlowProtocolOIDC,
			CurrentStep:  flowdomain.FlowStepStart,
			GrantType:    definitions.OIDCFlowDeviceCode,
			ReturnTarget: h.deviceConsentPath(ctx),
			Metadata: map[string]string{
				flowdomain.FlowMetadataClientID:     request.ClientID,
				flowdomain.FlowMetadataDeviceCode:   deviceCode,
				flowdomain.FlowMetadataResumeTarget: flowdomain.FlowMetadataResumeTargetDeviceCodeComplete,
			},
		}, time.Now())
		if err != nil {
			util.DebugModuleWithCfg(
				ctx.Request.Context(),
				h.deps.Cfg,
				h.deps.Logger,
				definitions.DbgIdp,
				definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
				definitions.LogKeyMsg, "OIDC device flow creation failed",
				"flow_branch", "device_verify_consent",
				"new_flow_id", createdFlowID,
				"error", err,
			)

			h.renderDeviceVerifyError(ctx, userCode, "Internal server error")

			return
		}

		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "OIDC device flow creation completed",
			"flow_branch", "device_verify_consent",
			"new_flow_id", createdFlowID,
			"redirect_target", decision.RedirectURI,
		)

		oidcFlowContext := newOIDCDeviceFlowContext(mgr)

		request.VerificationLocked = true
		if err = h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request); err != nil {
			h.renderDeviceVerifyError(ctx, userCode, "Internal server error")

			return
		}

		oidcFlowContext.StoreConsentContext(deviceCode, request.ClientID, user.Id)

		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "Device code flow requires consent",
			"client_id", request.ClientID,
			"username", username,
		)

		advanceFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix(), flowdomain.FlowStepDeviceVerification)
		advanceFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix(), flowdomain.FlowStepLogin)
		advanceFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix(), flowdomain.FlowStepConsent)

		ctx.Redirect(http.StatusFound, decision.RedirectURI)

		return
	}

	// No consent required - authorize device code directly
	request.Status = idp.DeviceCodeStatusAuthorized
	request.UserID = user.Id

	if err := h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request); err != nil {
		h.renderDeviceVerifyError(ctx, userCode, "Internal server error")

		return
	}

	client, _ := h.idp.FindClient(request.ClientID)
	newOIDCAuthorizeFlowContext(cookie.GetManager(ctx)).AddClientConsent(request.ClientID, request.Scopes, consentTTLForClient(h.deps.Cfg, client))

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "Device code authorized (no MFA, consent skipped)",
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
	data["PostDeviceVerifyEndpoint"] = deviceVerifyPathFromContext(ctx)
	data["CSRFToken"] = csrf.Token(ctx)

	haveError := false
	errorMessage := ""

	if mgr := cookie.GetManager(ctx); mgr != nil {
		if loginError := mgr.GetString(definitions.SessionKeyLoginError, ""); loginError != "" {
			haveError = true
			errorMessage = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, loginError)

			mgr.Delete(definitions.SessionKeyLoginError)
			_ = mgr.Save(ctx)
		}
	}

	data["HaveError"] = haveError
	data["ErrorMessage"] = errorMessage

	return data
}

// renderDeviceVerifyError re-renders the device verify page with an error message.
func (h *OIDCHandler) renderDeviceVerifyError(ctx *gin.Context, userCode string, errorMsg string) {
	renderDeviceCodeError(ctx, h.deps, userCode, errorMsg)
}

// deviceCodeNeedsConsent checks whether the device code flow requires user consent for the given client.
// It mirrors the consent logic from the authorization code grant: consent is needed when
// the client has not set skip_consent and the user has not previously consented in this session.
func (h *OIDCHandler) deviceCodeNeedsConsent(ctx *gin.Context, clientID string, requestedScopes []string) bool {
	client, ok := h.idp.FindClient(clientID)
	if !ok {
		return false
	}

	if client.SkipConsent {
		return false
	}

	mgr := cookie.GetManager(ctx)

	return !newOIDCAuthorizeFlowContext(mgr).HasClientConsent(clientID, requestedScopes)
}

// deviceConsentPath returns the device consent page path with optional language tag.
func (h *OIDCHandler) deviceConsentPath(ctx *gin.Context) string {
	lang := ctx.Param("languageTag")

	if lang != "" {
		return "/oidc/device/consent/" + lang
	}

	return "/oidc/device/consent"
}

// DeviceConsentGET renders the consent page for the device code flow (RFC 8628 §3.3).
// The user is shown which application requests access and which scopes are requested,
// and can approve or deny the authorization.
func (h *OIDCHandler) DeviceConsentGET(ctx *gin.Context) {
	mgr := cookie.GetManager(ctx)
	if mgr == nil {
		ctx.Redirect(http.StatusFound, "/oidc/device/verify")

		return
	}

	oidcFlowContext := newOIDCDeviceFlowContext(mgr)
	deviceCode := oidcFlowContext.DeviceCode()
	if deviceCode == "" {
		ctx.Redirect(http.StatusFound, "/oidc/device/verify")

		return
	}

	request, err := h.deviceStore.GetDeviceCode(ctx.Request.Context(), deviceCode)
	if err != nil || request == nil {
		ctx.Redirect(http.StatusFound, "/oidc/device/verify")

		return
	}

	data := h.buildDeviceConsentPageData(ctx, request)

	ctx.HTML(http.StatusOK, "idp_consent.html", data)
}

// DeviceConsentPOST handles the user's consent decision for the device code flow.
// On approval, the device code is authorized and the success page is shown.
// On denial, the device code is denied and an error page is shown.
func (h *OIDCHandler) DeviceConsentPOST(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "oidc.device_consent_post")
	defer sp.End()

	mgr := cookie.GetManager(ctx)
	if mgr == nil {
		ctx.Redirect(http.StatusFound, "/oidc/device/verify")

		return
	}

	oidcFlowContext := newOIDCDeviceFlowContext(mgr)
	deviceCode := oidcFlowContext.DeviceCode()
	if deviceCode == "" {
		ctx.Redirect(http.StatusFound, "/oidc/device/verify")

		return
	}

	request, err := h.deviceStore.GetDeviceCode(ctx.Request.Context(), deviceCode)
	if err != nil || request == nil {
		ctx.Redirect(http.StatusFound, "/oidc/device/verify")

		return
	}

	submit := ctx.PostForm("submit")

	sp.SetAttributes(attribute.String("client_id", request.ClientID))

	if submit != "allow" {
		// User denied consent
		request.Status = idp.DeviceCodeStatusDenied
		_ = h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request)

		stats.GetMetrics().GetIdpConsentTotal().WithLabelValues(request.ClientID, "deny").Inc()

		abortFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())

		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "Device code consent denied",
			"client_id", request.ClientID,
			"user_code", request.UserCode,
		)

		h.renderDeviceVerifyFailed(ctx, "Authorization denied")

		return
	}

	// User approved consent
	stats.GetMetrics().GetIdpConsentTotal().WithLabelValues(request.ClientID, "allow").Inc()

	request.Status = idp.DeviceCodeStatusAuthorized
	request.UserID = oidcFlowContext.UniqueUserID()
	applyDeviceCodeMFASessionState(mgr, request)

	if err := h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request); err != nil {
		h.renderDeviceVerifyError(ctx, request.UserCode, "Internal server error")

		return
	}

	client, _ := h.idp.FindClient(request.ClientID)
	consentMode := client.GetConsentMode(h.deps.Cfg.GetIdP().OIDC.GetConsentMode())

	if consentMode == config.OIDCConsentModeGranularOptional {
		plan := buildConsentScopePlan(client, h.deps.Cfg.GetIdP().OIDC.GetConsentMode(), request.Scopes)
		grantedScopes, resolveErr := plan.ResolveGranted(ctx.PostFormArray("optional_scope"))
		if resolveErr != nil {
			h.renderDeviceVerifyError(ctx, request.UserCode, "Invalid optional scope selection")

			return
		}

		request.Scopes = grantedScopes
	}

	newOIDCAuthorizeFlowContext(mgr).AddClientConsent(request.ClientID, request.Scopes, consentTTLForClient(h.deps.Cfg, client))

	advanceFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix(), flowdomain.FlowStepCallback)
	completeFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "Device code authorized (consent approved)",
		"client_id", request.ClientID,
		"user_id", request.UserID,
		"user_code", request.UserCode,
	)

	h.renderDeviceVerifySuccess(ctx)
}

// buildDeviceConsentPageData returns the template data for the device consent page.
func (h *OIDCHandler) buildDeviceConsentPageData(ctx *gin.Context, request *idp.DeviceCodeRequest) gin.H {
	data := BasePageData(ctx, h.deps.Cfg, h.deps.LangManager)

	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Consent")
	data["Application"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Application")
	data["WantsToAccessYourAccount"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "wants to access your account")
	data["RequestedPermissions"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Requested permissions")
	data["Allow"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Allow")
	data["Deny"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Deny")

	client, _ := h.idp.FindClient(request.ClientID)
	plan := buildConsentScopePlan(client, h.deps.Cfg.GetIdP().OIDC.GetConsentMode(), request.Scopes)
	scopeDescriptions := consentScopeDescriptions(ctx, h.deps.Cfg, h.deps.Logger, plan.Required)
	optionalScopeChoices := make([]gin.H, 0, len(plan.Optional))
	customScopes := h.deps.Cfg.GetIdP().OIDC.CustomScopes
	lang := consentLanguage(ctx)

	for _, scope := range plan.Optional {
		description, ok := consentScopeDescription(ctx, h.deps.Cfg, h.deps.Logger, customScopes, lang, scope)
		if !ok {
			continue
		}

		optionalScopeChoices = append(optionalScopeChoices, gin.H{
			"Name":        scope,
			"Description": description,
			"Checked":     true,
		})
	}

	data["ClientID"] = request.ClientID
	data["Scopes"] = scopeDescriptions
	data["ConsentModeGranularOptional"] = plan.Mode == config.OIDCConsentModeGranularOptional
	data["OptionalScopeChoices"] = optionalScopeChoices
	data["NoAdditionalPermissions"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, consentMsgNoAdditional)
	data["ConsentChallenge"] = ""
	data["State"] = ""
	data["PostConsentEndpoint"] = ctx.Request.URL.Path
	data["CSRFToken"] = csrf.Token(ctx)

	return data
}

// renderDeviceVerifySuccess renders the success page after device authorization.
func (h *OIDCHandler) renderDeviceVerifySuccess(ctx *gin.Context) {
	renderDeviceCodeSuccess(ctx, h.deps)
}

// renderDeviceVerifyFailed renders the terminal failure page after device authorization fails.
func (h *OIDCHandler) renderDeviceVerifyFailed(ctx *gin.Context, errorMsg string) {
	renderDeviceCodeFailed(ctx, h.deps, errorMsg)
}

// renderDeviceCodeSuccess is a package-level helper that renders the device authorization success page.
// It is used by both OIDCHandler and FrontendHandler to avoid code duplication.
func renderDeviceCodeSuccess(ctx *gin.Context, d *deps.Deps) {
	data := BasePageData(ctx, d.Cfg, d.LangManager)

	data["Title"] = frontend.GetLocalized(ctx, d.Cfg, d.Logger, "Device Authorized")
	data["DeviceVerifySuccessMessage"] = frontend.GetLocalized(ctx, d.Cfg, d.Logger, "Your device has been successfully authorized.")
	data["DeviceVerifySuccessHint"] = frontend.GetLocalized(ctx, d.Cfg, d.Logger, "You can close this window and return to your device.")

	ctx.HTML(http.StatusOK, "idp_device_verify_success.html", data)
}

// renderDeviceCodeFailed is a package-level helper that renders the terminal
// failure page for device authorization attempts.
func renderDeviceCodeFailed(ctx *gin.Context, d *deps.Deps, errorMsg string) {
	data := BasePageData(ctx, d.Cfg, d.LangManager)

	data["Title"] = frontend.GetLocalized(ctx, d.Cfg, d.Logger, "Device Authorization Failed")
	data["DeviceVerifyFailedMessage"] = frontend.GetLocalized(ctx, d.Cfg, d.Logger, errorMsg)
	data["DeviceVerifyFailedHint"] = frontend.GetLocalized(ctx, d.Cfg, d.Logger, "This code can no longer be used. Please start again on your device.")

	ctx.HTML(http.StatusOK, "idp_device_verify_failed.html", data)
}

// renderDeviceCodeError is a package-level helper that renders the device
// verification page with an error message.
func renderDeviceCodeError(ctx *gin.Context, d *deps.Deps, userCode string, errorMsg string) {
	data := BasePageData(ctx, d.Cfg, d.LangManager)

	data["Title"] = frontend.GetLocalized(ctx, d.Cfg, d.Logger, "Device Authorization")
	data["DeviceVerifyDescription"] = frontend.GetLocalized(ctx, d.Cfg, d.Logger, "Enter the code displayed on your device and sign in to authorize it.")
	data["UserCodeLabel"] = frontend.GetLocalized(ctx, d.Cfg, d.Logger, "Device Code")
	data["UserCodePlaceholder"] = frontend.GetLocalized(ctx, d.Cfg, d.Logger, "ABCD-EFGH")
	data["UsernameLabel"] = frontend.GetLocalized(ctx, d.Cfg, d.Logger, "Username")
	data["UsernamePlaceholder"] = frontend.GetLocalized(ctx, d.Cfg, d.Logger, "Username")
	data["PasswordLabel"] = frontend.GetLocalized(ctx, d.Cfg, d.Logger, "Password")
	data["PasswordPlaceholder"] = frontend.GetLocalized(ctx, d.Cfg, d.Logger, "Password")
	data["Submit"] = frontend.GetLocalized(ctx, d.Cfg, d.Logger, "Authorize Device")
	data["PostDeviceVerifyEndpoint"] = deviceVerifyPathFromContext(ctx)
	data["CSRFToken"] = csrf.Token(ctx)
	data["HaveError"] = true
	data["ErrorMessage"] = frontend.GetLocalized(ctx, d.Cfg, d.Logger, errorMsg)
	data["UserCode"] = userCode

	ctx.HTML(http.StatusOK, "idp_device_verify.html", data)
}

func deviceVerifyPathFromContext(ctx *gin.Context) string {
	lang := ctx.Param("languageTag")
	if lang != "" {
		return "/oidc/device/verify/" + lang
	}

	return "/oidc/device/verify"
}

func applyDeviceCodeMFASessionState(mgr cookie.Manager, request *idp.DeviceCodeRequest) {
	if mgr == nil || request == nil {
		return
	}

	request.MFACompleted = mgr.GetBool(definitions.SessionKeyMFACompleted, false)
	request.MFAMethod = mgr.GetString(definitions.SessionKeyMFAMethod, "")
}
