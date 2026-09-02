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
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/idp"
	"github.com/croessner/nauthilus/v4/server/util"
	"github.com/gin-gonic/gin"
	"github.com/segmentio/ksuid"
	"go.opentelemetry.io/otel/attribute"
)

// deviceAuthorizationClient resolves and validates the requesting device client.
func (h *OIDCHandler) deviceAuthorizationClient(ctx *gin.Context, clientID string) (*config.OIDCClient, bool) {
	if clientID == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{frontChannelLogoutTaskStatusError: oidcErrorInvalidRequest, oidcJSONErrorDescriptionKey: "client_id is required"})

		return nil, false
	}

	client, ok := h.idp.FindClient(clientID)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{frontChannelLogoutTaskStatusError: oidcErrorInvalidClient})

		return nil, false
	}

	if !client.SupportsGrantType(definitions.OIDCGrantTypeDeviceCode) {
		ctx.JSON(http.StatusBadRequest, gin.H{frontChannelLogoutTaskStatusError: oidcErrorUnauthorizedClient, oidcJSONErrorDescriptionKey: "client does not support device code grant"})

		return nil, false
	}

	return client, true
}

// authenticateDeviceAuthorizationClient validates the device client before state allocation.
func (h *OIDCHandler) authenticateDeviceAuthorizationClient(ctx *gin.Context) (*config.OIDCClient, bool) {
	formClientID := ctx.PostForm(oidcParamClientID)
	clientID := formClientID

	if clientID == "" {
		if basicID, _, ok := ctx.Request.BasicAuth(); ok {
			clientID = decodeOIDCBasicAuthValue(basicID)
		}
	}

	client, ok := h.deviceAuthorizationClient(ctx, clientID)
	if !ok {
		return nil, false
	}

	if allowsUnauthenticatedDeviceAuthorizationClient(client) {
		return client, true
	}

	if formValue(ctx, oidcParamClientAssertion) != "" {
		return h.authenticateDeviceAuthorizationPrivateKeyJWT(ctx, client)
	}

	if !h.authenticateDeviceAuthorizationSecret(ctx, client, formClientID) {
		return nil, false
	}

	return client, true
}

// allowsUnauthenticatedDeviceAuthorizationClient reports whether the device endpoint may skip client authentication.
func allowsUnauthenticatedDeviceAuthorizationClient(client *config.OIDCClient) bool {
	if client == nil {
		return false
	}

	if client.TokenEndpointAuthMethod != "" {
		return client.TokenEndpointAuthMethod == oidcClientAuthMethodNone
	}

	return client.IsPublicClient()
}

// authenticateDeviceAuthorizationPrivateKeyJWT verifies assertion-based device client auth.
func (h *OIDCHandler) authenticateDeviceAuthorizationPrivateKeyJWT(ctx *gin.Context, expectedClient *config.OIDCClient) (*config.OIDCClient, bool) {
	client, ok := h.authenticateClientPrivateKeyJWT(ctx, h.oidcEndpointURL(oidcEndpointPathDevice))
	if !ok {
		return nil, false
	}

	if client.ClientID == expectedClient.ClientID {
		return client, true
	}

	writeOIDCInvalidClientResponse(ctx)

	return nil, false
}

// authenticateDeviceAuthorizationSecret verifies Basic or post-secret device client auth.
func (h *OIDCHandler) authenticateDeviceAuthorizationSecret(ctx *gin.Context, client *config.OIDCClient, formClientID string) bool {
	credentials, ok := h.resolveDeviceAuthorizationSecretCredentials(ctx, formClientID)
	if !ok {
		return false
	}

	if credentials.clientID != client.ClientID {
		writeOIDCInvalidClientResponse(ctx)

		return false
	}

	if !h.enforceOIDCClientAuthMethod(ctx, client, credentials) {
		return false
	}

	if credentials.authSource == "" || credentials.authSource == oidcClientAuthMethodNone {
		writeOIDCInvalidClientResponse(ctx)

		return false
	}

	return h.verifyOIDCClientSecret(ctx, client, credentials)
}

// resolveDeviceAuthorizationSecretCredentials allows Basic auth plus matching form client_id.
func (h *OIDCHandler) resolveDeviceAuthorizationSecretCredentials(ctx *gin.Context, formClientID string) (oidcClientCredentials, bool) {
	credentials := basicOIDCClientCredentials(ctx)
	bodySecret := ctx.PostForm(oidcParamClientSecret)

	if credentials.authSource != "" {
		if formClientID != "" && credentials.clientID != formClientID {
			writeOIDCInvalidClientResponse(ctx)

			return credentials, false
		}

		if bodySecret != "" {
			h.logMultipleOIDCClientAuthenticationMethods(ctx, credentials.authSource)
			writeOIDCInvalidClientResponse(ctx)

			return credentials, false
		}

		ctx.Set(definitions.CtxAuthMethodKey, credentials.authSource)

		return credentials, true
	}

	credentials.bodyClientID = formClientID
	credentials.bodyClientSecret = bodySecret
	credentials.applyBodyCredentials()

	if credentials.authSource != "" {
		ctx.Set(definitions.CtxAuthMethodKey, credentials.authSource)
	}

	return credentials, true
}

// logDeviceAuthorizationRequest records a created device authorization request.
func (h *OIDCHandler) logDeviceAuthorizationRequest(ctx *gin.Context, clientID string, userCode string) {
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
}

// deviceAuthorizationResponse builds the RFC 8628 device authorization response.
func deviceAuthorizationResponse(issuer string, userCode string, deviceCode string, request *idp.DeviceCodeRequest) gin.H {
	verificationURI := issuer + frontendDeviceVerifyPath

	return gin.H{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURI + "?user_code=" + userCode,
		oidcJSONFieldExpiresIn:      int(time.Until(request.ExpiresAt).Seconds()),
		"interval":                  request.Interval,
	}
}

// DeviceAuthorization handles the device authorization request (RFC 8628 §3.1).
// The client requests a device code and user code for the user to authorize.
func (h *OIDCHandler) DeviceAuthorization(ctx *gin.Context) {
	spanCtx, sp := h.tracer.Start(ctx.Request.Context(), "oidc.device_authorization")
	requestScope := util.NewHTTPRequestContextScope(spanCtx, &ctx.Request)

	defer requestScope.Restore()
	defer sp.End()

	clientID := ctx.PostForm(oidcParamClientID)

	h.logIncomingOIDCFlowRequest(ctx, "device_authorization", "", clientID)
	defer h.logCompletedOIDCFlowRequest(ctx, "device_authorization", "", clientID)

	client, ok := h.authenticateDeviceAuthorizationClient(ctx)
	if !ok {
		return
	}

	clientID = client.ClientID
	sp.SetAttributes(attribute.String(oidcParamClientID, clientID))

	oidcCfg := h.deps.Cfg.GetIDP().OIDC
	requestedScopes := strings.Fields(ctx.PostForm("scope"))
	filteredScopes := h.idp.FilterScopes(client, requestedScopes)

	userCode, deviceCode, deviceRequest, err := h.createDeviceCodeRequest(ctx, client, &oidcCfg, filteredScopes)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{frontChannelLogoutTaskStatusError: oidcErrorServerError})

		return
	}

	h.logDeviceAuthorizationRequest(ctx, clientID, userCode)
	ctx.JSON(http.StatusOK, deviceAuthorizationResponse(oidcCfg.Issuer, userCode, deviceCode, deviceRequest))
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

// prepareDeviceCodePoll validates a polling request before status handling.
func (h *OIDCHandler) prepareDeviceCodePoll(ctx *gin.Context, client *config.OIDCClient) (string, *idp.DeviceCodeRequest, bool) {
	deviceCode := formValue(ctx, "device_code")
	if deviceCode == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{frontChannelLogoutTaskStatusError: oidcErrorInvalidRequest, oidcJSONErrorDescriptionKey: "device_code is required"})

		return "", nil, false
	}

	request, err := h.deviceStore.GetDeviceCode(ctx.Request.Context(), deviceCode)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{frontChannelLogoutTaskStatusError: oidcErrorExpiredToken, oidcJSONErrorDescriptionKey: "device code has expired"})

		return "", nil, false
	}

	if request.ClientID != client.ClientID {
		ctx.JSON(http.StatusBadRequest, gin.H{frontChannelLogoutTaskStatusError: oidcErrorInvalidGrant})

		return "", nil, false
	}

	if time.Now().After(request.ExpiresAt) {
		_ = h.deviceStore.DeleteDeviceCode(ctx.Request.Context(), deviceCode)
		ctx.JSON(http.StatusBadRequest, gin.H{frontChannelLogoutTaskStatusError: oidcErrorExpiredToken})

		return "", nil, false
	}

	if !request.LastPoll.IsZero() && time.Since(request.LastPoll) < time.Duration(request.Interval)*time.Second {
		ctx.JSON(http.StatusBadRequest, gin.H{frontChannelLogoutTaskStatusError: oidcErrorSlowDown})

		return "", nil, false
	}

	request.LastPoll = time.Now()
	_ = h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request)

	return deviceCode, request, true
}

// handleDeviceCodePollStatus writes the token endpoint response for current status.
func (h *OIDCHandler) handleDeviceCodePollStatus(ctx *gin.Context, deviceCode string, request *idp.DeviceCodeRequest, client *config.OIDCClient) {
	switch request.Status {
	case idp.DeviceCodeStatusPending:
		ctx.JSON(http.StatusBadRequest, gin.H{frontChannelLogoutTaskStatusError: oidcErrorAuthorizationPending})

	case idp.DeviceCodeStatusDenied:
		_ = h.deviceStore.DeleteDeviceCode(ctx.Request.Context(), deviceCode)
		ctx.JSON(http.StatusBadRequest, gin.H{frontChannelLogoutTaskStatusError: oidcErrorAccessDenied})

	case idp.DeviceCodeStatusAuthorized:
		claimed, err := h.deviceStore.ClaimAuthorizedDeviceCode(ctx.Request.Context(), deviceCode, client.ClientID)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{frontChannelLogoutTaskStatusError: oidcErrorInvalidGrant})

			return
		}

		h.issueDeviceCodeTokens(ctx, deviceCode, claimed, client)

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

		ctx.JSON(http.StatusInternalServerError, gin.H{frontChannelLogoutTaskStatusError: oidcErrorServerError})
	}
}

// handleDeviceCodeTokenExchange handles the token exchange for the device code grant (RFC 8628 §3.4).
// The client polls this endpoint until the user authorizes or denies the request.
func (h *OIDCHandler) handleDeviceCodeTokenExchange(ctx *gin.Context, client *config.OIDCClient) {
	deviceCode, request, ok := h.prepareDeviceCodePoll(ctx, client)
	if !ok {
		return
	}

	h.handleDeviceCodePollStatus(ctx, deviceCode, request, client)
}

// ensureDeviceCodeRequestClaims recovers missing claims before token issuance.
func (h *OIDCHandler) ensureDeviceCodeRequestClaims(ctx *gin.Context, deviceCode string, request *idp.DeviceCodeRequest, client *config.OIDCClient) bool {
	if request.IDTokenClaims == nil || request.AccessTokenClaims == nil {
		if err := h.recoverMissingDeviceRequestClaims(ctx, deviceCode, request, client); err != nil {
			util.DebugModuleWithCfg(
				ctx.Request.Context(),
				h.deps.Cfg,
				h.deps.Logger,
				definitions.DbgIdp,
				definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
				definitions.LogKeyMsg, "Device code token: missing persisted claims",
				"device_code", deviceCode,
				"user_id", request.UserID,
				"client_id", request.ClientID,
				"error", err,
			)

			ctx.JSON(http.StatusInternalServerError, gin.H{frontChannelLogoutTaskStatusError: oidcErrorServerError})

			return false
		}
	}

	return true
}

// newDeviceCodeOIDCSession builds an OIDC session from an authorized device request.
func newDeviceCodeOIDCSession(request *idp.DeviceCodeRequest) *idp.OIDCSession {
	return &idp.OIDCSession{
		ClientID:          request.ClientID,
		UserID:            request.UserID,
		Username:          request.Username,
		DisplayName:       request.DisplayName,
		Scopes:            request.Scopes,
		AuthTime:          time.Now(),
		MFACompleted:      request.MFACompleted,
		MFAMethod:         request.MFAMethod,
		IDTokenClaims:     request.IDTokenClaims,
		AccessTokenClaims: request.AccessTokenClaims,
	}
}

// issueDeviceCodeTokens generates and returns tokens after successful device authorization.
func (h *OIDCHandler) issueDeviceCodeTokens(ctx *gin.Context, deviceCode string, request *idp.DeviceCodeRequest, client *config.OIDCClient) {
	if !h.ensureDeviceCodeRequestClaims(ctx, deviceCode, request, client) {
		return
	}

	session := newDeviceCodeOIDCSession(request)

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

	h.sendTokenResponse(ctx, request.ClientID, definitions.OIDCGrantTypeDeviceCode, &tokenResponse{
		idToken:      idToken,
		accessToken:  accessToken,
		refreshToken: refreshToken,
		expiresIn:    expiresIn,
	})
}

func (h *OIDCHandler) recoverMissingDeviceRequestClaims(
	ctx *gin.Context,
	deviceCode string,
	request *idp.DeviceCodeRequest,
	client *config.OIDCClient,
) error {
	if request.UserFromSnapshot() == nil {
		if err := h.backfillDeviceRequestSnapshot(ctx, request); err != nil {
			return err
		}
	}

	if err := hydrateDeviceRequestClaims(ctx, h.idp, request, client, nil); err != nil {
		return err
	}

	if err := h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request); err != nil {
		return fmt.Errorf("failed to persist recovered device claims: %w", err)
	}

	return nil
}

func (h *OIDCHandler) backfillDeviceRequestSnapshot(ctx *gin.Context, request *idp.DeviceCodeRequest) error {
	if request == nil {
		return fmt.Errorf("device request is nil")
	}

	candidates := make([]string, 0, 2)
	if request.Username != "" {
		candidates = append(candidates, request.Username)
	}

	if request.UserID != "" && request.UserID != request.Username {
		candidates = append(candidates, request.UserID)
	}

	client, ok := h.idp.FindClient(request.ClientID)
	if !ok {
		return fmt.Errorf("oidc client is not configured")
	}

	for _, candidate := range candidates {
		user, err := h.idp.GetUserByUsernameForOIDCClaims(ctx, candidate, client, request.Scopes)
		if err != nil || user == nil {
			continue
		}

		request.StoreUserSnapshot(user)

		return nil
	}

	return fmt.Errorf("device request has no user snapshot")
}

func hydrateDeviceRequestClaims(
	ctx *gin.Context,
	idpInstance *idp.NauthilusIDP,
	request *idp.DeviceCodeRequest,
	client *config.OIDCClient,
	user *backend.User,
) error {
	if request == nil {
		return fmt.Errorf("device request is nil")
	}

	if idpInstance == nil {
		return fmt.Errorf("idp instance is nil")
	}

	if client == nil {
		return fmt.Errorf("oidc client is nil")
	}

	if user != nil {
		request.StoreUserSnapshot(user)
	}

	snapshotUser := request.UserFromSnapshot()
	if snapshotUser == nil {
		return fmt.Errorf("device request has no user snapshot")
	}

	idTokenClaims, accessTokenClaims, err := idpInstance.GetClaims(ctx, snapshotUser, client, request.Scopes)
	if err != nil {
		return err
	}

	request.IDTokenClaims = idTokenClaims
	request.AccessTokenClaims = accessTokenClaims

	return nil
}
