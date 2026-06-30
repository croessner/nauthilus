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

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/frontend"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/idp"
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/croessner/nauthilus/v3/server/middleware/csrf"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
	"github.com/segmentio/ksuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
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
	_, sp := h.tracer.Start(ctx.Request.Context(), "oidc.device_authorization")
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
	setOIDCTokenPostActionMFAOverrides(ctx, request.MFACompleted, request.MFAMethod)

	if !h.ensureDeviceCodeRequestClaims(ctx, deviceCode, request, client) {
		return
	}

	session := newDeviceCodeOIDCSession(request)

	setOIDCTokenPostActionSubject(ctx, session)

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

// deviceVerifyCredentials carries submitted device verification credentials.
type deviceVerifyCredentials struct {
	userCode string
	username string
	password string
}

// deviceVerifyMFAState carries resolved MFA routing state.
type deviceVerifyMFAState struct {
	user         *backend.User
	factorUser   *backend.User
	factorRef    core.RemoteBackendRef
	availability mfaAvailability
	protocol     string
}

// readDeviceVerifyCredentials validates the submitted device verification form.
func (h *OIDCHandler) readDeviceVerifyCredentials(ctx *gin.Context) (deviceVerifyCredentials, bool) {
	credentials := deviceVerifyCredentials{userCode: ctx.PostForm("user_code")}
	if credentials.userCode == "" {
		h.renderDeviceVerifyError(ctx, "", "User code is required")

		return credentials, false
	}

	credentials.username = ctx.PostForm("username")

	credentials.password = ctx.PostForm("password")
	if credentials.username == "" || credentials.password == "" {
		h.renderDeviceVerifyError(ctx, credentials.userCode, "Username and password are required")

		return credentials, false
	}

	return credentials, true
}

// loadPendingDeviceVerifyRequest loads and validates the pending device request.
func (h *OIDCHandler) loadPendingDeviceVerifyRequest(ctx *gin.Context, userCode string) (string, *idp.DeviceCodeRequest, bool) {
	deviceCode, request, err := h.deviceStore.GetDeviceCodeByUserCode(ctx.Request.Context(), userCode)
	if err != nil {
		h.renderDeviceVerifyError(ctx, userCode, "Invalid or expired user code")

		return "", nil, false
	}

	if time.Now().After(request.ExpiresAt) {
		_ = h.deviceStore.DeleteDeviceCode(ctx.Request.Context(), deviceCode)
		h.renderDeviceVerifyError(ctx, userCode, "Device code has expired")

		return "", nil, false
	}

	if request.Status != idp.DeviceCodeStatusPending || request.VerificationLocked {
		h.renderDeviceVerifyFailed(ctx, "Device code has already been processed")

		return "", nil, false
	}

	return deviceCode, request, true
}

// rejectLatchedDeviceVerifyFailure handles a previously latched auth failure.
func (h *OIDCHandler) rejectLatchedDeviceVerifyFailure(
	ctx *gin.Context,
	mgr cookie.Manager,
	redisPrefix string,
	deviceCode string,
	request *idp.DeviceCodeRequest,
) bool {
	outcome, ok := getFlowAuthOutcome(ctx.Request.Context(), mgr, h.deps.Redis, redisPrefix)
	if !ok || outcome != flowdomain.AuthOutcomeFailLatched {
		return false
	}

	request.Status = idp.DeviceCodeStatusDenied
	_ = h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request)
	abortFlow(ctx.Request.Context(), mgr, h.deps.Redis, redisPrefix)

	h.renderDeviceVerifyFailed(
		ctx,
		renderStoredIDPAuthStatusBridgeMessage(ctx, h.deps, mgr, idpGenericInvalidLoginMessage),
	)

	return true
}

// deviceVerifyDelayedResponseAllowed checks whether MFA can defer an auth failure.
func (h *OIDCHandler) deviceVerifyDelayedResponseAllowed(
	ctx *gin.Context,
	credentials deviceVerifyCredentials,
	request *idp.DeviceCodeRequest,
	client *config.OIDCClient,
	err error,
) bool {
	if !idpAuthFailureAllowsDelayedResponse(err) || !h.idp.IsDelayedResponse(request.ClientID, "") {
		return false
	}

	delayedUser, userErr := h.idp.GetUserByUsernameForOIDCClaims(ctx, credentials.username, client, request.Scopes)
	if userErr != nil || delayedUser == nil {
		return false
	}

	factorUser, _, factorRef, factorErr := h.frontend.resolveMFAFactorUser(ctx, h.idp, credentials.username, delayedUser, client.ClientID, "")
	if factorErr != nil {
		factorUser = nil
	}

	availability := h.frontend.getMFAAvailabilityWithBackendRef(ctx, factorUser, definitions.ProtoOIDC, cookie.GetManager(ctx), factorRef)

	return availability.count > 0
}

// denyDeviceVerifyAuthentication marks the device request denied after auth failure.
func (h *OIDCHandler) denyDeviceVerifyAuthentication(
	ctx *gin.Context,
	mgr cookie.Manager,
	redisPrefix string,
	deviceCode string,
	request *idp.DeviceCodeRequest,
	err error,
) {
	request.Status = idp.DeviceCodeStatusDenied
	_ = h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request)
	abortFlow(ctx.Request.Context(), mgr, h.deps.Redis, redisPrefix)

	h.renderDeviceVerifyFailed(
		ctx,
		renderIDPAuthFailureMessage(ctx, h.deps, err, idpGenericInvalidLoginMessage),
	)
}

// authenticateDeviceVerifyUser verifies first-factor credentials for device flow.
func (h *OIDCHandler) authenticateDeviceVerifyUser(
	ctx *gin.Context,
	mgr cookie.Manager,
	redisPrefix string,
	deviceCode string,
	request *idp.DeviceCodeRequest,
	client *config.OIDCClient,
	credentials deviceVerifyCredentials,
) (definitions.AuthResult, bool, error) {
	_, err := h.idp.Authenticate(ctx, credentials.username, credentials.password, request.ClientID, "")
	if err == nil {
		return definitions.AuthResultOK, true, nil
	}

	if h.deviceVerifyDelayedResponseAllowed(ctx, credentials, request, client, err) {
		return definitions.AuthResultFail, true, err
	}

	h.denyDeviceVerifyAuthentication(ctx, mgr, redisPrefix, deviceCode, request, err)

	return definitions.AuthResultFail, false, err
}

// loadDeviceVerifyUserAndClaims loads OIDC claims for the verified user.
func (h *OIDCHandler) loadDeviceVerifyUserAndClaims(
	ctx *gin.Context,
	credentials deviceVerifyCredentials,
	request *idp.DeviceCodeRequest,
	client *config.OIDCClient,
) (*backend.User, bool) {
	user, err := h.idp.GetUserByUsernameForOIDCClaims(ctx, credentials.username, client, request.Scopes)
	if err != nil {
		h.renderDeviceVerifyError(ctx, credentials.userCode, "Internal server error")

		return nil, false
	}

	if err = hydrateDeviceRequestClaims(ctx, h.idp, request, client, user); err != nil {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "Device code verify: failed to hydrate claims",
			"user_id", request.UserID,
			"client_id", request.ClientID,
			"error", err,
		)

		h.renderDeviceVerifyError(ctx, credentials.userCode, "Internal server error")

		return nil, false
	}

	return user, true
}

// resolveDeviceVerifyMFAState resolves backend identity and active MFA methods.
func (h *OIDCHandler) resolveDeviceVerifyMFAState(
	ctx *gin.Context,
	mgr cookie.Manager,
	credentials deviceVerifyCredentials,
	request *idp.DeviceCodeRequest,
	client *config.OIDCClient,
	user *backend.User,
) (deviceVerifyMFAState, bool) {
	state := deviceVerifyMFAState{user: user, protocol: definitions.ProtoOIDC}

	factorUser, _, factorRef, err := h.frontend.resolveMFAFactorUser(ctx, h.idp, credentials.username, user, client.ClientID, "")
	if err != nil {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "Device code verify: failed to load Master-User MFA factor account",
			"client_id", request.ClientID,
			"error", err,
		)

		h.renderDeviceVerifyError(ctx, credentials.userCode, "Invalid login or password")

		return state, false
	}

	state.factorUser = factorUser
	state.factorRef = factorRef
	state.availability = h.frontend.getMFAAvailabilityWithBackendRef(ctx, factorUser, state.protocol, mgr, factorRef)

	return state, true
}

// deviceVerifyFlowState builds the Redis flow state for MFA or consent redirects.
func (h *OIDCHandler) deviceVerifyFlowState(
	request *idp.DeviceCodeRequest,
	deviceCode string,
	createdFlowID string,
	returnTarget string,
) *flowdomain.State {
	return &flowdomain.State{
		FlowID:       createdFlowID,
		Type:         flowdomain.FlowTypeOIDCDeviceCode,
		Protocol:     flowdomain.FlowProtocolOIDC,
		CurrentStep:  flowdomain.FlowStepStart,
		GrantType:    definitions.OIDCFlowDeviceCode,
		ReturnTarget: returnTarget,
		Metadata: map[string]string{
			flowdomain.FlowMetadataClientID:     request.ClientID,
			flowdomain.FlowMetadataDeviceCode:   deviceCode,
			flowdomain.FlowMetadataResumeTarget: flowdomain.FlowMetadataResumeTargetDeviceCodeComplete,
		},
	}
}

// startDeviceVerifyFlow creates flow state for MFA or consent continuation.
func (h *OIDCHandler) startDeviceVerifyFlow(
	ctx *gin.Context,
	mgr cookie.Manager,
	flowBranch string,
	returnTarget string,
	request *idp.DeviceCodeRequest,
	deviceCode string,
) (flowdomain.Decision, bool) {
	controller := newFlowController(mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())
	createdFlowID := ksuid.New().String()

	h.logDeviceFlowStateCreation(
		ctx,
		mgr,
		flowBranch,
		mgr.GetString(definitions.SessionKeyIDPFlowID, ""),
		mgr.GetString(definitions.SessionKeyIDPFlowType, ""),
		mgr.GetString(definitions.SessionKeyOIDCGrantType, ""),
		createdFlowID,
		request,
		deviceCode,
	)

	decision, err := controller.Start(ctx.Request.Context(), h.deviceVerifyFlowState(request, deviceCode, createdFlowID, returnTarget), time.Now())
	if err != nil {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "OIDC device flow creation failed",
			"flow_branch", flowBranch,
			"new_flow_id", createdFlowID,
			"error", err,
		)

		h.renderDeviceVerifyError(ctx, request.UserCode, "Internal server error")

		return decision, false
	}

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "OIDC device flow creation completed",
		"flow_branch", flowBranch,
		"new_flow_id", createdFlowID,
		"redirect_target", decision.RedirectURI,
	)

	return decision, true
}

// setDeviceVerifyAuthOutcome stores the first-factor result for later MFA completion.
func (h *OIDCHandler) setDeviceVerifyAuthOutcome(
	ctx *gin.Context,
	mgr cookie.Manager,
	redisPrefix string,
	authResult definitions.AuthResult,
	authErr error,
) {
	if authResult == definitions.AuthResultFail {
		_ = setFlowAuthOutcome(ctx.Request.Context(), mgr, h.deps.Redis, redisPrefix, flowdomain.AuthOutcomeFailLatched)
		storeIDPAuthStatusBridgeFromError(mgr, authErr)

		return
	}

	_ = setFlowAuthOutcome(ctx.Request.Context(), mgr, h.deps.Redis, redisPrefix, flowdomain.AuthOutcomeOK)
	clearIDPAuthStatusBridge(mgr)
}

// lockDeviceVerifyRequest marks a request as already being processed.
func (h *OIDCHandler) lockDeviceVerifyRequest(ctx *gin.Context, deviceCode string, request *idp.DeviceCodeRequest, userCode string) bool {
	request.VerificationLocked = true
	if err := h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request); err != nil {
		h.renderDeviceVerifyError(ctx, userCode, "Internal server error")

		return false
	}

	return true
}

// advanceDeviceVerifyFlow advances the common device verification flow steps.
func (h *OIDCHandler) advanceDeviceVerifyFlow(ctx *gin.Context, mgr cookie.Manager, steps ...flowdomain.Step) {
	for _, step := range steps {
		advanceFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix(), step)
	}
}

// redirectDeviceVerifyMFA stores MFA session state and redirects to the MFA flow.
func (h *OIDCHandler) redirectDeviceVerifyMFA(
	ctx *gin.Context,
	mgr cookie.Manager,
	redisPrefix string,
	deviceCode string,
	request *idp.DeviceCodeRequest,
	credentials deviceVerifyCredentials,
	mfaState deviceVerifyMFAState,
	authResult definitions.AuthResult,
	authErr error,
) bool {
	if mgr == nil {
		h.renderDeviceVerifyError(ctx, credentials.userCode, "Internal server error")

		return true
	}

	h.setDeviceVerifyAuthOutcome(ctx, mgr, redisPrefix, authResult, authErr)

	if !h.lockDeviceVerifyRequest(ctx, deviceCode, request, credentials.userCode) {
		return true
	}

	decision, ok := h.startDeviceVerifyFlow(ctx, mgr, "device_verify_mfa", h.frontend.getMFASelectPath(ctx), request, deviceCode)
	if !ok {
		return true
	}

	oidcFlowContext := newOIDCDeviceFlowContext(mgr)
	oidcFlowContext.StoreMFAContext(
		credentials.username,
		mfaState.user.ID,
		deviceCode,
		request.ClientID,
		mfaState.protocol,
		authResult,
		mfaState.availability.count > 1,
	)
	core.StorePendingIDPMFAIdentity(mgr, mfaState.user)
	core.StorePendingIDPMFAFactor(mgr, mfaState.factorUser)
	core.StorePendingIDPMFAFactorRemoteBackendRef(mgr, mfaState.factorRef)

	h.advanceDeviceVerifyFlow(ctx, mgr, flowdomain.FlowStepDeviceVerification, flowdomain.FlowStepLogin, flowdomain.FlowStepMFA)
	mgr.Debug(ctx, h.deps.Logger, "Device code MFA required - session data stored")
	h.logDeviceVerifyMFARequired(ctx, credentials.username, request, mfaState.availability)

	redirectTarget := decision.RedirectURI
	if redirectURL, ok := h.frontend.getMFARedirectURLFromAvailability(mfaState.availability); ok {
		redirectTarget = redirectURL
	}

	ctx.Redirect(http.StatusFound, redirectTarget)

	return true
}

// logDeviceVerifyMFARequired records the MFA branch of device verification.
func (h *OIDCHandler) logDeviceVerifyMFARequired(ctx *gin.Context, username string, request *idp.DeviceCodeRequest, availability mfaAvailability) {
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
}

// redirectDeviceVerifyConsent stores consent session state and redirects.
func (h *OIDCHandler) redirectDeviceVerifyConsent(
	ctx *gin.Context,
	mgr cookie.Manager,
	deviceCode string,
	request *idp.DeviceCodeRequest,
	credentials deviceVerifyCredentials,
	user *backend.User,
) bool {
	if mgr == nil {
		h.renderDeviceVerifyError(ctx, credentials.userCode, "Internal server error")

		return true
	}

	decision, ok := h.startDeviceVerifyFlow(ctx, mgr, "device_verify_consent", h.deviceConsentPath(ctx), request, deviceCode)
	if !ok {
		return true
	}

	if !h.lockDeviceVerifyRequest(ctx, deviceCode, request, credentials.userCode) {
		return true
	}

	newOIDCDeviceFlowContext(mgr).StoreConsentContext(deviceCode, request.ClientID, user.ID)
	h.logDeviceVerifyConsentRequired(ctx, credentials.username, request)
	h.advanceDeviceVerifyFlow(ctx, mgr, flowdomain.FlowStepDeviceVerification, flowdomain.FlowStepLogin, flowdomain.FlowStepConsent)

	ctx.Redirect(http.StatusFound, decision.RedirectURI)

	return true
}

// logDeviceVerifyConsentRequired records the consent branch of device verification.
func (h *OIDCHandler) logDeviceVerifyConsentRequired(ctx *gin.Context, username string, request *idp.DeviceCodeRequest) {
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
}

// authorizeDeviceCodeDirectly completes a device request without MFA or consent.
func (h *OIDCHandler) authorizeDeviceCodeDirectly(
	ctx *gin.Context,
	deviceCode string,
	request *idp.DeviceCodeRequest,
	client *config.OIDCClient,
	user *backend.User,
) {
	applyDeviceCodeMFASessionState(cookie.GetManager(ctx), request)

	if !h.enforceOIDCClientMFAAssurance(ctx, cookie.GetManager(ctx), client) {
		return
	}

	request.Status = idp.DeviceCodeStatusAuthorized
	if err := h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request); err != nil {
		h.renderDeviceVerifyError(ctx, request.UserCode, "Internal server error")

		return
	}

	newOIDCAuthorizeFlowContext(cookie.GetManager(ctx)).AddClientConsent(request.ClientID, request.Scopes, consentTTLForClient(h.deps.Cfg, client))

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "Device code authorized (no MFA, consent skipped)",
		"client_id", request.ClientID,
		"user_id", user.ID,
		"user_code", request.UserCode,
	)

	h.renderDeviceVerifySuccess(ctx)
}

// resolveDeviceVerifyClient resolves the client configured for a device request.
func (h *OIDCHandler) resolveDeviceVerifyClient(ctx *gin.Context, request *idp.DeviceCodeRequest, credentials deviceVerifyCredentials) (*config.OIDCClient, bool) {
	client, ok := h.idp.FindClient(request.ClientID)
	if !ok {
		h.renderDeviceVerifyError(ctx, credentials.userCode, "Internal server error")

		return nil, false
	}

	return client, true
}

// setDeviceVerifySpanAttributes adds non-secret device-verification attributes to the trace span.
func setDeviceVerifySpanAttributes(sp trace.Span, request *idp.DeviceCodeRequest, credentials deviceVerifyCredentials) {
	sp.SetAttributes(
		attribute.String("client_id", request.ClientID),
		attribute.String("username", credentials.username),
	)
}

// DeviceVerify handles the user verification of a device code (RFC 8628 §3.3).
// The user submits the user code along with their credentials to authorize or deny the device.
func (h *OIDCHandler) DeviceVerify(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "oidc.device_verify")
	defer sp.End()

	h.logIncomingOIDCFlowRequest(ctx, "device_verify", "", "")
	defer h.logCompletedOIDCFlowRequest(ctx, "device_verify", "", "")

	credentials, ok := h.readDeviceVerifyCredentials(ctx)
	if !ok {
		return
	}

	deviceCode, request, ok := h.loadPendingDeviceVerifyRequest(ctx, credentials.userCode)
	if !ok {
		return
	}

	setDeviceVerifySpanAttributes(sp, request, credentials)

	mgr := cookie.GetManager(ctx)

	redisPrefix := h.deps.Cfg.GetServer().GetRedis().GetPrefix()
	if h.rejectLatchedDeviceVerifyFailure(ctx, mgr, redisPrefix, deviceCode, request) {
		return
	}

	client, ok := h.resolveDeviceVerifyClient(ctx, request, credentials)
	if !ok {
		return
	}

	authResult, ok, authErr := h.authenticateDeviceVerifyUser(ctx, mgr, redisPrefix, deviceCode, request, client, credentials)
	if !ok {
		return
	}

	user, ok := h.loadDeviceVerifyUserAndClaims(ctx, credentials, request, client)
	if !ok {
		return
	}

	mfaState, ok := h.resolveDeviceVerifyMFAState(ctx, mgr, credentials, request, client, user)
	if !ok {
		return
	}

	if mfaState.availability.count > 0 {
		h.redirectDeviceVerifyMFA(ctx, mgr, redisPrefix, deviceCode, request, credentials, mfaState, authResult, authErr)

		return
	}

	if h.deviceCodeNeedsConsent(ctx, request.ClientID, request.Scopes) {
		h.redirectDeviceVerifyConsent(ctx, mgr, deviceCode, request, credentials, user)

		return
	}

	h.authorizeDeviceCodeDirectly(ctx, deviceCode, request, client, user)
}

// logDeviceFlowStateCreation records the diagnostic context used when device flows create flow state.
func (h *OIDCHandler) logDeviceFlowStateCreation(
	ctx *gin.Context,
	mgr cookie.Manager,
	flowBranch string,
	existingFlowID string,
	existingFlowType string,
	existingGrantType string,
	createdFlowID string,
	request *idp.DeviceCodeRequest,
	deviceCode string,
) {
	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "OIDC device flow creating flow state",
		"flow_branch", flowBranch,
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
		return frontendDeviceConsentPath + "/" + lang
	}

	return frontendDeviceConsentPath
}

// DeviceConsentGET renders the consent page for the device code flow (RFC 8628 §3.3).
// The user is shown which application requests access and which scopes are requested,
// and can approve or deny the authorization.
func (h *OIDCHandler) DeviceConsentGET(ctx *gin.Context) {
	h.logIncomingOIDCFlowRequest(ctx, "device_consent_get", "", "")
	defer h.logCompletedOIDCFlowRequest(ctx, "device_consent_get", "", "")

	mgr := cookie.GetManager(ctx)
	if mgr == nil {
		ctx.Redirect(http.StatusFound, frontendDeviceVerifyPath)

		return
	}

	oidcFlowContext := newOIDCDeviceFlowContext(mgr)

	deviceCode := oidcFlowContext.DeviceCode()
	if deviceCode == "" {
		ctx.Redirect(http.StatusFound, frontendDeviceVerifyPath)

		return
	}

	request, err := h.deviceStore.GetDeviceCode(ctx.Request.Context(), deviceCode)
	if err != nil || request == nil {
		ctx.Redirect(http.StatusFound, frontendDeviceVerifyPath)

		return
	}

	data := h.buildDeviceConsentPageData(ctx, request)

	ctx.HTML(http.StatusOK, "idp_consent.html", data)
}

// denyDeviceConsent marks the device code as denied and aborts the flow.
func (h *OIDCHandler) denyDeviceConsent(ctx *gin.Context, mgr cookie.Manager, deviceCode string, request *idp.DeviceCodeRequest) {
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
}

// rejectDeviceConsentIfAuthFailure denies consent when auth failure was latched.
func (h *OIDCHandler) rejectDeviceConsentIfAuthFailure(ctx *gin.Context, mgr cookie.Manager, deviceCode string, request *idp.DeviceCodeRequest) bool {
	if !h.flowAuthFailureLatched(ctx, mgr) {
		return false
	}

	request.Status = idp.DeviceCodeStatusDenied
	_ = h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request)

	stats.GetMetrics().GetIdpConsentTotal().WithLabelValues(request.ClientID, "deny").Inc()
	h.abortFlow(ctx, mgr)
	h.renderDeviceVerifyFailed(
		ctx,
		renderStoredIDPAuthStatusBridgeMessage(ctx, h.deps, mgr, idpGenericInvalidLoginMessage),
	)

	return true
}

// applyDeviceConsentScopeSelection applies optional granular scopes.
func (h *OIDCHandler) applyDeviceConsentScopeSelection(ctx *gin.Context, request *idp.DeviceCodeRequest, client *config.OIDCClient) bool {
	consentMode := client.GetConsentMode(h.deps.Cfg.GetIDP().OIDC.GetConsentMode())
	if consentMode != config.OIDCConsentModeGranularOptional {
		return true
	}

	plan := buildConsentScopePlan(client, h.deps.Cfg.GetIDP().OIDC.GetConsentMode(), request.Scopes)

	grantedScopes, err := plan.ResolveGranted(ctx.PostFormArray("optional_scope"))
	if err != nil {
		h.renderDeviceVerifyError(ctx, request.UserCode, "Invalid optional scope selection")

		return false
	}

	request.Scopes = grantedScopes

	return true
}

// hydrateDeviceConsentClaims updates claims after consent approval.
func (h *OIDCHandler) hydrateDeviceConsentClaims(ctx *gin.Context, request *idp.DeviceCodeRequest, client *config.OIDCClient) bool {
	if err := hydrateDeviceRequestClaims(ctx, h.idp, request, client, nil); err != nil {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "Device code consent: failed to hydrate claims",
			"user_id", request.UserID,
			"client_id", request.ClientID,
			"error", err,
		)

		h.renderDeviceVerifyError(ctx, request.UserCode, "Internal server error")

		return false
	}

	return true
}

// completeDeviceConsentApproval persists approval and completes the device flow.
func (h *OIDCHandler) completeDeviceConsentApproval(
	ctx *gin.Context,
	mgr cookie.Manager,
	deviceCode string,
	request *idp.DeviceCodeRequest,
	client *config.OIDCClient,
) bool {
	if err := h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request); err != nil {
		h.renderDeviceVerifyError(ctx, request.UserCode, "Internal server error")

		return false
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

	return true
}

// deviceConsentContext carries the loaded device consent state.
type deviceConsentContext struct {
	mgr             cookie.Manager
	oidcFlowContext *oidcDeviceFlowContext
	request         *idp.DeviceCodeRequest
	deviceCode      string
}

// loadDeviceConsentContext loads cookie and device-code state for consent POST.
func (h *OIDCHandler) loadDeviceConsentContext(ctx *gin.Context) (deviceConsentContext, bool) {
	consentContext := deviceConsentContext{mgr: cookie.GetManager(ctx)}
	if consentContext.mgr == nil {
		ctx.Redirect(http.StatusFound, frontendDeviceVerifyPath)

		return consentContext, false
	}

	consentContext.oidcFlowContext = newOIDCDeviceFlowContext(consentContext.mgr)

	consentContext.deviceCode = consentContext.oidcFlowContext.DeviceCode()
	if consentContext.deviceCode == "" {
		ctx.Redirect(http.StatusFound, frontendDeviceVerifyPath)

		return consentContext, false
	}

	request, err := h.deviceStore.GetDeviceCode(ctx.Request.Context(), consentContext.deviceCode)
	if err != nil || request == nil {
		ctx.Redirect(http.StatusFound, frontendDeviceVerifyPath)

		return consentContext, false
	}

	consentContext.request = request

	return consentContext, true
}

// approveDeviceConsent authorizes the device request after positive consent.
func (h *OIDCHandler) approveDeviceConsent(ctx *gin.Context, consentContext deviceConsentContext) bool {
	request := consentContext.request
	stats.GetMetrics().GetIdpConsentTotal().WithLabelValues(request.ClientID, oidcConsentDecisionAllow).Inc()

	client, ok := h.idp.FindClient(request.ClientID)
	if !ok {
		h.renderDeviceVerifyError(ctx, request.UserCode, "Internal server error")

		return false
	}

	request.Status = idp.DeviceCodeStatusAuthorized
	if request.UserID == "" {
		request.UserID = consentContext.oidcFlowContext.UniqueUserID()
	}

	applyDeviceCodeMFASessionState(consentContext.mgr, request)

	if !h.enforceOIDCClientMFAAssurance(ctx, consentContext.mgr, client) {
		return false
	}

	return h.applyDeviceConsentScopeSelection(ctx, request, client) &&
		h.hydrateDeviceConsentClaims(ctx, request, client) &&
		h.completeDeviceConsentApproval(ctx, consentContext.mgr, consentContext.deviceCode, request, client)
}

// DeviceConsentPOST handles the user's consent decision for the device code flow.
// On approval, the device code is authorized and the success page is shown.
// On denial, the device code is denied and an error page is shown.
func (h *OIDCHandler) DeviceConsentPOST(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "oidc.device_consent_post")
	defer sp.End()

	h.logIncomingOIDCFlowRequest(ctx, "device_consent_post", "", "")
	defer h.logCompletedOIDCFlowRequest(ctx, "device_consent_post", "", "")

	consentContext, ok := h.loadDeviceConsentContext(ctx)
	if !ok {
		return
	}

	submit := ctx.PostForm("submit")

	sp.SetAttributes(attribute.String("client_id", consentContext.request.ClientID))

	if submit != oidcConsentDecisionAllow {
		h.denyDeviceConsent(ctx, consentContext.mgr, consentContext.deviceCode, consentContext.request)
		return
	}

	if h.rejectDeviceConsentIfAuthFailure(ctx, consentContext.mgr, consentContext.deviceCode, consentContext.request) {
		return
	}

	if !h.approveDeviceConsent(ctx, consentContext) {
		return
	}

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
	plan := buildConsentScopePlan(client, h.deps.Cfg.GetIDP().OIDC.GetConsentMode(), request.Scopes)
	customScopes := h.deps.Cfg.GetIDP().OIDC.GetEffectiveCustomScopes(client)
	scopeDescriptions := consentScopeDescriptions(ctx, h.deps.Cfg, h.deps.Logger, customScopes, plan.Required)
	optionalScopeChoices := make([]gin.H, 0, len(plan.Optional))
	lang := consentLanguage(ctx)

	for _, scope := range plan.Optional {
		description, ok := consentScopeDescription(ctx, h.deps.Cfg, h.deps.Logger, customScopes, lang, scope)
		if !ok {
			continue
		}

		optionalScopeChoices = append(optionalScopeChoices, gin.H{
			templateDataName:        scope,
			templateDataDescription: description,
			templateDataChecked:     true,
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
		return frontendDeviceVerifyPath + "/" + lang
	}

	return frontendDeviceVerifyPath
}

func applyDeviceCodeMFASessionState(mgr cookie.Manager, request *idp.DeviceCodeRequest) {
	if mgr == nil || request == nil {
		return
	}

	request.MFACompleted = mgr.GetBool(definitions.SessionKeyMFACompleted, false)
	request.MFAMethod = mgr.GetString(definitions.SessionKeyMFAMethod, "")
}
