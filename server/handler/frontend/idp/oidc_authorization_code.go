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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/frontend"
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

// oidcAuthorizeRequest carries validated authorization request parameters.
type oidcAuthorizeRequest struct {
	clientID            string
	redirectURI         string
	scope               string
	state               string
	nonce               string
	responseType        string
	prompt              string
	codeChallenge       string
	codeChallengeMethod string
}

// readOIDCAuthorizeRequest reads and normalizes authorization request parameters.
func readOIDCAuthorizeRequest(ctx *gin.Context) (oidcAuthorizeRequest, bool) {
	request := oidcAuthorizeRequest{
		clientID:      ctx.Query(oidcParamClientID),
		redirectURI:   ctx.Query(oidcParamRedirectURI),
		scope:         ctx.Query(oidcParamScope),
		state:         ctx.Query(oidcParamState),
		nonce:         ctx.Query(oidcParamNonce),
		responseType:  ctx.Query(oidcParamResponseType),
		prompt:        ctx.Query(oidcParamPrompt),
		codeChallenge: ctx.Query(oidcParamCodeChallenge),
	}

	codeChallengeMethod, err := normalizeCodeChallengeMethod(request.codeChallenge, ctx.Query(oidcParamCodeChallengeMethod))
	if err != nil {
		ctx.String(http.StatusBadRequest, err.Error())

		return request, false
	}

	request.codeChallengeMethod = codeChallengeMethod

	return request, true
}

// setOIDCAuthorizeSpanAttributes annotates the authorization span.
func setOIDCAuthorizeSpanAttributes(sp trace.Span, request oidcAuthorizeRequest) {
	sp.SetAttributes(
		attribute.String(definitions.LogKeyClientID, request.clientID),
		attribute.String(oidcParamRedirectURI, request.redirectURI),
		attribute.String(oidcParamScope, request.scope),
	)
}

// validateOIDCAuthorizeRequest verifies client, redirect, response type, and PKCE.
func (h *OIDCHandler) validateOIDCAuthorizeRequest(ctx *gin.Context, request oidcAuthorizeRequest) (*config.OIDCClient, bool) {
	if request.responseType != oidcResponseTypeCode {
		ctx.String(http.StatusBadRequest, "Only response_type=code is supported")

		return nil, false
	}

	client, ok := h.idp.FindClient(request.clientID)
	if !ok {
		ctx.String(http.StatusBadRequest, "Invalid client_id")

		return nil, false
	}

	if !h.idp.ValidateRedirectURI(client, request.redirectURI) {
		ctx.String(http.StatusBadRequest, "Invalid redirect_uri")

		return nil, false
	}

	if client.IsPublicClient() && request.codeChallenge == "" {
		ctx.String(http.StatusBadRequest, "PKCE is required for public clients")

		return nil, false
	}

	return client, true
}

// redirectOIDCAuthorizeError redirects an authorization error to the client.
func redirectOIDCAuthorizeError(ctx *gin.Context, redirectURI string, state string, errorCode string) {
	target := fmt.Sprintf("%s?error=%s", redirectURI, errorCode)
	if state != "" {
		target += "&state=" + url.QueryEscape(state)
	}

	ctx.Redirect(http.StatusFound, target)
}

// buildOIDCCallbackRedirectURL appends authorization response parameters safely.
func buildOIDCCallbackRedirectURL(redirectURI string, code string, state string) (string, error) {
	callbackURL, err := url.Parse(strings.TrimSpace(redirectURI))
	if err != nil {
		return "", err
	}

	if strings.TrimSpace(callbackURL.String()) == "" {
		return "", fmt.Errorf("redirect_uri is missing")
	}

	query := callbackURL.Query()
	query.Set(oidcParamCode, code)

	if state != "" {
		query.Set(oidcParamState, state)
	}

	callbackURL.RawQuery = query.Encode()
	callbackURL.Fragment = ""

	return callbackURL.String(), nil
}

// flowMetadata returns Redis flow metadata for an authorization request.
func (request oidcAuthorizeRequest) flowMetadata(ctx *gin.Context) map[string]string {
	return map[string]string{
		flowdomain.FlowMetadataClientID:            request.clientID,
		flowdomain.FlowMetadataRedirectURI:         request.redirectURI,
		flowdomain.FlowMetadataScope:               request.scope,
		flowdomain.FlowMetadataState:               request.state,
		flowdomain.FlowMetadataNonce:               request.nonce,
		flowdomain.FlowMetadataResponseType:        request.responseType,
		flowdomain.FlowMetadataPrompt:              request.prompt,
		flowdomain.FlowMetadataCodeChallenge:       request.codeChallenge,
		flowdomain.FlowMetadataCodeChallengeMethod: request.codeChallengeMethod,
		flowdomain.FlowMetadataResumeTarget:        ctx.Request.URL.RequestURI(),
	}
}

// logOIDCAuthorizeFlowCreation records the browser flow-state creation attempt.
func (h *OIDCHandler) logOIDCAuthorizeFlowCreation(
	ctx *gin.Context,
	mgr cookie.Manager,
	request oidcAuthorizeRequest,
	account string,
	createdFlowID string,
) {
	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "OIDC authorize creating flow state",
		"http_method", ctx.Request.Method,
		"request_uri", ctx.Request.RequestURI,
		"request_host", ctx.Request.Host,
		"origin", ctx.GetHeader("Origin"),
		"referer", ctx.GetHeader("Referer"),
		"user_agent", ctx.GetHeader("User-Agent"),
		"x_forwarded_host", ctx.GetHeader("X-Forwarded-Host"),
		"x_forwarded_proto", ctx.GetHeader("X-Forwarded-Proto"),
		oidcParamPrompt, request.prompt,
		"account_present", account != "",
		"existing_flow_id", mgr.GetString(definitions.SessionKeyIDPFlowID, ""),
		"existing_flow_type", mgr.GetString(definitions.SessionKeyIDPFlowType, ""),
		"existing_grant_type", mgr.GetString(definitions.SessionKeyOIDCGrantType, ""),
		"new_flow_id", createdFlowID,
	)
}

// oidcAuthorizeFlowState builds the Redis-backed browser flow state.
func (request oidcAuthorizeRequest) oidcAuthorizeFlowState(ctx *gin.Context, flowID string) *flowdomain.State {
	return &flowdomain.State{
		FlowID:       flowID,
		Type:         flowdomain.FlowTypeOIDCAuthorization,
		Protocol:     flowdomain.FlowProtocolOIDC,
		CurrentStep:  flowdomain.FlowStepStart,
		GrantType:    definitions.OIDCFlowAuthorizationCode,
		ReturnTarget: frontendLoginPath,
		Metadata:     request.flowMetadata(ctx),
	}
}

// storeOIDCAuthorizeRequest stores request data in the browser flow context.
func storeOIDCAuthorizeRequest(ctx *gin.Context, oidcFlowContext *oidcAuthorizeFlowContext, request oidcAuthorizeRequest) bool {
	oidcFlowContext.StoreRequest(
		request.clientID,
		request.redirectURI,
		request.scope,
		request.state,
		request.nonce,
		request.responseType,
		request.prompt,
	)

	if err := oidcFlowContext.Save(ctx); err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to save session")

		return false
	}

	return true
}

// startOIDCAuthorizeLoginFlow stores authorization flow state before login redirect.
func (h *OIDCHandler) startOIDCAuthorizeLoginFlow(
	ctx *gin.Context,
	mgr cookie.Manager,
	oidcFlowContext *oidcAuthorizeFlowContext,
	request oidcAuthorizeRequest,
	account string,
) (string, bool) {
	createdFlowID := ksuid.New().String()
	h.logOIDCAuthorizeFlowCreation(ctx, mgr, request, account, createdFlowID)

	controller := newFlowController(mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())

	decision, err := controller.Start(ctx.Request.Context(), request.oidcAuthorizeFlowState(ctx, createdFlowID), time.Now())
	if err != nil {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "OIDC authorize flow creation failed",
			"new_flow_id", createdFlowID,
			definitions.LogKeyError, err,
		)

		ctx.String(http.StatusInternalServerError, "Failed to initialize flow session")

		return "", false
	}

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "OIDC authorize flow creation completed",
		"new_flow_id", createdFlowID,
		"redirect_target", decision.RedirectURI,
	)

	if !storeOIDCAuthorizeRequest(ctx, oidcFlowContext, request) {
		return "", false
	}

	mgr.Debug(ctx, h.deps.Logger, "OIDC flow state stored in cookie - redirecting to login")

	return decision.RedirectURI, true
}

// redirectUnauthenticatedOIDCAuthorize handles unauthenticated authorization requests.
func (h *OIDCHandler) redirectUnauthenticatedOIDCAuthorize(
	ctx *gin.Context,
	mgr cookie.Manager,
	oidcFlowContext *oidcAuthorizeFlowContext,
	request oidcAuthorizeRequest,
	account string,
) bool {
	if account != "" {
		return false
	}

	if request.prompt == oidcClientAuthMethodNone {
		redirectOIDCAuthorizeError(ctx, request.redirectURI, request.state, "login_required")

		return true
	}

	redirectTarget := frontendLoginPath

	if mgr != nil {
		target, ok := h.startOIDCAuthorizeLoginFlow(ctx, mgr, oidcFlowContext, request, account)
		if !ok {
			return true
		}

		redirectTarget = target
	}

	ctx.Redirect(http.StatusFound, redirectTarget)

	return true
}

// oidcAuthorizeSessionMFA returns MFA state from the current browser session.
func oidcAuthorizeSessionMFA(mgr cookie.Manager) (bool, string) {
	if mgr == nil {
		return false, ""
	}

	return mgr.GetBool(definitions.SessionKeyMFACompleted, false), mgr.GetString(definitions.SessionKeyMFAMethod, "")
}

// buildOIDCAuthorizeSession creates the pending OIDC session for authorization code issuance.
func (h *OIDCHandler) buildOIDCAuthorizeSession(
	ctx *gin.Context,
	mgr cookie.Manager,
	client *config.OIDCClient,
	request oidcAuthorizeRequest,
	account string,
) (*idp.OIDCSession, []string, bool) {
	requestedScopes := strings.Split(request.scope, " ")
	filteredScopes := h.idp.FilterScopes(client, requestedScopes)

	user, err := h.idp.GetUserByUsernameForOIDCClaims(ctx, account, client, filteredScopes)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Internal error loading user details")

		return nil, nil, false
	}

	idTokenClaims, accessTokenClaims, err := h.idp.GetClaims(ctx, user, client, filteredScopes)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Internal error mapping claims")

		return nil, nil, false
	}

	mfaCompleted, mfaMethod := oidcAuthorizeSessionMFA(mgr)

	return &idp.OIDCSession{
		ClientID:            request.clientID,
		UserID:              user.ID,
		Username:            user.Name,
		DisplayName:         user.DisplayName,
		Scopes:              filteredScopes,
		RedirectURI:         request.redirectURI,
		AuthTime:            time.Now(),
		MFACompleted:        mfaCompleted,
		MFAMethod:           mfaMethod,
		Nonce:               request.nonce,
		CodeChallenge:       request.codeChallenge,
		CodeChallengeMethod: request.codeChallengeMethod,
		IDTokenClaims:       idTokenClaims,
		AccessTokenClaims:   accessTokenClaims,
	}, filteredScopes, true
}

// oidcAuthorizeNeedsConsent reports whether the request must show consent.
func oidcAuthorizeNeedsConsent(client *config.OIDCClient, oidcFlowContext *oidcAuthorizeFlowContext, request oidcAuthorizeRequest, filteredScopes []string) bool {
	if client.SkipConsent {
		return false
	}

	return request.prompt == "consent" || !oidcFlowContext.HasClientConsent(request.clientID, filteredScopes)
}

// redirectOIDCAuthorizeConsent stores pending consent and redirects to the consent page.
func (h *OIDCHandler) redirectOIDCAuthorizeConsent(
	ctx *gin.Context,
	mgr cookie.Manager,
	client *config.OIDCClient,
	oidcFlowContext *oidcAuthorizeFlowContext,
	request oidcAuthorizeRequest,
	session *idp.OIDCSession,
	filteredScopes []string,
) bool {
	if !oidcAuthorizeNeedsConsent(client, oidcFlowContext, request, filteredScopes) {
		return false
	}

	if request.prompt == oidcClientAuthMethodNone {
		redirectOIDCAuthorizeError(ctx, request.redirectURI, request.state, "consent_required")

		return true
	}

	consentChallenge := ksuid.New().String()
	if err := h.storage.StoreSession(ctx.Request.Context(), "consent:"+consentChallenge, session, 10*time.Minute); err != nil {
		ctx.String(http.StatusInternalServerError, "Internal error storing consent session")

		return true
	}

	advanceFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix(), flowdomain.FlowStepConsent)
	ctx.Redirect(http.StatusFound, "/oidc/consent?consent_challenge="+consentChallenge+"&state="+url.QueryEscape(request.state))

	return true
}

// issueOIDCAuthorizeCode stores the OIDC session and redirects back to the client.
func (h *OIDCHandler) issueOIDCAuthorizeCode(
	ctx *gin.Context,
	mgr cookie.Manager,
	oidcFlowContext *oidcAuthorizeFlowContext,
	client *config.OIDCClient,
	request oidcAuthorizeRequest,
	session *idp.OIDCSession,
	filteredScopes []string,
) {
	code := ksuid.New().String()
	if err := h.storage.StoreSession(ctx.Request.Context(), code, session, 10*time.Minute); err != nil {
		ctx.String(http.StatusInternalServerError, "Internal error storing session")

		return
	}

	stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("oidc", "success").Inc()
	oidcFlowContext.AddClientConsent(request.clientID, filteredScopes, consentTTLForClient(h.deps.Cfg, client))
	advanceFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix(), flowdomain.FlowStepCallback)
	completeFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())

	if mgr != nil {
		mgr.Debug(ctx, h.deps.Logger, "OIDC authorization successful - client added to session")
	}

	target, err := buildOIDCCallbackRedirectURL(request.redirectURI, code, request.state)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Invalid redirect_uri")

		return
	}

	ctx.Redirect(http.StatusFound, target)
}

// Authorize handles the OIDC authorization request.
func (h *OIDCHandler) Authorize(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "oidc.authorize")
	defer sp.End()

	if rejectDuplicateOIDCAuthorizeParameters(ctx) {
		return
	}

	h.logIncomingOIDCFlowRequest(ctx, definitions.OIDCFlowAuthorizationCode, "", ctx.Query(oidcParamClientID))
	defer h.logCompletedOIDCFlowRequest(ctx, definitions.OIDCFlowAuthorizationCode, "", ctx.Query(oidcParamClientID))

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "OIDC Authorize request",
		definitions.LogKeyClientID, ctx.Query(oidcParamClientID),
		oidcParamRedirectURI, ctx.Query(oidcParamRedirectURI),
		oidcParamScope, ctx.Query(oidcParamScope),
	)

	request, ok := readOIDCAuthorizeRequest(ctx)
	if !ok {
		return
	}

	setOIDCAuthorizeSpanAttributes(sp, request)

	mgr := cookie.GetManager(ctx)
	oidcFlowContext := newOIDCAuthorizeFlowContext(mgr)
	account := oidcFlowContext.Account()

	client, ok := h.validateOIDCAuthorizeRequest(ctx, request)
	if !ok {
		return
	}

	if h.redirectUnauthenticatedOIDCAuthorize(ctx, mgr, oidcFlowContext, request, account) {
		return
	}

	if h.flowAuthFailureLatched(ctx, mgr) {
		h.abortFlow(ctx, mgr)
		ctx.String(http.StatusForbidden, "Authorization denied")

		return
	}

	oidcSession, filteredScopes, ok := h.buildOIDCAuthorizeSession(ctx, mgr, client, request, account)
	if !ok {
		return
	}

	if h.redirectOIDCAuthorizeConsent(ctx, mgr, client, oidcFlowContext, request, oidcSession, filteredScopes) {
		return
	}

	h.issueOIDCAuthorizeCode(ctx, mgr, oidcFlowContext, client, request, oidcSession, filteredScopes)
}

var oidcAuthorizeSingleValueParameters = []string{
	oidcParamResponseType,
	oidcParamClientID,
	oidcParamRedirectURI,
	oidcParamScope,
	oidcParamState,
	oidcParamNonce,
	oidcParamPrompt,
	oidcParamCodeChallenge,
	oidcParamCodeChallengeMethod,
}

func rejectDuplicateOIDCAuthorizeParameters(ctx *gin.Context) bool {
	if ctx == nil || ctx.Request == nil || ctx.Request.URL == nil {
		return false
	}

	values := ctx.Request.URL.Query()
	for _, key := range oidcAuthorizeSingleValueParameters {
		if len(values[key]) <= 1 {
			continue
		}

		ctx.String(http.StatusBadRequest, "duplicate parameter: "+key)

		return true
	}

	return false
}

// handleAuthorizationCodeTokenExchange processes the authorization_code grant type
// within the token endpoint.
func (h *OIDCHandler) handleAuthorizationCodeTokenExchange(ctx *gin.Context, client *config.OIDCClient, grantType string) {
	clientID := client.ClientID
	code := formValue(ctx, oidcParamCode)

	session, getErr := h.storage.GetSession(ctx.Request.Context(), code)
	if getErr != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{definitions.LogKeyError: oidcErrorInvalidGrant})

		return
	}

	// Delete code after one-time use
	_ = h.storage.DeleteSession(ctx.Request.Context(), code)

	if session.ClientID != clientID {
		ctx.JSON(http.StatusBadRequest, gin.H{definitions.LogKeyError: oidcErrorInvalidGrant})

		return
	}

	if formValue(ctx, oidcParamRedirectURI) != session.RedirectURI {
		ctx.JSON(http.StatusBadRequest, gin.H{definitions.LogKeyError: oidcErrorInvalidGrant})

		return
	}

	if pkceErr := validatePKCEVerifier(session.CodeChallenge, session.CodeChallengeMethod, formValue(ctx, oidcParamCodeVerifier)); pkceErr != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{definitions.LogKeyError: oidcErrorInvalidGrant})

		return
	}

	setOIDCTokenPostActionSubject(ctx, session)
	setOIDCTokenPostActionMFAOverrides(ctx, session.MFACompleted, session.MFAMethod)

	idToken, accessToken, refreshToken, expiresIn, err := h.idp.IssueTokens(ctx.Request.Context(), session)
	if err != nil {
		h.logTokenError(ctx, grantType, clientID, err)

		return
	}

	h.sendTokenResponse(ctx, clientID, grantType, &tokenResponse{
		idToken:      idToken,
		accessToken:  accessToken,
		refreshToken: refreshToken,
		expiresIn:    expiresIn,
	})
}

// handleRefreshTokenExchange processes the refresh_token grant type
// within the token endpoint.
func (h *OIDCHandler) handleRefreshTokenExchange(ctx *gin.Context, client *config.OIDCClient, grantType string) {
	clientID := client.ClientID
	rt := formValue(ctx, oidcParamRefreshToken)

	session, idToken, accessToken, refreshToken, expiresIn, err := h.idp.ExchangeRefreshToken(ctx.Request.Context(), rt, clientID)
	if err != nil {
		if errors.Is(err, idp.ErrInvalidRefreshToken) || errors.Is(err, idp.ErrRefreshTokenClientMismatch) {
			setOIDCTokenFailureReason(ctx, oidcRefreshTokenFailureReason(err))
			ctx.JSON(http.StatusBadRequest, gin.H{definitions.LogKeyError: oidcErrorInvalidGrant})

			return
		}

		h.logTokenError(ctx, grantType, clientID, err)

		return
	}

	setOIDCTokenPostActionSubject(ctx, session)
	setOIDCTokenPostActionMFAOverrides(ctx, session.MFACompleted, session.MFAMethod)

	h.sendTokenResponse(ctx, clientID, grantType, &tokenResponse{
		idToken:      idToken,
		accessToken:  accessToken,
		refreshToken: refreshToken,
		expiresIn:    expiresIn,
	})
}

// loadOIDCConsentSession loads a consent session by challenge.
func (h *OIDCHandler) loadOIDCConsentSession(ctx *gin.Context, consentChallenge string) (*idp.OIDCSession, bool) {
	session, err := h.storage.GetSession(ctx.Request.Context(), "consent:"+consentChallenge)
	if err != nil {
		ctx.String(http.StatusBadRequest, "Invalid consent challenge")

		return nil, false
	}

	return session, true
}

// rejectOIDCConsentIfAuthFailure aborts consent when the flow has latched auth failure.
func (h *OIDCHandler) rejectOIDCConsentIfAuthFailure(ctx *gin.Context, mgr cookie.Manager, consentChallenge string, session *idp.OIDCSession) bool {
	if !h.flowAuthFailureLatched(ctx, mgr) {
		return false
	}

	_ = h.storage.DeleteSession(ctx.Request.Context(), "consent:"+consentChallenge)
	h.abortFlow(ctx, mgr)

	if session != nil {
		stats.GetMetrics().GetIdpConsentTotal().WithLabelValues(session.ClientID, "deny").Inc()
	}

	ctx.String(http.StatusForbidden, "Consent denied")

	return true
}

// oidcConsentOptionalScopeChoices builds template choices for optional scopes.
func (h *OIDCHandler) oidcConsentOptionalScopeChoices(ctx *gin.Context, client *config.OIDCClient, plan consentScopePlan) []gin.H {
	customScopes := h.deps.Cfg.GetIDP().OIDC.GetEffectiveCustomScopes(client)
	lang := consentLanguage(ctx)
	choices := make([]gin.H, 0, len(plan.Optional))

	for _, scope := range plan.Optional {
		description, ok := consentScopeDescription(ctx, h.deps.Cfg, h.deps.Logger, customScopes, lang, scope)
		if !ok {
			continue
		}

		choices = append(choices, gin.H{
			templateDataName:        scope,
			templateDataDescription: description,
			templateDataChecked:     true,
		})
	}

	return choices
}

// oidcConsentPageData builds template data for the consent prompt.
func (h *OIDCHandler) oidcConsentPageData(ctx *gin.Context, session *idp.OIDCSession, consentChallenge string, state string) gin.H {
	data := BasePageData(ctx, h.deps.Cfg, h.deps.LangManager)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Consent")
	data["Application"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Application")
	data["WantsToAccessYourAccount"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "wants to access your account")
	data["RequestedPermissions"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Requested permissions")
	data["Allow"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Allow")
	data["Deny"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Deny")

	if data["ReturnTo"] == "" || data["ReturnTo"] == nil {
		data["ReturnTo"] = ctx.Request.URL.String()
	}

	client, _ := h.idp.FindClient(session.ClientID)
	plan := buildConsentScopePlan(client, h.deps.Cfg.GetIDP().OIDC.GetConsentMode(), session.Scopes)
	customScopes := h.deps.Cfg.GetIDP().OIDC.GetEffectiveCustomScopes(client)

	data["ClientID"] = session.ClientID
	data["Scopes"] = consentScopeDescriptions(ctx, h.deps.Cfg, h.deps.Logger, customScopes, plan.Required)
	data["ConsentModeGranularOptional"] = plan.Mode == config.OIDCConsentModeGranularOptional
	data["OptionalScopeChoices"] = h.oidcConsentOptionalScopeChoices(ctx, client, plan)
	data["NoAdditionalPermissions"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, consentMsgNoAdditional)
	data["ConsentChallenge"] = consentChallenge
	data["State"] = state
	data["PostConsentEndpoint"] = ctx.Request.URL.Path
	data["CSRFToken"] = csrf.Token(ctx)

	return data
}

// ConsentGET handles the OIDC consent request.
func (h *OIDCHandler) ConsentGET(ctx *gin.Context) {
	consentChallenge := ctx.Query("consent_challenge")
	state := ctx.Query(oidcParamState)

	h.logIncomingOIDCFlowRequest(ctx, "consent_get", "", "")
	defer h.logCompletedOIDCFlowRequest(ctx, "consent_get", "", "")

	session, ok := h.loadOIDCConsentSession(ctx, consentChallenge)
	if !ok {
		return
	}

	mgr := cookie.GetManager(ctx)
	if h.rejectOIDCConsentIfAuthFailure(ctx, mgr, consentChallenge, nil) {
		return
	}

	ctx.HTML(http.StatusOK, "idp_consent.html", h.oidcConsentPageData(ctx, session, consentChallenge, state))
}

// oidcConsentPostState resolves state from form data or query fallback.
func oidcConsentPostState(ctx *gin.Context) string {
	state := ctx.PostForm(oidcParamState)
	if state != "" {
		return state
	}

	return ctx.Query(oidcParamState)
}

// denyOIDCConsent rejects and deletes a consent session.
func (h *OIDCHandler) denyOIDCConsent(ctx *gin.Context, consentChallenge string, clientID string) {
	_ = h.storage.DeleteSession(ctx.Request.Context(), "consent:"+consentChallenge)

	stats.GetMetrics().GetIdpConsentTotal().WithLabelValues(clientID, "deny").Inc()

	ctx.String(http.StatusForbidden, "Consent denied")
}

// findOIDCConsentClient resolves the client for a consent session.
func (h *OIDCHandler) findOIDCConsentClient(ctx *gin.Context, session *idp.OIDCSession) (*config.OIDCClient, bool) {
	client, ok := h.idp.FindClient(session.ClientID)
	if !ok {
		ctx.String(http.StatusBadRequest, "Invalid client configuration")

		return nil, false
	}

	return client, true
}

// applyGranularOIDCConsentSelection updates claims when optional scopes changed.
func (h *OIDCHandler) applyGranularOIDCConsentSelection(ctx *gin.Context, session *idp.OIDCSession, client *config.OIDCClient) bool {
	consentMode := client.GetConsentMode(h.deps.Cfg.GetIDP().OIDC.GetConsentMode())
	if consentMode != config.OIDCConsentModeGranularOptional {
		return true
	}

	plan := buildConsentScopePlan(client, h.deps.Cfg.GetIDP().OIDC.GetConsentMode(), session.Scopes)

	grantedScopes, err := plan.ResolveGranted(ctx.PostFormArray("optional_scope"))
	if err != nil {
		ctx.String(http.StatusBadRequest, "Invalid optional scope selection")

		return false
	}

	user, err := h.idp.GetUserByUsernameForOIDCClaims(ctx, session.Username, client, grantedScopes)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Internal error loading user details")

		return false
	}

	idTokenClaims, accessTokenClaims, err := h.idp.GetClaims(ctx, user, client, grantedScopes)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Internal error mapping claims")

		return false
	}

	session.Scopes = grantedScopes
	session.IDTokenClaims = idTokenClaims
	session.AccessTokenClaims = accessTokenClaims

	return true
}

// storeOIDCConsentAuthorizationCode persists the consent-approved OIDC session.
func (h *OIDCHandler) storeOIDCConsentAuthorizationCode(ctx *gin.Context, session *idp.OIDCSession) (string, bool) {
	code := ksuid.New().String()
	if err := h.storage.StoreSession(ctx.Request.Context(), code, session, 10*time.Minute); err != nil {
		ctx.String(http.StatusInternalServerError, "Internal error storing session")

		return "", false
	}

	return code, true
}

// completeOIDCConsentFlow records consent and completes the login flow.
func (h *OIDCHandler) completeOIDCConsentFlow(ctx *gin.Context, mgr cookie.Manager, session *idp.OIDCSession, client *config.OIDCClient) {
	if mgr == nil {
		return
	}

	newOIDCAuthorizeFlowContext(mgr).AddClientConsent(session.ClientID, session.Scopes, consentTTLForClient(h.deps.Cfg, client))
	advanceFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix(), flowdomain.FlowStepCallback)
	completeFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())
	mgr.Debug(ctx, h.deps.Logger, "OIDC consent granted - client added to session")
}

// ConsentPOST handles the OIDC consent submission.
func (h *OIDCHandler) ConsentPOST(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "oidc.consent_post")
	defer sp.End()

	h.logIncomingOIDCFlowRequest(ctx, "consent_post", "", "")
	defer h.logCompletedOIDCFlowRequest(ctx, "consent_post", "", "")

	consentChallenge := ctx.PostForm("consent_challenge")
	state := oidcConsentPostState(ctx)
	submit := ctx.PostForm("submit")

	session, ok := h.loadOIDCConsentSession(ctx, consentChallenge)
	if !ok {
		return
	}

	sp.SetAttributes(attribute.String(definitions.LogKeyClientID, session.ClientID))

	if submit != oidcConsentDecisionAllow {
		h.denyOIDCConsent(ctx, consentChallenge, session.ClientID)
		return
	}

	mgr := cookie.GetManager(ctx)
	if h.rejectOIDCConsentIfAuthFailure(ctx, mgr, consentChallenge, session) {
		return
	}

	stats.GetMetrics().GetIdpConsentTotal().WithLabelValues(session.ClientID, oidcConsentDecisionAllow).Inc()

	client, ok := h.findOIDCConsentClient(ctx, session)
	if !ok {
		return
	}

	if !h.applyGranularOIDCConsentSelection(ctx, session, client) {
		return
	}

	code, ok := h.storeOIDCConsentAuthorizationCode(ctx, session)
	if !ok {
		return
	}

	stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("oidc", "success").Inc()

	_ = h.storage.DeleteSession(ctx.Request.Context(), "consent:"+consentChallenge)

	target, err := buildOIDCCallbackRedirectURL(session.RedirectURI, code, state)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Invalid redirect_uri")

		return
	}

	h.completeOIDCConsentFlow(ctx, mgr, session, client)

	ctx.Redirect(http.StatusFound, target)
}

func (h *OIDCHandler) flowAuthFailureLatched(ctx *gin.Context, mgr cookie.Manager) bool {
	if h == nil || h.deps == nil || ctx == nil {
		return false
	}

	return flowAuthFailureLatched(ctx.Request.Context(), mgr, h.deps.Redis, h.flowRedisPrefix())
}

func (h *OIDCHandler) abortFlow(ctx *gin.Context, mgr cookie.Manager) {
	if h == nil || h.deps == nil || ctx == nil {
		return
	}

	abortFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.flowRedisPrefix())
}

func (h *OIDCHandler) flowRedisPrefix() string {
	if h == nil || h.deps == nil || h.deps.Cfg == nil || h.deps.Cfg.GetServer() == nil {
		return ""
	}

	return h.deps.Cfg.GetServer().GetRedis().GetPrefix()
}

func normalizeCodeChallengeMethod(codeChallenge, codeChallengeMethod string) (string, error) {
	method := strings.TrimSpace(codeChallengeMethod)

	challenge := strings.TrimSpace(codeChallenge)
	if challenge == "" {
		if method != "" {
			return "", fmt.Errorf("code_challenge_method requires code_challenge")
		}

		return "", nil
	}

	if !strings.EqualFold(method, oidcPKCEChallengeMethodS256) {
		return "", fmt.Errorf("unsupported code_challenge_method: only S256 is allowed")
	}

	return oidcPKCEChallengeMethodS256, nil
}

func validatePKCEVerifier(codeChallenge, codeChallengeMethod, codeVerifier string) error {
	challenge := strings.TrimSpace(codeChallenge)
	if challenge == "" {
		return nil
	}

	verifier := strings.TrimSpace(codeVerifier)
	if !isValidCodeVerifier(verifier) {
		return fmt.Errorf("invalid code_verifier")
	}

	if codeChallengeMethod != oidcPKCEChallengeMethodS256 {
		return fmt.Errorf("unsupported code_challenge_method: only S256 is allowed")
	}

	sum := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])

	if subtle.ConstantTimeCompare([]byte(challenge), []byte(expected)) != 1 {
		return fmt.Errorf("code_verifier mismatch")
	}

	return nil
}

func isValidCodeVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}

	for _, char := range verifier {
		if char >= 'A' && char <= 'Z' {
			continue
		}

		if char >= 'a' && char <= 'z' {
			continue
		}

		if char >= '0' && char <= '9' {
			continue
		}

		switch char {
		case '-', '.', '_', '~':
			continue
		default:
			return false
		}
	}

	return true
}
