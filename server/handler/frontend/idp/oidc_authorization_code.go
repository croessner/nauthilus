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
)

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

	mgr := cookie.GetManager(ctx)
	oidcFlowContext := newOIDCAuthorizeFlowContext(mgr)
	account := ""

	account = oidcFlowContext.Account()

	clientID := ctx.Query(oidcParamClientID)
	redirectURI := ctx.Query(oidcParamRedirectURI)
	scope := ctx.Query(oidcParamScope)
	state := ctx.Query(oidcParamState)
	nonce := ctx.Query(oidcParamNonce)
	responseType := ctx.Query(oidcParamResponseType)
	prompt := ctx.Query(oidcParamPrompt)
	codeChallenge := ctx.Query(oidcParamCodeChallenge)

	codeChallengeMethod, pkceErr := normalizeCodeChallengeMethod(codeChallenge, ctx.Query(oidcParamCodeChallengeMethod))
	if pkceErr != nil {
		ctx.String(http.StatusBadRequest, pkceErr.Error())

		return
	}

	sp.SetAttributes(
		attribute.String(definitions.LogKeyClientID, clientID),
		attribute.String(oidcParamRedirectURI, redirectURI),
		attribute.String(oidcParamScope, scope),
	)

	if responseType != oidcResponseTypeCode {
		ctx.String(http.StatusBadRequest, "Only response_type=code is supported")

		return
	}

	client, ok := h.idp.FindClient(clientID)
	if !ok {
		ctx.String(http.StatusBadRequest, "Invalid client_id")

		return
	}

	if !h.idp.ValidateRedirectURI(client, redirectURI) {
		ctx.String(http.StatusBadRequest, "Invalid redirect_uri")

		return
	}

	if client.IsPublicClient() && codeChallenge == "" {
		ctx.String(http.StatusBadRequest, "PKCE is required for public clients")

		return
	}

	if account == "" {
		if prompt == "none" {
			target := fmt.Sprintf("%s?error=login_required", redirectURI)
			if state != "" {
				target += "&state=" + url.QueryEscape(state)
			}

			ctx.Redirect(http.StatusFound, target)

			return
		}

		// User not logged in - store OIDC flow state in secure cookie and redirect to login.
		// This prevents open redirect vulnerabilities by not passing return_to in URL.
		redirectTarget := "/login"

		if mgr != nil {
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
				definitions.LogKeyMsg, "OIDC authorize creating flow state",
				"http_method", ctx.Request.Method,
				"request_uri", ctx.Request.RequestURI,
				"request_host", ctx.Request.Host,
				"origin", ctx.GetHeader("Origin"),
				"referer", ctx.GetHeader("Referer"),
				"user_agent", ctx.GetHeader("User-Agent"),
				"x_forwarded_host", ctx.GetHeader("X-Forwarded-Host"),
				"x_forwarded_proto", ctx.GetHeader("X-Forwarded-Proto"),
				oidcParamPrompt, prompt,
				"account_present", account != "",
				"existing_flow_id", existingFlowID,
				"existing_flow_type", existingFlowType,
				"existing_grant_type", existingGrantType,
				"new_flow_id", createdFlowID,
			)

			controller := newFlowController(mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())

			decision, err := controller.Start(ctx.Request.Context(), &flowdomain.State{
				FlowID:       createdFlowID,
				FlowType:     flowdomain.FlowTypeOIDCAuthorization,
				Protocol:     flowdomain.FlowProtocolOIDC,
				CurrentStep:  flowdomain.FlowStepStart,
				GrantType:    definitions.OIDCFlowAuthorizationCode,
				ReturnTarget: "/login",
				Metadata: map[string]string{
					flowdomain.FlowMetadataClientID:            clientID,
					flowdomain.FlowMetadataRedirectURI:         redirectURI,
					flowdomain.FlowMetadataScope:               scope,
					flowdomain.FlowMetadataState:               state,
					flowdomain.FlowMetadataNonce:               nonce,
					flowdomain.FlowMetadataResponseType:        responseType,
					flowdomain.FlowMetadataPrompt:              prompt,
					flowdomain.FlowMetadataCodeChallenge:       codeChallenge,
					flowdomain.FlowMetadataCodeChallengeMethod: codeChallengeMethod,
					flowdomain.FlowMetadataResumeTarget:        ctx.Request.URL.RequestURI(),
				},
			}, time.Now())
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

				return
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

			redirectTarget = decision.RedirectURI

			oidcFlowContext.StoreRequest(clientID, redirectURI, scope, state, nonce, responseType, prompt)

			// Explicitly save cookie before redirect to ensure it's written to the response
			if err := oidcFlowContext.Save(ctx); err != nil {
				ctx.String(http.StatusInternalServerError, "Failed to save session")

				return
			}

			mgr.Debug(ctx, h.deps.Logger, "OIDC flow state stored in cookie - redirecting to login")
		}

		ctx.Redirect(http.StatusFound, redirectTarget)

		return
	}

	if h.flowAuthFailureLatched(ctx, mgr) {
		h.abortFlow(ctx, mgr)
		ctx.String(http.StatusForbidden, "Authorization denied")

		return
	}

	requestedScopes := strings.Split(scope, " ")
	filteredScopes := h.idp.FilterScopes(client, requestedScopes)

	// User is logged in.
	user, err := h.idp.GetUserByUsernameForOIDCClaims(ctx, account, client, filteredScopes)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Internal error loading user details")

		return
	}

	idTokenClaims, accessTokenClaims, err := h.idp.GetClaims(ctx, user, client, filteredScopes)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Internal error mapping claims")

		return
	}

	oidcSession := &idp.OIDCSession{
		ClientID:            clientID,
		UserID:              user.Id,
		Username:            user.Name,
		DisplayName:         user.DisplayName,
		Scopes:              filteredScopes,
		RedirectURI:         redirectURI,
		AuthTime:            time.Now(),
		MFACompleted:        mgr.GetBool(definitions.SessionKeyMFACompleted, false),
		MFAMethod:           mgr.GetString(definitions.SessionKeyMFAMethod, ""),
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		IdTokenClaims:       idTokenClaims,
		AccessTokenClaims:   accessTokenClaims,
	}

	// Check if consent is needed
	needsConsent := !client.SkipConsent && !oidcFlowContext.HasClientConsent(clientID, filteredScopes)
	if !client.SkipConsent && prompt == "consent" {
		needsConsent = true
	}

	if needsConsent {
		if prompt == "none" {
			target := fmt.Sprintf("%s?error=consent_required", redirectURI)
			if state != "" {
				target += "&state=" + url.QueryEscape(state)
			}
			ctx.Redirect(http.StatusFound, target)

			return
		}

		consentChallenge := ksuid.New().String()
		err := h.storage.StoreSession(ctx.Request.Context(), "consent:"+consentChallenge, oidcSession, 10*time.Minute)

		if err != nil {
			ctx.String(http.StatusInternalServerError, "Internal error storing consent session")

			return
		}

		advanceFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix(), flowdomain.FlowStepConsent)

		ctx.Redirect(http.StatusFound, "/oidc/consent?consent_challenge="+consentChallenge+"&state="+url.QueryEscape(state))

		return
	}

	// Generate authorization code
	code := ksuid.New().String()

	// Store session in Redis (expires in 10 minutes)
	err = h.storage.StoreSession(ctx.Request.Context(), code, oidcSession, 10*time.Minute)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Internal error storing session")

		return
	}

	stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("oidc", "success").Inc()

	oidcFlowContext.AddClientConsent(clientID, filteredScopes, consentTTLForClient(h.deps.Cfg, client))

	advanceFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix(), flowdomain.FlowStepCallback)
	completeFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())

	if mgr != nil {
		mgr.Debug(ctx, h.deps.Logger, "OIDC authorization successful - client added to session")
	}

	// Redirect back to client
	target := fmt.Sprintf("%s?code=%s", redirectURI, code)
	if state != "" {
		target += "&state=" + url.QueryEscape(state)
	}

	ctx.Redirect(http.StatusFound, target)
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

// ConsentGET handles the OIDC consent request.
func (h *OIDCHandler) ConsentGET(ctx *gin.Context) {
	consentChallenge := ctx.Query("consent_challenge")
	state := ctx.Query(oidcParamState)

	h.logIncomingOIDCFlowRequest(ctx, "consent_get", "", "")
	defer h.logCompletedOIDCFlowRequest(ctx, "consent_get", "", "")

	session, err := h.storage.GetSession(ctx.Request.Context(), "consent:"+consentChallenge)
	if err != nil {
		ctx.String(http.StatusBadRequest, "Invalid consent challenge")

		return
	}

	mgr := cookie.GetManager(ctx)
	if h.flowAuthFailureLatched(ctx, mgr) {
		_ = h.storage.DeleteSession(ctx.Request.Context(), "consent:"+consentChallenge)
		h.abortFlow(ctx, mgr)
		ctx.String(http.StatusForbidden, "Consent denied")

		return
	}

	data := BasePageData(ctx, h.deps.Cfg, h.deps.LangManager)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Consent")
	data["Application"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Application")
	data["WantsToAccessYourAccount"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "wants to access your account")
	data["RequestedPermissions"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Requested permissions")
	data["Allow"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Allow")
	data["Deny"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Deny")

	// Ensure ReturnTo is set for the header logout link
	if data["ReturnTo"] == "" || data["ReturnTo"] == nil {
		data["ReturnTo"] = ctx.Request.URL.String()
	}

	client, _ := h.idp.FindClient(session.ClientID)
	plan := buildConsentScopePlan(client, h.deps.Cfg.GetIdP().OIDC.GetConsentMode(), session.Scopes)
	customScopes := h.deps.Cfg.GetIdP().OIDC.GetEffectiveCustomScopes(client)
	scopeDescriptions := consentScopeDescriptions(ctx, h.deps.Cfg, h.deps.Logger, customScopes, plan.Required)
	optionalScopeChoices := make([]gin.H, 0, len(plan.Optional))
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

	data["ClientID"] = session.ClientID
	data["Scopes"] = scopeDescriptions
	data["ConsentModeGranularOptional"] = plan.Mode == config.OIDCConsentModeGranularOptional
	data["OptionalScopeChoices"] = optionalScopeChoices
	data["NoAdditionalPermissions"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, consentMsgNoAdditional)
	data["ConsentChallenge"] = consentChallenge
	data["State"] = state
	data["PostConsentEndpoint"] = ctx.Request.URL.Path + "?state=" + url.QueryEscape(state)
	data["CSRFToken"] = csrf.Token(ctx)

	ctx.HTML(http.StatusOK, "idp_consent.html", data)
}

// ConsentPOST handles the OIDC consent submission.
func (h *OIDCHandler) ConsentPOST(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "oidc.consent_post")
	defer sp.End()

	h.logIncomingOIDCFlowRequest(ctx, "consent_post", "", "")
	defer h.logCompletedOIDCFlowRequest(ctx, "consent_post", "", "")

	consentChallenge := ctx.PostForm("consent_challenge")

	state := ctx.PostForm(oidcParamState)
	if state == "" {
		state = ctx.Query(oidcParamState)
	}
	submit := ctx.PostForm("submit")

	session, err := h.storage.GetSession(ctx.Request.Context(), "consent:"+consentChallenge)
	if err != nil {
		ctx.String(http.StatusBadRequest, "Invalid consent challenge")

		return
	}

	sp.SetAttributes(attribute.String(definitions.LogKeyClientID, session.ClientID))

	if submit != "allow" {
		// Denied
		_ = h.storage.DeleteSession(ctx.Request.Context(), "consent:"+consentChallenge)
		stats.GetMetrics().GetIdpConsentTotal().WithLabelValues(session.ClientID, "deny").Inc()
		ctx.String(http.StatusForbidden, "Consent denied")

		return
	}

	mgr := cookie.GetManager(ctx)
	if h.flowAuthFailureLatched(ctx, mgr) {
		_ = h.storage.DeleteSession(ctx.Request.Context(), "consent:"+consentChallenge)
		h.abortFlow(ctx, mgr)
		stats.GetMetrics().GetIdpConsentTotal().WithLabelValues(session.ClientID, "deny").Inc()
		ctx.String(http.StatusForbidden, "Consent denied")

		return
	}

	stats.GetMetrics().GetIdpConsentTotal().WithLabelValues(session.ClientID, "allow").Inc()

	client, ok := h.idp.FindClient(session.ClientID)
	if !ok {
		ctx.String(http.StatusBadRequest, "Invalid client configuration")

		return
	}

	consentMode := client.GetConsentMode(h.deps.Cfg.GetIdP().OIDC.GetConsentMode())
	if consentMode == config.OIDCConsentModeGranularOptional {
		plan := buildConsentScopePlan(client, h.deps.Cfg.GetIdP().OIDC.GetConsentMode(), session.Scopes)
		grantedScopes, resolveErr := plan.ResolveGranted(ctx.PostFormArray("optional_scope"))
		if resolveErr != nil {
			ctx.String(http.StatusBadRequest, "Invalid optional scope selection")

			return
		}

		user, userErr := h.idp.GetUserByUsernameForOIDCClaims(ctx, session.Username, client, grantedScopes)
		if userErr != nil {
			ctx.String(http.StatusInternalServerError, "Internal error loading user details")

			return
		}

		idTokenClaims, accessTokenClaims, claimsErr := h.idp.GetClaims(ctx, user, client, grantedScopes)
		if claimsErr != nil {
			ctx.String(http.StatusInternalServerError, "Internal error mapping claims")

			return
		}

		session.Scopes = grantedScopes
		session.IdTokenClaims = idTokenClaims
		session.AccessTokenClaims = accessTokenClaims
	}

	// Generate authorization code
	code := ksuid.New().String()

	// Store session in Redis
	err = h.storage.StoreSession(ctx.Request.Context(), code, session, 10*time.Minute)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Internal error storing session")

		return
	}

	stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("oidc", "success").Inc()

	// Cleanup consent session
	_ = h.storage.DeleteSession(ctx.Request.Context(), "consent:"+consentChallenge)

	// Redirect back to client
	target := fmt.Sprintf("%s?code=%s&state=%s", session.RedirectURI, code, state)

	if mgr := cookie.GetManager(ctx); mgr != nil {
		newOIDCAuthorizeFlowContext(mgr).AddClientConsent(session.ClientID, session.Scopes, consentTTLForClient(h.deps.Cfg, client))

		advanceFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix(), flowdomain.FlowStepCallback)
		completeFlow(ctx.Request.Context(), mgr, h.deps.Redis, h.deps.Cfg.GetServer().GetRedis().GetPrefix())

		mgr.Debug(ctx, h.deps.Logger, "OIDC consent granted - client added to session")
	}

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

	if !strings.EqualFold(method, "s256") {
		return "", fmt.Errorf("unsupported code_challenge_method: only S256 is allowed")
	}

	return "S256", nil
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

	if codeChallengeMethod != "S256" {
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
