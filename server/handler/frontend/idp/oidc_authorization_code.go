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
	"net/url"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core/cookie"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/frontend"
	"github.com/croessner/nauthilus/server/idp"
	"github.com/croessner/nauthilus/server/middleware/csrf"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/segmentio/ksuid"
	"go.opentelemetry.io/otel/attribute"
)

// hasClientConsent checks whether the user has already granted consent for the given client.
func hasClientConsent(mgr cookie.Manager, clientID string) bool {
	if mgr == nil {
		return false
	}

	oidcClients := mgr.GetString(definitions.SessionKeyOIDCClients, "")
	if oidcClients == "" {
		return false
	}

	for _, id := range strings.Split(oidcClients, ",") {
		if id == clientID {
			return true
		}
	}

	return false
}

// addClientToCookie persists the client ID in the session cookie so that
// consent does not have to be requested again during the same session.
func addClientToCookie(mgr cookie.Manager, clientID string) {
	if mgr == nil {
		return
	}

	oidcClients := mgr.GetString(definitions.SessionKeyOIDCClients, "")

	if oidcClients != "" {
		for _, id := range strings.Split(oidcClients, ",") {
			if id == clientID {
				return
			}
		}

		oidcClients += "," + clientID
	} else {
		oidcClients = clientID
	}

	mgr.Set(definitions.SessionKeyOIDCClients, oidcClients)
}

// Authorize handles the OIDC authorization request.
func (h *OIDCHandler) Authorize(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "oidc.authorize")
	defer sp.End()

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "OIDC Authorize request",
		"client_id", ctx.Query("client_id"),
		"redirect_uri", ctx.Query("redirect_uri"),
		"scope", ctx.Query("scope"),
	)

	mgr := cookie.GetManager(ctx)
	account := ""

	if mgr != nil {
		account = mgr.GetString(definitions.SessionKeyAccount, "")
	}

	clientID := ctx.Query("client_id")
	redirectURI := ctx.Query("redirect_uri")
	scope := ctx.Query("scope")
	state := ctx.Query("state")
	nonce := ctx.Query("nonce")
	responseType := ctx.Query("response_type")
	prompt := ctx.Query("prompt")

	sp.SetAttributes(
		attribute.String("client_id", clientID),
		attribute.String("redirect_uri", redirectURI),
		attribute.String("scope", scope),
	)

	if responseType != "code" {
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
		if mgr != nil {
			mgr.Set(definitions.SessionKeyIdPFlowActive, true)
			mgr.Set(definitions.SessionKeyIdPFlowType, definitions.ProtoOIDC)
			mgr.Set(definitions.SessionKeyOIDCGrantType, definitions.OIDCFlowAuthorizationCode)
			mgr.Set(definitions.SessionKeyIdPClientID, clientID)
			mgr.Set(definitions.SessionKeyIdPRedirectURI, redirectURI)
			mgr.Set(definitions.SessionKeyIdPScope, scope)
			mgr.Set(definitions.SessionKeyIdPState, state)
			mgr.Set(definitions.SessionKeyIdPNonce, nonce)
			mgr.Set(definitions.SessionKeyIdPResponseType, responseType)
			mgr.Set(definitions.SessionKeyIdPPrompt, prompt)
			mgr.Set(definitions.SessionKeyProtocol, definitions.ProtoOIDC)

			// Explicitly save cookie before redirect to ensure it's written to the response
			if err := mgr.Save(ctx); err != nil {
				ctx.String(http.StatusInternalServerError, "Failed to save session")

				return
			}

			mgr.Debug(ctx, h.deps.Logger, "OIDC flow state stored in cookie - redirecting to login")
		}

		ctx.Redirect(http.StatusFound, "/login")

		return
	}

	// User is logged in.
	user, err := h.idp.GetUserByUsername(ctx, account, clientID, "")
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Internal error loading user details")

		return
	}

	requestedScopes := strings.Split(scope, " ")
	filteredScopes := h.idp.FilterScopes(client, requestedScopes)

	idTokenClaims, accessTokenClaims, err := h.idp.GetClaims(ctx, user, client, filteredScopes)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Internal error mapping claims")

		return
	}

	oidcSession := &idp.OIDCSession{
		ClientID:          clientID,
		UserID:            user.Id,
		Username:          user.Name,
		DisplayName:       user.DisplayName,
		Scopes:            filteredScopes,
		RedirectURI:       redirectURI,
		AuthTime:          time.Now(),
		Nonce:             nonce,
		IdTokenClaims:     idTokenClaims,
		AccessTokenClaims: accessTokenClaims,
	}

	// Check if consent is needed
	needsConsent := !client.SkipConsent && !hasClientConsent(mgr, clientID)
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

	addClientToCookie(mgr, clientID)

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

// handleAuthorizationCodeTokenExchange processes the authorization_code grant type
// within the token endpoint.
func (h *OIDCHandler) handleAuthorizationCodeTokenExchange(ctx *gin.Context, client *config.OIDCClient, grantType string) {
	clientID := client.ClientID
	code := ctx.PostForm("code")

	session, getErr := h.storage.GetSession(ctx.Request.Context(), code)
	if getErr != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})

		return
	}

	// Delete code after one-time use
	_ = h.storage.DeleteSession(ctx.Request.Context(), code)

	if session.ClientID != clientID {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})

		return
	}

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
	rt := ctx.PostForm("refresh_token")

	idToken, accessToken, refreshToken, expiresIn, err := h.idp.ExchangeRefreshToken(ctx.Request.Context(), rt, clientID)
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

// ConsentGET handles the OIDC consent request.
func (h *OIDCHandler) ConsentGET(ctx *gin.Context) {
	consentChallenge := ctx.Query("consent_challenge")
	state := ctx.Query("state")

	session, err := h.storage.GetSession(ctx.Request.Context(), "consent:"+consentChallenge)
	if err != nil {
		ctx.String(http.StatusBadRequest, "Invalid consent challenge")

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

	data["ClientID"] = session.ClientID
	data["Scopes"] = session.Scopes
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

	consentChallenge := ctx.PostForm("consent_challenge")
	state := ctx.PostForm("state")
	if state == "" {
		state = ctx.Query("state")
	}
	submit := ctx.PostForm("submit")

	session, err := h.storage.GetSession(ctx.Request.Context(), "consent:"+consentChallenge)
	if err != nil {
		ctx.String(http.StatusBadRequest, "Invalid consent challenge")

		return
	}

	sp.SetAttributes(attribute.String("client_id", session.ClientID))

	if submit != "allow" {
		// Denied
		_ = h.storage.DeleteSession(ctx.Request.Context(), "consent:"+consentChallenge)
		stats.GetMetrics().GetIdpConsentTotal().WithLabelValues(session.ClientID, "deny").Inc()
		ctx.String(http.StatusForbidden, "Consent denied")

		return
	}

	stats.GetMetrics().GetIdpConsentTotal().WithLabelValues(session.ClientID, "allow").Inc()

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
		addClientToCookie(mgr, session.ClientID)
		mgr.Debug(ctx, h.deps.Logger, "OIDC consent granted - client added to session")
	}

	ctx.Redirect(http.StatusFound, target)
}
