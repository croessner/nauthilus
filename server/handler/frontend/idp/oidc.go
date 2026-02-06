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
	"context"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/core/cookie"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/frontend"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/idp"
	"github.com/croessner/nauthilus/server/middleware/i18n"
	mdlua "github.com/croessner/nauthilus/server/middleware/lua"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/gwatts/gin-adapter"
	"github.com/justinas/nosurf"
	"github.com/segmentio/ksuid"
	"go.opentelemetry.io/otel/attribute"
)

// OIDCHandler handles OIDC protocol requests.
type OIDCHandler struct {
	deps    *deps.Deps
	idp     *idp.NauthilusIdP
	storage *idp.RedisTokenStorage
	tracer  monittrace.Tracer
}

// NewOIDCHandler creates a new OIDCHandler.
func NewOIDCHandler(d *deps.Deps, idpInstance *idp.NauthilusIdP) *OIDCHandler {
	return &OIDCHandler{
		deps:    d,
		idp:     idpInstance,
		storage: idp.NewRedisTokenStorage(d.Redis, d.Cfg.GetServer().GetRedis().GetPrefix()),
		tracer:  monittrace.New("nauthilus/idp/oidc"),
	}
}

// Register registers the OIDC routes.
func (h *OIDCHandler) Register(router gin.IRouter) {
	router.Use(func(ctx *gin.Context) {
		ctx.Set(definitions.CtxServiceKey, definitions.ServIdP)
		ctx.Next()
	}, mdlua.LuaContextMiddleware())

	secureMW := cookie.Middleware(h.deps.Cfg.GetServer().GetFrontend().GetEncryptionSecret(), h.deps.Cfg, h.deps.Env)
	i18nMW := i18n.WithLanguage(h.deps.Cfg, h.deps.Logger, h.deps.LangManager)
	csrfMW := adapter.Wrap(nosurf.NewPure)

	router.GET("/.well-known/openid-configuration", h.Discovery)
	router.GET("/oidc/authorize", secureMW, i18nMW, h.Authorize)
	router.GET("/oidc/authorize/:languageTag", secureMW, i18nMW, h.Authorize)
	router.POST("/oidc/token", h.Token)
	router.GET("/oidc/userinfo", h.UserInfo)
	router.POST("/oidc/introspect", h.Introspect)
	router.GET("/oidc/jwks", h.JWKS)
	router.GET("/oidc/logout", secureMW, h.Logout)
	router.GET("/logout", secureMW, h.Logout)
	router.GET("/oidc/consent", csrfMW, secureMW, i18nMW, h.ConsentGET)
	router.GET("/oidc/consent/:languageTag", csrfMW, secureMW, i18nMW, h.ConsentGET)
	router.POST("/oidc/consent", csrfMW, secureMW, i18nMW, h.ConsentPOST)
	router.POST("/oidc/consent/:languageTag", csrfMW, secureMW, i18nMW, h.ConsentPOST)
}

// Discovery returns the OIDC discovery document.
func (h *OIDCHandler) Discovery(ctx *gin.Context) {
	oidcCfg := h.deps.Cfg.GetIdP().OIDC
	issuer := oidcCfg.Issuer

	scopesSupported := oidcCfg.GetScopesSupported()

	for _, customScope := range oidcCfg.CustomScopes {
		scopesSupported = append(scopesSupported, customScope.Name)
	}

	ctx.JSON(http.StatusOK, gin.H{
		"issuer":                                        issuer,
		"authorization_endpoint":                        issuer + "/oidc/authorize",
		"token_endpoint":                                issuer + "/oidc/token",
		"introspection_endpoint":                        issuer + "/oidc/introspect",
		"userinfo_endpoint":                             issuer + "/oidc/userinfo",
		"jwks_uri":                                      issuer + "/oidc/jwks",
		"end_session_endpoint":                          issuer + "/oidc/logout",
		"frontchannel_logout_supported":                 oidcCfg.GetFrontChannelLogoutSupported(),
		"frontchannel_logout_session_supported":         oidcCfg.GetFrontChannelLogoutSessionSupported(),
		"backchannel_logout_supported":                  oidcCfg.GetBackChannelLogoutSupported(),
		"backchannel_logout_session_supported":          oidcCfg.GetBackChannelLogoutSessionSupported(),
		"response_types_supported":                      oidcCfg.GetResponseTypesSupported(),
		"subject_types_supported":                       oidcCfg.GetSubjectTypesSupported(),
		"id_token_signing_alg_values_supported":         oidcCfg.GetIDTokenSigningAlgValuesSupported(),
		"scopes_supported":                              scopesSupported,
		"token_endpoint_auth_methods_supported":         oidcCfg.GetTokenEndpointAuthMethodsSupported(),
		"introspection_endpoint_auth_methods_supported": oidcCfg.GetTokenEndpointAuthMethodsSupported(),
		"claims_supported":                              oidcCfg.GetClaimsSupported(),
	})
}

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

	claims, err := h.idp.GetClaims(ctx, user, client, filteredScopes)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Internal error mapping claims")

		return
	}

	oidcSession := &idp.OIDCSession{
		ClientID:    clientID,
		UserID:      user.Id,
		Username:    user.Name,
		DisplayName: user.DisplayName,
		Scopes:      filteredScopes,
		RedirectURI: redirectURI,
		AuthTime:    time.Now(),
		Nonce:       nonce,
		Claims:      claims,
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

// authenticateClient extracts and authenticates the OIDC client.
func (h *OIDCHandler) authenticateClient(ctx *gin.Context) (*config.OIDCClient, bool) {
	var clientID, clientSecret string

	var authSource string

	// 1. Try Basic Auth
	if hClientID, hClientSecret, ok := ctx.Request.BasicAuth(); ok {
		if uClientID, err := url.QueryUnescape(hClientID); err == nil {
			clientID = uClientID
		} else {
			clientID = hClientID
		}

		if uClientSecret, err := url.QueryUnescape(hClientSecret); err == nil {
			clientSecret = uClientSecret
		} else {
			clientSecret = hClientSecret
		}

		authSource = "client_secret_basic"
	}

	// 2. Try Body
	bClientID := ctx.PostForm("client_id")
	bClientSecret := ctx.PostForm("client_secret")

	if bClientID != "" || bClientSecret != "" {
		if authSource != "" {
			util.DebugModuleWithCfg(
				ctx.Request.Context(),
				h.deps.Cfg,
				h.deps.Logger,
				definitions.DbgIdp,
				definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
				definitions.LogKeyMsg, "Multiple OIDC client authentication methods used",
				"methods", authSource+",client_secret_post",
			)

			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})

			return nil, false
		}

		clientID = bClientID
		clientSecret = bClientSecret
		authSource = "client_secret_post"
	}

	if clientID == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})

		return nil, false
	}

	client, ok := h.idp.FindClient(clientID)
	if !ok {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "OIDC client not found",
			"client_id", clientID,
		)

		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})

		return nil, false
	}

	// Enforce TokenEndpointAuthMethod if configured
	if client.TokenEndpointAuthMethod != "" {
		allowed := false
		switch client.TokenEndpointAuthMethod {
		case "client_secret_basic":
			if authSource == "client_secret_basic" {
				allowed = true
			}
		case "client_secret_post":
			if authSource == "client_secret_post" {
				allowed = true
			}
		case "none":
			if authSource == "" {
				allowed = true
			}
		default:
			// If unknown, default to allowing existing behavior (basic or post)
			allowed = (authSource == "client_secret_basic" || authSource == "client_secret_post")
		}

		if !allowed {
			util.DebugModuleWithCfg(
				ctx.Request.Context(),
				h.deps.Cfg,
				h.deps.Logger,
				definitions.DbgIdp,
				definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
				definitions.LogKeyMsg, "OIDC client authentication method not allowed",
				"client_id", clientID,
				"auth_source", authSource,
				"expected_method", client.TokenEndpointAuthMethod,
			)

			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})

			return nil, false
		}
	}

	if client.ClientSecret != clientSecret {
		keyvals := []any{
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "OIDC client secret mismatch",
			"client_id", clientID,
			"expected_len", len(client.ClientSecret),
			"received_len", len(clientSecret),
		}

		if clientSecret == "secret" {
			keyvals = append(keyvals, "hint", "Client sent literal string 'secret' - check client configuration")
		}

		if strings.TrimSpace(clientSecret) != clientSecret {
			keyvals = append(keyvals, "hint", "Received secret contains leading/trailing whitespace")
		}

		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			keyvals...,
		)

		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})

		return nil, false
	}

	return client, true
}

// Token handles the OIDC token request.
func (h *OIDCHandler) Token(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "oidc.token")
	defer sp.End()

	grantType := ctx.PostForm("grant_type")

	client, ok := h.authenticateClient(ctx)
	if !ok {
		return
	}

	clientID := client.ClientID

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "OIDC Token request",
		"grant_type", grantType,
		"client_id", clientID,
	)

	sp.SetAttributes(attribute.String("client_id", clientID))

	var idToken, accessToken, refreshToken string

	var expiresIn time.Duration

	var err error

	switch grantType {
	case "authorization_code":
		code := ctx.PostForm("code")

		session, err := h.storage.GetSession(ctx.Request.Context(), code)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})

			return
		}

		// Delete code after one-time use
		_ = h.storage.DeleteSession(ctx.Request.Context(), code)

		if session.ClientID != clientID {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})

			return
		}

		idToken, accessToken, refreshToken, expiresIn, err = h.idp.IssueTokens(ctx.Request.Context(), session)

	case "refresh_token":
		rt := ctx.PostForm("refresh_token")
		idToken, accessToken, refreshToken, expiresIn, err = h.idp.ExchangeRefreshToken(ctx.Request.Context(), rt, clientID)

	default:
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})

		return
	}

	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})

		return
	}

	stats.GetMetrics().GetIdpTokensIssuedTotal().WithLabelValues("oidc", clientID, grantType).Inc()

	resp := gin.H{
		"access_token": accessToken,
		"id_token":     idToken,
		"token_type":   "Bearer",
		"expires_in":   int(expiresIn.Seconds()),
	}

	if refreshToken != "" {
		resp["refresh_token"] = refreshToken
	}

	ctx.JSON(http.StatusOK, resp)
}

// UserInfo handles the OIDC userinfo request.
func (h *OIDCHandler) UserInfo(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "oidc.userinfo")
	defer sp.End()

	authHeader := ctx.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "missing_token"})

		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Validate token
	claims, err := h.idp.ValidateToken(ctx.Request.Context(), tokenString)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})

		return
	}

	// Return user info from token claims
	ctx.JSON(http.StatusOK, claims)
}

// Introspect handles the OIDC token introspection request.
func (h *OIDCHandler) Introspect(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "oidc.introspect")
	defer sp.End()

	client, ok := h.authenticateClient(ctx)
	if !ok {
		return
	}

	token := ctx.PostForm("token")
	if token == "" {
		ctx.JSON(http.StatusOK, gin.H{"active": false})

		return
	}

	claims, err := h.idp.ValidateToken(ctx.Request.Context(), token)
	if err != nil {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "OIDC token introspection failed",
			"error", err,
		)

		ctx.JSON(http.StatusOK, gin.H{"active": false})

		return
	}

	// Verify that the token was issued to the client making the request,
	// or that the client is otherwise authorized to introspect this token.
	if aud, ok := claims["aud"].(string); ok && aud != client.ClientID {
		ctx.JSON(http.StatusOK, gin.H{"active": false})

		return
	}

	response := gin.H{
		"active": true,
	}

	for k, v := range claims {
		response[k] = v
	}

	ctx.JSON(http.StatusOK, response)
}

// JWKS handles the OIDC JWKS request.
func (h *OIDCHandler) JWKS(ctx *gin.Context) {
	allKeys, err := h.idp.GetKeyManager().GetAllKeys(ctx.Request.Context())
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get keys"})

		return
	}

	var keys []gin.H

	for kid, key := range allKeys {
		publicKey := key.PublicKey
		n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

		keys = append(keys, gin.H{
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"kid": kid,
			"n":   n,
			"e":   e,
		})
	}

	ctx.JSON(http.StatusOK, gin.H{
		"keys": keys,
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
	data["CSRFToken"] = nosurf.Token(ctx.Request)

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

func (h *OIDCHandler) calculateLogoutTarget(client *config.OIDCClient, sessionClients []string) string {
	if client != nil && client.LogoutRedirectURI != "" {
		return client.LogoutRedirectURI
	}

	if len(sessionClients) == 1 {
		if c, ok := h.idp.FindClient(sessionClients[0]); ok && c.LogoutRedirectURI != "" {
			return c.LogoutRedirectURI
		}
	}

	return "/logged_out"
}

// Logout handles the OIDC logout request.
func (h *OIDCHandler) Logout(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "oidc.logout")
	defer sp.End()

	idTokenHint := ctx.Query("id_token_hint")
	postLogoutRedirectURI := ctx.Query("post_logout_redirect_uri")
	state := ctx.Query("state")

	mgr := cookie.GetManager(ctx)
	account := ""
	uniqueUserID := ""

	if mgr != nil {
		account = mgr.GetString(definitions.SessionKeyAccount, "")
		uniqueUserID = mgr.GetString(definitions.SessionKeyUniqueUserID, "")
	}

	userID := ""
	if uniqueUserID != "" {
		userID = uniqueUserID
	} else if account != "" {
		userID = account
	}

	// Validate id_token_hint if provided
	var client *config.OIDCClient

	if idTokenHint != "" {
		claims, err := h.idp.ValidateToken(ctx.Request.Context(), idTokenHint)
		if err == nil {
			if cid, ok := claims["aud"].(string); ok {
				client, _ = h.idp.FindClient(cid)
			}

			if userID == "" {
				if sub, ok := claims["sub"].(string); ok {
					userID = sub
				}
			}
		}
	}

	if userID != "" {
		_ = h.storage.DeleteUserRefreshTokens(ctx.Request.Context(), userID)
	}

	// Get clients to logout from
	oidcClients := ""
	if mgr != nil {
		oidcClients = mgr.GetString(definitions.SessionKeyOIDCClients, "")
		mgr.Debug(ctx, h.deps.Logger, "OIDC logout initiated - session data before cleanup")
	}

	var clientIDs []string

	if oidcClients != "" {
		clientIDs = strings.Split(oidcClients, ",")
	}

	var frontChannelURIs []string

	for _, cid := range clientIDs {
		c, ok := h.idp.FindClient(cid)
		if !ok {
			continue
		}

		// Back-channel logout
		if c.BackChannelLogoutURI != "" && userID != "" {
			go h.doBackChannelLogout(cid, userID, c.BackChannelLogoutURI)
		}

		// Front-channel logout
		if c.FrontChannelLogoutURI != "" {
			uri := c.FrontChannelLogoutURI
			// In a real implementation, we could add sid here if required
			frontChannelURIs = append(frontChannelURIs, uri)
		}
	}

	// Redirect or show logout page
	if client != nil && postLogoutRedirectURI != "" {
		if h.idp.ValidatePostLogoutRedirectURI(client, postLogoutRedirectURI) {
			target := postLogoutRedirectURI

			if state != "" {
				if strings.Contains(target, "?") {
					target += "&state=" + url.QueryEscape(state)
				} else {
					target += "?state=" + url.QueryEscape(state)
				}
			}

			core.SessionCleaner(ctx)
			core.ClearBrowserCookies(ctx)

			ctx.Redirect(http.StatusFound, target)

			return
		}
	}

	if len(frontChannelURIs) > 0 {
		data := BasePageData(ctx, h.deps.Cfg, h.deps.LangManager)
		data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Logout")
		data["LoggingOutFromAllApplications"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Logging out from all applications...")
		data["PleaseWaitWhileLogoutProcessIsCompleted"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please wait while the logout process is completed.")
		data["FrontChannelLogoutURIs"] = frontChannelURIs
		data["LogoutTarget"] = h.calculateLogoutTarget(client, clientIDs)

		core.SessionCleaner(ctx)
		core.ClearBrowserCookies(ctx)

		ctx.HTML(http.StatusOK, "idp_logout_frames.html", data)

		return
	}

	core.SessionCleaner(ctx)
	core.ClearBrowserCookies(ctx)

	ctx.Redirect(http.StatusFound, h.calculateLogoutTarget(client, clientIDs))
}

func (h *OIDCHandler) doBackChannelLogout(clientID, userID, logoutURI string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	token, err := h.idp.IssueLogoutToken(ctx, clientID, userID)
	if err != nil {
		return
	}

	form := url.Values{}
	form.Set("logout_token", token)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, logoutURI, strings.NewReader(form.Encode()))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}

	defer resp.Body.Close()
}
