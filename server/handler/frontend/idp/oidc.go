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
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/frontend"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/idp"
	"github.com/croessner/nauthilus/server/middleware/i18n"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/segmentio/ksuid"
	"go.opentelemetry.io/otel/attribute"
)

// OIDCHandler handles OIDC protocol requests.
type OIDCHandler struct {
	deps    *deps.Deps
	idp     *idp.NauthilusIdP
	store   sessions.Store
	storage *idp.RedisTokenStorage
	tracer  monittrace.Tracer
}

// NewOIDCHandler creates a new OIDCHandler.
func NewOIDCHandler(sessStore sessions.Store, d *deps.Deps, idpInstance *idp.NauthilusIdP) *OIDCHandler {
	return &OIDCHandler{
		deps:    d,
		idp:     idpInstance,
		store:   sessStore,
		storage: idp.NewRedisTokenStorage(d.Redis, d.Cfg.GetServer().GetRedis().GetPrefix()),
		tracer:  monittrace.New("nauthilus/idp/oidc"),
	}
}

// Register registers the OIDC routes.
func (h *OIDCHandler) Register(router gin.IRouter) {
	sessionMW := sessions.Sessions(definitions.SessionName, h.store)
	i18nMW := i18n.WithLanguage(h.deps.Cfg, h.deps.Logger)

	router.GET("/.well-known/openid-configuration", h.Discovery)
	router.GET("/oidc/authorize", sessionMW, i18nMW, h.Authorize)
	router.GET("/oidc/authorize/:languageTag", sessionMW, i18nMW, h.Authorize)
	router.POST("/oidc/token", h.Token)
	router.GET("/oidc/userinfo", h.UserInfo)
	router.GET("/oidc/jwks", h.JWKS)
	router.GET("/oidc/logout", sessionMW, h.Logout)
	router.GET("/oidc/consent", sessionMW, i18nMW, h.ConsentGET)
	router.GET("/oidc/consent/:languageTag", sessionMW, i18nMW, h.ConsentGET)
	router.POST("/oidc/consent", sessionMW, i18nMW, h.ConsentPOST)
	router.POST("/oidc/consent/:languageTag", sessionMW, i18nMW, h.ConsentPOST)
}

// Discovery returns the OIDC discovery document.
func (h *OIDCHandler) Discovery(ctx *gin.Context) {
	issuer := h.deps.Cfg.GetIdP().OIDC.Issuer
	ctx.JSON(http.StatusOK, gin.H{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oidc/authorize",
		"token_endpoint":                        issuer + "/oidc/token",
		"userinfo_endpoint":                     issuer + "/oidc/userinfo",
		"jwks_uri":                              issuer + "/oidc/jwks",
		"end_session_endpoint":                  issuer + "/oidc/logout",
		"frontchannel_logout_supported":         true,
		"frontchannel_logout_session_supported": false,
		"backchannel_logout_supported":          true,
		"backchannel_logout_session_supported":  false,
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"claims_supported":                      []string{"sub", "name", "preferred_username", "email"},
	})
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

	session := sessions.Default(ctx)
	account := session.Get(definitions.CookieAccount)

	clientID := ctx.Query("client_id")
	redirectURI := ctx.Query("redirect_uri")
	scope := ctx.Query("scope")
	state := ctx.Query("state")
	responseType := ctx.Query("response_type")

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

	if account == nil {
		// User not logged in, redirect to login page
		loginURL := "/login"
		// Append original request to return_to
		originalURL := ctx.Request.URL.String()
		ctx.Redirect(http.StatusFound, loginURL+"?return_to="+url.QueryEscape(originalURL))

		return
	}

	// User is logged in.
	user, err := h.idp.GetUserByUsername(ctx, account.(string), clientID, "")
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Internal error loading user details")

		return
	}

	claims, err := h.idp.GetClaims(user, client)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Internal error mapping claims")

		return
	}

	// Check if consent is needed
	oidcSession := &idp.OIDCSession{
		ClientID:    clientID,
		UserID:      user.Id,
		Username:    user.Name,
		DisplayName: user.DisplayName,
		Scopes:      strings.Split(scope, " "),
		RedirectURI: redirectURI,
		AuthTime:    time.Now(),
		Claims:      claims,
	}

	if !client.SkipConsent {
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

	h.addClientToSession(session, clientID)

	// Redirect back to client
	target := fmt.Sprintf("%s?code=%s", redirectURI, code)
	if state != "" {
		target += "&state=" + url.QueryEscape(state)
	}

	ctx.Redirect(http.StatusFound, target)
}

// Token handles the OIDC token request.
func (h *OIDCHandler) Token(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "oidc.token")
	defer sp.End()

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "OIDC Token request",
		"grant_type", ctx.PostForm("grant_type"),
		"client_id", ctx.PostForm("client_id"),
	)

	grantType := ctx.PostForm("grant_type")
	code := ctx.PostForm("code")
	clientID := ctx.PostForm("client_id")
	clientSecret := ctx.PostForm("client_secret")

	// Fallback to Basic Auth if not in post form
	if clientID == "" {
		var ok bool
		clientID, clientSecret, ok = ctx.Request.BasicAuth()

		if !ok {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})

			return
		}
	}

	sp.SetAttributes(attribute.String("client_id", clientID))

	if grantType != "authorization_code" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})

		return
	}

	client, ok := h.idp.FindClient(clientID)
	if !ok || client.ClientSecret != clientSecret {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})

		return
	}

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

	idToken, accessToken, err := h.idp.IssueTokens(ctx.Request.Context(), session)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})

		return
	}

	stats.GetMetrics().GetIdpTokensIssuedTotal().WithLabelValues("oidc", clientID, grantType).Inc()

	ctx.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
		"id_token":     idToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
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

// JWKS handles the OIDC JWKS request.
func (h *OIDCHandler) JWKS(ctx *gin.Context) {
	signingKey := h.deps.Cfg.GetIdP().OIDC.SigningKey
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(signingKey))

	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse signing key"})

		return
	}

	publicKey := key.PublicKey
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

	ctx.JSON(http.StatusOK, gin.H{
		"keys": []gin.H{
			{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": "default",
				"n":   n,
				"e":   e,
			},
		},
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

	data := BasePageData(ctx, h.deps.Cfg)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Consent")
	data["Application"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Application")
	data["WantsToAccessYourAccount"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "wants to access your account")
	data["RequestedPermissions"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Requested permissions")
	data["Allow"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Allow")
	data["Deny"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Deny")

	data["ClientID"] = session.ClientID
	data["Scopes"] = session.Scopes
	data["ConsentChallenge"] = consentChallenge
	data["State"] = state
	data["CSRFToken"] = "TODO_CSRF"

	ctx.HTML(http.StatusOK, "idp_consent.html", data)
}

// ConsentPOST handles the OIDC consent submission.
func (h *OIDCHandler) ConsentPOST(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "oidc.consent_post")
	defer sp.End()

	consentChallenge := ctx.PostForm("consent_challenge")
	state := ctx.PostForm("state")
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

	h.addClientToSession(sessions.Default(ctx), session.ClientID)

	ctx.Redirect(http.StatusFound, target)
}

func (h *OIDCHandler) addClientToSession(session sessions.Session, clientID string) {
	clientsRaw := session.Get(definitions.CookieOIDCClients)

	var clients []string

	if clientsRaw != nil {
		clients = strings.Split(clientsRaw.(string), ",")
	}

	for _, c := range clients {
		if c == clientID {
			return
		}
	}

	clients = append(clients, clientID)

	session.Set(definitions.CookieOIDCClients, strings.Join(clients, ","))

	_ = session.Save()
}

// Logout handles the OIDC logout request.
func (h *OIDCHandler) Logout(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "oidc.logout")
	defer sp.End()

	idTokenHint := ctx.Query("id_token_hint")
	postLogoutRedirectURI := ctx.Query("post_logout_redirect_uri")
	state := ctx.Query("state")

	session := sessions.Default(ctx)
	account := session.Get(definitions.CookieAccount)

	userID := ""
	if account != nil {
		userID = account.(string)
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

	// Get clients to logout from
	clientsRaw := session.Get(definitions.CookieOIDCClients)

	var clientIDs []string

	if clientsRaw != nil {
		clientIDs = strings.Split(clientsRaw.(string), ",")
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

			session.Clear()

			_ = session.Save()

			ctx.Redirect(http.StatusFound, target)

			return
		}
	}

	if len(frontChannelURIs) > 0 {
		data := BasePageData(ctx, h.deps.Cfg)
		data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Logout")
		data["LoggingOutFromAllApplications"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Logging out from all applications...")
		data["PleaseWaitWhileLogoutProcessIsCompleted"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please wait while the logout process is completed.")
		data["FrontChannelLogoutURIs"] = frontChannelURIs

		session.Clear()

		_ = session.Save()

		ctx.HTML(http.StatusOK, "idp_logout_frames.html", data)

		return
	}

	session.Clear()

	_ = session.Save()

	ctx.Redirect(http.StatusFound, "/idp/login")
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
