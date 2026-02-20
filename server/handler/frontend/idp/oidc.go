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
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
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
	"github.com/croessner/nauthilus/server/idp/clientauth"
	"github.com/croessner/nauthilus/server/idp/signing"
	"github.com/croessner/nauthilus/server/middleware/csrf"
	"github.com/croessner/nauthilus/server/middleware/i18n"
	mdlua "github.com/croessner/nauthilus/server/middleware/lua"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
)

// formValue retrieves a request parameter from either the POST body or the URL
// query string. This allows token-endpoint handlers to work with both POST and
// GET requests (some OIDC clients, e.g. Roundcube, use GET for /oidc/token).
func formValue(ctx *gin.Context, key string) string {
	return ctx.Request.FormValue(key)
}

// OIDCHandler handles OIDC protocol requests.
type OIDCHandler struct {
	deps        *deps.Deps
	idp         *idp.NauthilusIdP
	storage     *idp.RedisTokenStorage
	deviceStore idp.DeviceCodeStore
	userCodeGen idp.UserCodeGenerator
	frontend    *FrontendHandler
	tracer      monittrace.Tracer
}

// NewOIDCHandler creates a new OIDCHandler.
func NewOIDCHandler(d *deps.Deps, idpInstance *idp.NauthilusIdP, frontendHandler *FrontendHandler) *OIDCHandler {
	prefix := d.Cfg.GetServer().GetRedis().GetPrefix()

	return &OIDCHandler{
		deps:        d,
		idp:         idpInstance,
		storage:     idp.NewRedisTokenStorage(d.Redis, prefix),
		deviceStore: idp.NewRedisDeviceCodeStore(d.Redis, prefix),
		userCodeGen: &idp.DefaultUserCodeGenerator{},
		frontend:    frontendHandler,
		tracer:      monittrace.New("nauthilus/idp/oidc"),
	}
}

// Register registers the OIDC routes.
func (h *OIDCHandler) Register(router gin.IRouter) {
	router.Use(func(ctx *gin.Context) {
		ctx.Set(definitions.CtxServiceKey, definitions.ServIdP)
		ctx.Next()
	}, mdlua.LuaContextMiddleware())

	var frontendSecret []byte
	h.deps.Cfg.GetServer().GetFrontend().GetEncryptionSecret().WithBytes(func(value []byte) {
		if len(value) == 0 {
			return
		}

		frontendSecret = bytes.Clone(value)
	})
	secureMW := cookie.Middleware(frontendSecret, h.deps.Cfg, h.deps.Env)
	i18nMW := i18n.WithLanguage(h.deps.Cfg, h.deps.Logger, h.deps.LangManager)
	csrfMW := csrf.New()

	router.GET("/.well-known/openid-configuration", h.Discovery)
	router.GET("/oidc/authorize", secureMW, i18nMW, h.Authorize)
	router.GET("/oidc/authorize/:languageTag", secureMW, i18nMW, h.Authorize)
	router.POST("/oidc/token", h.Token)
	router.GET("/oidc/token", h.Token)
	router.GET("/oidc/userinfo", h.UserInfo)
	router.POST("/oidc/introspect", h.Introspect)
	router.GET("/oidc/jwks", h.JWKS)
	router.POST("/oidc/device", h.DeviceAuthorization)
	router.GET("/oidc/device/verify", csrfMW, secureMW, i18nMW, h.DeviceVerifyPage)
	router.GET("/oidc/device/verify/:languageTag", csrfMW, secureMW, i18nMW, h.DeviceVerifyPage)
	router.POST("/oidc/device/verify", csrfMW, secureMW, i18nMW, h.DeviceVerify)
	router.POST("/oidc/device/verify/:languageTag", csrfMW, secureMW, i18nMW, h.DeviceVerify)
	router.GET("/oidc/device/consent", csrfMW, secureMW, i18nMW, h.DeviceConsentGET)
	router.GET("/oidc/device/consent/:languageTag", csrfMW, secureMW, i18nMW, h.DeviceConsentGET)
	router.POST("/oidc/device/consent", csrfMW, secureMW, i18nMW, h.DeviceConsentPOST)
	router.POST("/oidc/device/consent/:languageTag", csrfMW, secureMW, i18nMW, h.DeviceConsentPOST)
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
		"device_authorization_endpoint":                 issuer + "/oidc/device",
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
	bClientID := formValue(ctx, "client_id")
	bClientSecret := formValue(ctx, "client_secret")

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
			allowed = authSource == "client_secret_basic" || authSource == "client_secret_post"
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

	var expectedSecret []byte
	client.ClientSecret.WithBytes(func(value []byte) {
		if len(value) == 0 {
			return
		}

		expectedSecret = bytes.Clone(value)
	})

	receivedSecret := []byte(clientSecret)
	if subtle.ConstantTimeCompare(expectedSecret, receivedSecret) != 1 {
		keyvals := []any{
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "OIDC client secret mismatch",
			"client_id", clientID,
			"expected_len", len(expectedSecret),
			"received_len", len(receivedSecret),
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

// authenticateClientPrivateKeyJWT authenticates a client using the private_key_jwt method (RFC 7523).
func (h *OIDCHandler) authenticateClientPrivateKeyJWT(ctx *gin.Context) (*config.OIDCClient, bool) {
	assertionType := formValue(ctx, "client_assertion_type")
	assertion := formValue(ctx, "client_assertion")
	clientID := formValue(ctx, "client_id")

	if assertionType == "" || assertion == "" {
		return nil, false
	}

	if assertionType != clientauth.AssertionTypeJWTBearer {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "unsupported client_assertion_type"})

		return nil, false
	}

	// If client_id not in form, try to extract from the assertion's iss claim
	if clientID == "" {
		clientID = extractIssFromJWT(assertion)
	}

	if clientID == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})

		return nil, false
	}

	client, ok := h.idp.FindClient(clientID)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})

		return nil, false
	}

	if client.TokenEndpointAuthMethod != clientauth.MethodPrivateKeyJWT {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client", "error_description": "client not configured for private_key_jwt"})

		return nil, false
	}

	verifier, err := h.buildClientVerifier(client)
	if err != nil {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "Failed to build client verifier",
			"client_id", clientID,
			"error", err,
		)

		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})

		return nil, false
	}

	tokenEndpoint := h.deps.Cfg.GetIdP().OIDC.Issuer + "/oidc/token"
	auth := clientauth.NewPrivateKeyJWTAuthenticator(verifier, clientID, tokenEndpoint)

	err = auth.Authenticate(&clientauth.AuthRequest{
		ClientID:            clientID,
		ClientAssertionType: assertionType,
		ClientAssertion:     assertion,
		TokenEndpointURL:    tokenEndpoint,
	})

	if err != nil {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "private_key_jwt authentication failed",
			"client_id", clientID,
			"error", err,
		)

		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})

		return nil, false
	}

	return client, true
}

// buildClientVerifier creates a signing.Verifier for the client's public key.
func (h *OIDCHandler) buildClientVerifier(client *config.OIDCClient) (signing.Verifier, error) {
	pemData, err := client.GetClientPublicKey()
	if err != nil || pemData == "" {
		return nil, fmt.Errorf("no public key configured for client %s", client.ClientID)
	}

	algorithm := client.GetClientPublicKeyAlgorithm()

	switch algorithm {
	case signing.AlgorithmRS256:
		key, err := signing.ParseRSAPublicKeyPEM(pemData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
		}

		return signing.NewRS256Verifier(key), nil

	case signing.AlgorithmEdDSA:
		key, err := signing.ParseEd25519PublicKeyPEM(pemData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Ed25519 public key: %w", err)
		}

		return signing.NewEdDSAVerifier(key), nil

	default:
		return nil, fmt.Errorf("unsupported client public key algorithm: %s", algorithm)
	}
}

// extractIssFromJWT extracts the iss claim from a JWT without full verification.
func extractIssFromJWT(tokenString string) string {
	parts := strings.SplitN(tokenString, ".", 3)
	if len(parts) < 2 {
		return ""
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}

	// Simple JSON extraction without full parse
	var claims map[string]any

	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}

	iss, _ := claims["iss"].(string)

	return iss
}

// tokenResponse holds the result of a token exchange operation.
type tokenResponse struct {
	idToken      string
	accessToken  string
	refreshToken string
	expiresIn    time.Duration
}

// logTokenError logs a token issuance failure and responds with a server error.
func (h *OIDCHandler) logTokenError(ctx *gin.Context, grantType, clientID string, err error) {
	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "OIDC Token issuance failed",
		"grant_type", grantType,
		"client_id", clientID,
		"error", err,
	)

	ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
}

// sendTokenResponse writes the common OIDC token response JSON.
func (h *OIDCHandler) sendTokenResponse(ctx *gin.Context, clientID, grantType string, resp *tokenResponse) {
	stats.GetMetrics().GetIdpTokensIssuedTotal().WithLabelValues("oidc", clientID, grantType).Inc()

	result := gin.H{
		"access_token": resp.accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(resp.expiresIn.Seconds()),
	}

	// Per OIDC Core 1.0 §3.1.2.1: id_token is only present when "openid" scope was requested.
	// Client Credentials Grant also never returns an id_token (RFC 6749 §4.4).
	if resp.idToken != "" {
		result["id_token"] = resp.idToken
	}

	if resp.refreshToken != "" {
		result["refresh_token"] = resp.refreshToken
	}

	ctx.JSON(http.StatusOK, result)
}

// Token handles the OIDC token request.
func (h *OIDCHandler) Token(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "oidc.token")
	defer sp.End()

	grantType := formValue(ctx, "grant_type")

	// Try private_key_jwt first if client_assertion is present
	var client *config.OIDCClient
	var ok bool

	if formValue(ctx, "client_assertion") != "" {
		client, ok = h.authenticateClientPrivateKeyJWT(ctx)
	} else {
		client, ok = h.authenticateClient(ctx)
	}

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

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeTokenExchange(ctx, client, grantType)

	case "refresh_token":
		h.handleRefreshTokenExchange(ctx, client, grantType)

	case "client_credentials":
		h.handleClientCredentialsTokenExchange(ctx, client, grantType)

	case definitions.OIDCGrantTypeDeviceCode:
		if !client.SupportsGrantType(definitions.OIDCGrantTypeDeviceCode) {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "unauthorized_client"})

			return
		}

		h.handleDeviceCodeTokenExchange(ctx, client)

	default:
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
	}
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
	var keys []gin.H

	rsaKeys, err := h.idp.GetKeyManager().GetAllKeys(ctx.Request.Context())
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get keys"})

		return
	}

	for kid, key := range rsaKeys {
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

	edKeys, err := h.idp.GetKeyManager().GetAllEdKeys(ctx.Request.Context())
	if err == nil {
		for kid, key := range edKeys {
			pubKey := key.Public().(ed25519.PublicKey)
			x := base64.RawURLEncoding.EncodeToString(pubKey)

			keys = append(keys, gin.H{
				"kty": "OKP",
				"alg": "EdDSA",
				"use": "sig",
				"kid": kid,
				"crv": "Ed25519",
				"x":   x,
			})
		}
	}

	ctx.JSON(http.StatusOK, gin.H{
		"keys": keys,
	})
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
