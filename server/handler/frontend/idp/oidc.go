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
	"maps"
	"math/big"
	"net"
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
	"github.com/croessner/nauthilus/server/idp/flow"
	"github.com/croessner/nauthilus/server/idp/signing"
	slodomain "github.com/croessner/nauthilus/server/idp/slo"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/middleware/csrf"
	"github.com/croessner/nauthilus/server/middleware/i18n"
	mdlua "github.com/croessner/nauthilus/server/middleware/lua"
	"github.com/croessner/nauthilus/server/middleware/securityheaders"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// formValue retrieves a request parameter from either the POST body or the URL
// query string depending on request method.
// For POST it reads only form body values, for GET it reads query values.
// GET support on /oidc/token is optional and controlled via idp.oidc.token_endpoint_allow_get.
func formValue(ctx *gin.Context, key string) string {
	if ctx == nil || ctx.Request == nil {
		return ""
	}

	if ctx.Request.Method == http.MethodGet {
		return ctx.Query(key)
	}

	return ctx.PostForm(key)
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

const (
	frontChannelLogoutTaskProtocolOIDC = "oidc"
	frontChannelLogoutTaskProtocolSAML = "saml"
	frontChannelLogoutTaskMethodGET    = "GET"
	frontChannelLogoutTaskMethodPOST   = "POST"
	frontChannelLogoutTaskMethodNone   = "NONE"
	frontChannelLogoutTaskStatusError  = "error"
	frontChannelLogoutTaskStatusSkip   = "skipped"

	frontChannelLogoutTimeout       = 4 * time.Second
	frontChannelLogoutMaxRetries    = 1
	frontChannelLogoutRedirectDelay = 1500 * time.Millisecond
)

type frontChannelLogoutTask struct {
	ID            string `json:"id"`
	DisplayName   string `json:"display_name"`
	Protocol      string `json:"protocol"`
	Method        string `json:"method"`
	URL           string `json:"url,omitzero"`
	PayloadBase64 string `json:"payload_base64,omitzero"`
	InitialStatus string `json:"initial_status,omitzero"`
	InitialDetail string `json:"initial_detail,omitzero"`
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
	securityMW := securityheaders.New(securityheaders.MiddlewareConfig{Config: h.deps.Cfg}).Handler()

	router.GET("/.well-known/openid-configuration", h.Discovery)
	router.GET("/oidc/authorize", securityMW, secureMW, i18nMW, h.Authorize)
	router.GET("/oidc/authorize/:languageTag", securityMW, secureMW, i18nMW, h.Authorize)
	router.POST("/oidc/token", h.Token)
	if h.deps.Cfg.GetIdP().OIDC.IsTokenEndpointGETAllowed() {
		router.GET("/oidc/token", h.Token)
	}
	router.GET("/oidc/userinfo", h.UserInfo)
	router.POST("/oidc/introspect", h.Introspect)
	router.GET("/oidc/jwks", h.JWKS)
	router.POST("/oidc/device", h.DeviceAuthorization)
	router.GET("/oidc/device/verify", securityMW, csrfMW, secureMW, i18nMW, h.DeviceVerifyPage)
	router.GET("/oidc/device/verify/:languageTag", securityMW, csrfMW, secureMW, i18nMW, h.DeviceVerifyPage)
	router.GET("/oidc/device/verify/failed", securityMW, csrfMW, secureMW, i18nMW, h.DeviceVerifyFailedPage)
	router.GET("/oidc/device/verify/failed/:languageTag", securityMW, csrfMW, secureMW, i18nMW, h.DeviceVerifyFailedPage)
	router.POST("/oidc/device/verify", securityMW, csrfMW, secureMW, i18nMW, h.DeviceVerify)
	router.POST("/oidc/device/verify/:languageTag", securityMW, csrfMW, secureMW, i18nMW, h.DeviceVerify)
	router.GET("/oidc/device/consent", securityMW, csrfMW, secureMW, i18nMW, h.DeviceConsentGET)
	router.GET("/oidc/device/consent/:languageTag", securityMW, csrfMW, secureMW, i18nMW, h.DeviceConsentGET)
	router.POST("/oidc/device/consent", securityMW, csrfMW, secureMW, i18nMW, h.DeviceConsentPOST)
	router.POST("/oidc/device/consent/:languageTag", securityMW, csrfMW, secureMW, i18nMW, h.DeviceConsentPOST)
	router.GET("/oidc/logout", securityMW, secureMW, h.Logout)
	router.GET("/logout", securityMW, secureMW, h.Logout)
	router.GET("/oidc/consent", securityMW, csrfMW, secureMW, i18nMW, h.ConsentGET)
	router.GET("/oidc/consent/:languageTag", securityMW, csrfMW, secureMW, i18nMW, h.ConsentGET)
	router.POST("/oidc/consent", securityMW, csrfMW, secureMW, i18nMW, h.ConsentPOST)
	router.POST("/oidc/consent/:languageTag", securityMW, csrfMW, secureMW, i18nMW, h.ConsentPOST)
}

// Discovery returns the OIDC discovery document.
func (h *OIDCHandler) Discovery(ctx *gin.Context) {
	oidcCfg := h.deps.Cfg.GetIdP().OIDC
	issuer := oidcCfg.Issuer

	scopesSupported := oidcCfg.GetScopesSupported()
	tokenEndpointAuthMethodsSupported := oidcCfg.GetTokenEndpointAuthMethodsSupported()
	discoveryDocument := gin.H{
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
		"grant_types_supported":                         oidcCfg.GetGrantTypesSupported(),
		"subject_types_supported":                       oidcCfg.GetSubjectTypesSupported(),
		"id_token_signing_alg_values_supported":         oidcCfg.GetIDTokenSigningAlgValuesSupported(),
		"scopes_supported":                              scopesSupported,
		"token_endpoint_auth_methods_supported":         tokenEndpointAuthMethodsSupported,
		"code_challenge_methods_supported":              oidcCfg.GetCodeChallengeMethodsSupported(),
		"introspection_endpoint_auth_methods_supported": oidcCfg.GetIntrospectionEndpointAuthMethodsSupported(),
		"claims_supported":                              oidcCfg.GetClaimsSupported(),
	}

	for _, customScope := range oidcCfg.CustomScopes {
		scopesSupported = append(scopesSupported, customScope.Name)
	}

	discoveryDocument["scopes_supported"] = scopesSupported

	if signingAlgs := oidcCfg.GetTokenEndpointAuthSigningAlgValuesSupported(); len(signingAlgs) > 0 {
		discoveryDocument["token_endpoint_auth_signing_alg_values_supported"] = signingAlgs
	}

	ctx.JSON(http.StatusOK, discoveryDocument)
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

		authSource = clientauth.MethodClientSecretBasic
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
				"methods", authSource+","+clientauth.MethodClientSecretPost,
			)

			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})

			return nil, false
		}

		if bClientID != "" {
			clientID = bClientID
		}
		clientSecret = bClientSecret
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

	if authSource == "" && bClientSecret != "" {
		authSource = clientauth.MethodClientSecretPost
	}

	if authSource == "" && bClientID != "" && (client.TokenEndpointAuthMethod == "none" || client.IsPublicClient()) {
		authSource = "none"
	}

	if authSource != "" {
		ctx.Set(definitions.CtxAuthMethodKey, authSource)
	}

	// Enforce TokenEndpointAuthMethod if configured
	if client.TokenEndpointAuthMethod != "" {
		allowed := false
		switch client.TokenEndpointAuthMethod {
		case clientauth.MethodClientSecretBasic:
			if authSource == clientauth.MethodClientSecretBasic {
				allowed = true
			}
		case clientauth.MethodClientSecretPost:
			if authSource == clientauth.MethodClientSecretPost {
				allowed = true
			}
		case "none":
			if authSource == "none" {
				allowed = true
			}
		default:
			// If unknown, default to allowing existing behavior (basic or post)
			allowed = authSource == clientauth.MethodClientSecretBasic || authSource == clientauth.MethodClientSecretPost
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

	if authSource == "none" {
		return client, true
	}

	if authSource == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})

		return nil, false
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

	ctx.Set(definitions.CtxAuthMethodKey, clientauth.MethodPrivateKeyJWT)

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

type oidcTokenPostActionSubject struct {
	Username     string
	UniqueUserID string
	DisplayName  string
	MFACompleted bool
	MFAMethod    string
	UserFound    bool
}

const oidcTokenPostActionSubjectKey = "oidc_token_post_action_subject"

// oidcTokenAuthMethod resolves the effective token endpoint client authentication method.
func oidcTokenAuthMethod(ctx *gin.Context) string {
	if ctx == nil || ctx.Request == nil {
		return ""
	}

	if authMethod, exists := ctx.Get(definitions.CtxAuthMethodKey); exists {
		if method, ok := authMethod.(string); ok && method != "" {
			return method
		}
	}

	if strings.HasPrefix(ctx.GetHeader("Authorization"), "Basic ") {
		return clientauth.MethodClientSecretBasic
	}

	if formValue(ctx, "client_assertion") != "" {
		return clientauth.MethodPrivateKeyJWT
	}

	if formValue(ctx, "client_secret") != "" {
		return clientauth.MethodClientSecretPost
	}

	if formValue(ctx, "client_id") != "" {
		return "none"
	}

	return ""
}

func oidcTokenResult(httpStatus int) string {
	if httpStatus >= http.StatusOK && httpStatus < http.StatusMultipleChoices {
		return sloRequestOutcomeSuccess
	}

	return "failed"
}

func oidcTokenClientPort(remoteAddr string) string {
	_, port, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return ""
	}

	return port
}

func oidcTokenStatusMessage(result string, httpStatus int) string {
	if result == sloRequestOutcomeSuccess {
		return "OIDC token issued"
	}

	return fmt.Sprintf("OIDC token request failed (%d)", httpStatus)
}

func oidcTokenDataContext(ctx *gin.Context) *lualib.Context {
	if ctx == nil {
		return lualib.NewContext()
	}

	luaCtx, ok := ctx.Get(definitions.CtxDataExchangeKey)
	contextData, _ := luaCtx.(*lualib.Context)
	if !ok || contextData == nil {
		return lualib.NewContext()
	}

	return contextData
}

func newOIDCTokenPostActionSubjectFromSession(session *idp.OIDCSession) *oidcTokenPostActionSubject {
	if session == nil {
		return nil
	}

	username := strings.TrimSpace(session.Username)
	if username == "" {
		username = strings.TrimSpace(session.UserID)
	}

	subject := &oidcTokenPostActionSubject{
		Username:     username,
		UniqueUserID: strings.TrimSpace(session.UserID),
		DisplayName:  strings.TrimSpace(session.DisplayName),
		MFACompleted: session.MFACompleted,
		MFAMethod:    strings.TrimSpace(session.MFAMethod),
	}

	subject.UserFound = subject.Username != "" || subject.UniqueUserID != "" || subject.DisplayName != ""

	return subject
}

func setOIDCTokenPostActionSubject(ctx *gin.Context, session *idp.OIDCSession) {
	if ctx == nil {
		return
	}

	subject := newOIDCTokenPostActionSubjectFromSession(session)
	if subject == nil {
		return
	}

	ctx.Set(oidcTokenPostActionSubjectKey, subject)
}

func oidcTokenPostActionSubjectFromContext(ctx *gin.Context) (*oidcTokenPostActionSubject, bool) {
	if ctx == nil {
		return nil, false
	}

	value, ok := ctx.Get(oidcTokenPostActionSubjectKey)
	if !ok {
		return nil, false
	}

	subject, ok := value.(*oidcTokenPostActionSubject)
	if !ok || subject == nil {
		return nil, false
	}

	return subject, true
}

func (h *OIDCHandler) buildOIDCTokenPostActionRequest(
	ctx *gin.Context,
	auth *core.AuthState,
	service string,
	grantType string,
	clientID string,
	authMethod string,
	httpStatus int,
	result string,
	latency time.Duration,
) lualib.CommonRequest {
	request := lualib.CommonRequest{}

	if auth != nil {
		auth.Runtime.GUID = ctx.GetString(definitions.CtxGUIDKey)
		auth.Request.Service = service
		auth.SetStatusCodes(service)
		auth.SetOIDCCID(clientID)
		auth.SetProtocol(config.NewProtocol(definitions.ProtoOIDC))
		auth.FillCommonRequest(&request)
	}

	request.Debug = h.deps.Cfg.GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
	request.NoAuth = true
	request.Authenticated = result == sloRequestOutcomeSuccess
	request.UserFound = false
	request.Service = service
	request.Session = ctx.GetString(definitions.CtxGUIDKey)
	request.ClientIP = ctx.ClientIP()
	request.ClientPort = oidcTokenClientPort(ctx.Request.RemoteAddr)
	request.ClientID = clientID
	request.UserAgent = ctx.Request.UserAgent()
	request.Protocol = definitions.ProtoOIDC
	request.Method = authMethod
	request.OIDCCID = clientID
	request.GrantType = grantType
	request.FeatureStageExpected = false
	request.FilterStageExpected = false
	request.Latency = float64(latency.Milliseconds())
	request.HTTPStatus = httpStatus

	if subject, ok := oidcTokenPostActionSubjectFromContext(ctx); ok {
		request.Username = subject.Username
		request.UniqueUserID = subject.UniqueUserID
		request.DisplayName = subject.DisplayName
		request.UserFound = subject.UserFound
		request.MFACompleted = subject.MFACompleted
		request.MFAMethod = subject.MFAMethod
	}

	if mfaCompleted, ok := ctx.Get(definitions.CtxMFACompletedKey); ok {
		if value, ok := mfaCompleted.(bool); ok {
			request.MFACompleted = value
		}
	}

	if mfaMethod, ok := ctx.Get(definitions.CtxMFAMethodKey); ok {
		if value, ok := mfaMethod.(string); ok {
			request.MFAMethod = value
		}
	}

	return request
}

func (h *OIDCHandler) runOIDCTokenPostAction(
	ctx *gin.Context,
	grantType string,
	clientID string,
	authMethod string,
	httpStatus int,
	result string,
	latency time.Duration,
) {
	if h == nil || h.deps == nil || h.deps.Cfg == nil || !h.deps.Cfg.HaveLuaActions() {
		return
	}

	if ctx == nil || ctx.Request == nil {
		return
	}

	authRaw := core.NewAuthStateFromContextWithDeps(ctx, h.deps.Auth())
	auth, ok := authRaw.(*core.AuthState)
	if !ok || auth == nil {
		return
	}

	service := ctx.GetString(definitions.CtxServiceKey)
	if service == "" {
		service = definitions.ServIdP
	}

	auth.Request.Service = service

	args := core.PostActionArgs{
		Context:       oidcTokenDataContext(ctx),
		HTTPRequest:   util.DetachedHTTPRequest(ctx.Request, nil),
		ParentSpan:    trace.SpanContextFromContext(ctx.Request.Context()),
		StatusMessage: oidcTokenStatusMessage(result, httpStatus),
		Request:       h.buildOIDCTokenPostActionRequest(ctx, auth, service, grantType, clientID, authMethod, httpStatus, result, latency),
	}

	go auth.RunLuaPostAction(args)
}

func (h *OIDCHandler) finishOIDCTokenRequest(ctx *gin.Context, grantType string, clientID string, startedAt time.Time) {
	if ctx == nil || ctx.Request == nil {
		return
	}

	httpStatus := http.StatusOK
	if ctx != nil && ctx.Writer != nil {
		httpStatus = ctx.Writer.Status()
	}

	result := oidcTokenResult(httpStatus)
	authMethod := oidcTokenAuthMethod(ctx)

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "OIDC Token request completed",
		"grant_type", util.WithNotAvailable(grantType),
		"client_id", util.WithNotAvailable(clientID),
		"auth_method", util.WithNotAvailable(authMethod),
		definitions.LogKeyHTTPStatus, httpStatus,
		"result", result,
	)

	h.runOIDCTokenPostAction(ctx, grantType, clientID, authMethod, httpStatus, result, time.Since(startedAt))
}

func setOIDCTokenPostActionMFAOverrides(ctx *gin.Context, completed bool, method string) {
	if ctx == nil {
		return
	}

	ctx.Set(definitions.CtxMFACompletedKey, completed)

	if method != "" {
		ctx.Set(definitions.CtxMFAMethodKey, method)
	}
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

	startedAt := time.Now()
	grantType := formValue(ctx, "grant_type")
	ctx.Set(definitions.CtxOIDCGrantTypeKey, grantType)

	clientID := formValue(ctx, "client_id")
	defer func() {
		h.finishOIDCTokenRequest(ctx, grantType, clientID, startedAt)
	}()

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

	clientID = client.ClientID

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

	// Validate token and retrieve IdTokenClaims for the UserInfo endpoint.
	claims, err := h.idp.ValidateTokenForUserInfo(ctx.Request.Context(), tokenString)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})

		return
	}

	// Return user info from IdToken claims
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

	maps.Copy(response, claims)

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

func appendStateToLogoutTarget(target, state string) string {
	target = strings.TrimSpace(target)
	state = strings.TrimSpace(state)
	if target == "" || state == "" {
		return target
	}

	parsedTarget, err := url.ParseRequestURI(target)
	if err != nil {
		return target
	}

	query := parsedTarget.Query()
	query.Set("state", state)
	parsedTarget.RawQuery = query.Encode()

	return parsedTarget.String()
}

func encodeFrontChannelLogoutTasks(tasks []frontChannelLogoutTask) string {
	rawTasks, err := json.Marshal(tasks)
	if err != nil {
		return "[]"
	}

	return string(rawTasks)
}

func buildSAMLFrontChannelLogoutTasks(result *sloFanoutResult) []frontChannelLogoutTask {
	if result == nil {
		return nil
	}

	tasks := make([]frontChannelLogoutTask, 0, len(result.Dispatches)+len(result.Failures))

	for index, dispatch := range result.Dispatches {
		task := frontChannelLogoutTask{
			ID:          fmt.Sprintf("saml-%d", index+1),
			DisplayName: strings.TrimSpace(dispatch.Participant.EntityID),
			Protocol:    frontChannelLogoutTaskProtocolSAML,
		}

		if task.DisplayName == "" {
			task.DisplayName = fmt.Sprintf("saml-participant-%d", index+1)
		}

		switch {
		case dispatch.RedirectURL != "":
			task.Method = frontChannelLogoutTaskMethodGET
			task.URL = dispatch.RedirectURL
		case dispatch.PostBody != "":
			task.Method = frontChannelLogoutTaskMethodPOST
			task.PayloadBase64 = base64.StdEncoding.EncodeToString([]byte(dispatch.PostBody))
		default:
			task.Method = frontChannelLogoutTaskMethodNone
			task.InitialStatus = frontChannelLogoutTaskStatusError
			task.InitialDetail = "missing front-channel payload"
		}

		tasks = append(tasks, task)
	}

	offset := len(tasks)

	for index, failure := range result.Failures {
		entityID := strings.TrimSpace(failure.EntityID)
		if entityID == "" {
			entityID = fmt.Sprintf("saml-participant-failed-%d", index+1)
		}

		task := frontChannelLogoutTask{
			ID:            fmt.Sprintf("saml-%d", offset+index+1),
			DisplayName:   entityID,
			Protocol:      frontChannelLogoutTaskProtocolSAML,
			Method:        frontChannelLogoutTaskMethodNone,
			InitialStatus: frontChannelLogoutTaskStatusError,
			InitialDetail: "fanout planning failed",
		}
		if failure.Err != nil {
			task.InitialDetail = failure.Err.Error()
		}

		tasks = append(tasks, task)
	}

	return tasks
}

func (h *OIDCHandler) samlFrontChannelLogoutTasks(ctx context.Context, account string) []frontChannelLogoutTask {
	account = strings.TrimSpace(account)
	if account == "" {
		return nil
	}

	samlHandler := NewSAMLHandler(h.deps, h.idp)
	if !samlHandler.sloEnabled() {
		_ = samlHandler.deleteSLOParticipantSessionsByAccount(ctx, account)

		return nil
	}

	sloTransaction, err := samlHandler.newIDPInitiatedSLOTransaction(account, slodomain.SLOBindingRedirect)
	if err != nil {
		util.DebugModuleWithCfg(
			ctx,
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyMsg, "Failed to initialize SAML SLO fanout transaction",
			"account", util.WithNotAvailable(account),
			"error", err.Error(),
		)

		return nil
	}

	if err = sloTransaction.TransitionTo(slodomain.SLOStatusLocalDone, time.Now().UTC()); err != nil {
		util.DebugModuleWithCfg(
			ctx,
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyMsg, "Failed to transition SAML SLO fanout transaction to local_done",
			"transaction_id", sloTransaction.TransactionID,
			"error", err.Error(),
		)

		return nil
	}

	result, err := samlHandler.orchestrateIDPInitiatedSLOFanout(ctx, sloTransaction, account)

	if err == nil {
		if stateErr := samlHandler.storeSLOFanoutTransactionState(ctx, sloTransaction, result); stateErr != nil {
			util.DebugModuleWithCfg(
				ctx,
				h.deps.Cfg,
				h.deps.Logger,
				definitions.DbgIdp,
				definitions.LogKeyMsg, "Failed to persist SAML SLO fanout transaction state",
				"transaction_id", sloTransaction.TransactionID,
				"error", stateErr.Error(),
			)

			return nil
		}
	}

	if cleanupErr := samlHandler.deleteSLOParticipantSessionsByAccount(ctx, account); cleanupErr != nil {
		util.DebugModuleWithCfg(
			ctx,
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyMsg, "Failed to cleanup SAML SLO participant sessions after fanout planning",
			"transaction_id", sloTransaction.TransactionID,
			"account", util.WithNotAvailable(account),
			"error", cleanupErr.Error(),
		)
	}

	if err != nil {
		util.DebugModuleWithCfg(
			ctx,
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyMsg, "Failed to orchestrate SAML SLO fanout",
			"transaction_id", sloTransaction.TransactionID,
			"error", err.Error(),
		)

		return nil
	}

	util.DebugModuleWithCfg(
		ctx,
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyMsg, "Prepared SAML SLO fanout requests",
		"transaction_id", sloTransaction.TransactionID,
		"transaction_status", sloTransaction.Status,
		"participants_total", len(result.Dispatches)+len(result.Failures),
		"participants_planned", len(result.Dispatches),
		"participants_failed", len(result.Failures),
	)

	return buildSAMLFrontChannelLogoutTasks(result)
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

	frontChannelTasks := make([]frontChannelLogoutTask, 0)

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
			parsedURI, parseErr := parseAbsoluteURL(c.FrontChannelLogoutURI)
			if parseErr != nil {
				util.DebugModuleWithCfg(
					ctx.Request.Context(),
					h.deps.Cfg,
					h.deps.Logger,
					definitions.DbgIdp,
					definitions.LogKeyMsg, "Skipping invalid OIDC front-channel logout URI",
					"client_id", util.WithNotAvailable(cid),
					"uri", util.WithNotAvailable(c.FrontChannelLogoutURI),
					"error", parseErr.Error(),
				)

				continue
			}

			// In a real implementation, we could add sid here if required.
			frontChannelTasks = append(frontChannelTasks, frontChannelLogoutTask{
				ID:          fmt.Sprintf("oidc-%d", len(frontChannelTasks)+1),
				DisplayName: cid,
				Protocol:    frontChannelLogoutTaskProtocolOIDC,
				Method:      frontChannelLogoutTaskMethodGET,
				URL:         parsedURI.String(),
			})
		}
	}

	frontChannelTasks = append(frontChannelTasks, h.samlFrontChannelLogoutTasks(ctx.Request.Context(), account)...)
	logoutTarget := h.calculateLogoutTarget(client, clientIDs)

	if client != nil && postLogoutRedirectURI != "" {
		if h.idp.ValidatePostLogoutRedirectURI(client, postLogoutRedirectURI) {
			logoutTarget = appendStateToLogoutTarget(postLogoutRedirectURI, state)
		}
	}

	if len(frontChannelTasks) > 0 {
		data := BasePageData(ctx, h.deps.Cfg, h.deps.LangManager)
		data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Logout")
		data["LoggingOutFromAllApplications"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Logging out from all applications...")
		data["PleaseWaitWhileLogoutProcessIsCompleted"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please wait while the logout process is completed.")
		data["FrontChannelLogoutTasks"] = frontChannelTasks
		data["FrontChannelLogoutTaskConfig"] = encodeFrontChannelLogoutTasks(frontChannelTasks)
		data["FrontChannelLogoutTimeoutMS"] = int(frontChannelLogoutTimeout / time.Millisecond)
		data["FrontChannelLogoutMaxRetries"] = frontChannelLogoutMaxRetries
		data["FrontChannelLogoutRedirectDelayMS"] = int(frontChannelLogoutRedirectDelay / time.Millisecond)
		data["LogoutTarget"] = logoutTarget
		data["LogoutProgress"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Logout progress")
		data["LogoutStatusPerApplication"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Logout status per application")
		data["LogoutSummaryPending"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Logout is in progress.")
		data["LogoutSummaryDone"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Logout completed successfully.")
		data["LogoutSummaryPartial"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Logout completed with partial failures.")
		data["LogoutStatusPending"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Pending")
		data["LogoutStatusRunning"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Running")
		data["LogoutStatusSuccess"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Success")
		data["LogoutStatusTimeout"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Timeout")
		data["LogoutStatusError"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Error")
		data["LogoutStatusSkipped"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Skipped")
		data["LogoutRetrying"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Retrying")
		data["LogoutAttempt"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Attempt")

		core.SessionCleaner(ctx)
		core.ClearBrowserCookies(ctx)

		ctx.HTML(http.StatusOK, "idp_logout_frames.html", data)

		return
	}

	core.SessionCleaner(ctx)
	core.ClearBrowserCookies(ctx)

	ctx.Redirect(http.StatusFound, logoutTarget)
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

// CleanupIdPFlowState removes all temporary IdP flow state keys from the cookie.
// These keys are only needed during the login redirect cycle
// (e.g. /oidc/authorize → /login → /oidc/authorize or /saml/sso → /login → /saml/sso)
// and should be cleaned up after the flow completes successfully.
// This covers OIDC (authorization code, device code) and SAML flows.
func CleanupIdPFlowState(mgr cookie.Manager) {
	flow.CleanupIdPState(mgr)
}

// CleanupMFAState removes all temporary MFA flow keys from the cookie.
// These keys are only needed during MFA verification and should be cleaned up
// after the MFA flow completes successfully (in finalizeMFALogin).
func CleanupMFAState(mgr cookie.Manager) {
	flow.CleanupMFAState(mgr)
}
