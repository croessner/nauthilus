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
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/frontend"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/idp"
	"github.com/croessner/nauthilus/v3/server/idp/clientauth"
	"github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/croessner/nauthilus/v3/server/idp/signing"
	slodomain "github.com/croessner/nauthilus/v3/server/idp/slo"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/middleware/csrf"
	"github.com/croessner/nauthilus/v3/server/middleware/i18n"
	mdlua "github.com/croessner/nauthilus/v3/server/middleware/lua"
	"github.com/croessner/nauthilus/v3/server/middleware/securityheaders"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
	jsoniter "github.com/json-iterator/go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// formValue retrieves a request parameter from either the POST body or the URL
// query string depending on request method.
// For POST it reads only form body values, for GET it reads query values.
// GET support on /oidc/token is optional and controlled via identity.oidc.tokens.token_endpoint_allow_get.
func formValue(ctx *gin.Context, key string) string {
	if ctx == nil || ctx.Request == nil {
		return ""
	}

	if ctx.Request.Method == http.MethodGet {
		return ctx.Query(key)
	}

	return ctx.PostForm(key)
}

const (
	oidcParamGrantType             = "grant_type"
	oidcParamClientID              = "client_id"
	oidcParamClientSecret          = "client_secret"
	oidcParamClientAssertionType   = "client_assertion_type"
	oidcParamClientAssertion       = "client_assertion"
	oidcParamCode                  = "code"
	oidcParamRedirectURI           = "redirect_uri"
	oidcParamCodeVerifier          = "code_verifier"
	oidcParamRefreshToken          = "refresh_token"
	oidcParamDeviceCode            = "device_code"
	oidcParamResponseType          = "response_type"
	oidcParamScope                 = "scope"
	oidcParamState                 = "state"
	oidcParamNonce                 = "nonce"
	oidcParamPrompt                = "prompt"
	oidcParamCodeChallenge         = "code_challenge"
	oidcParamCodeChallengeMethod   = "code_challenge_method"
	oidcEndpointPathToken          = "/oidc/token"
	oidcEndpointPathIntrospect     = "/oidc/introspect"
	oidcEndpointPathDevice         = "/oidc/device"
	oidcGrantTypeRefreshToken      = oidcParamRefreshToken
	oidcGrantTypeClientCredentials = "client_credentials"
	oidcResponseTypeCode           = oidcParamCode
	oidcJSONErrorDescriptionKey    = "error_description"
	oidcErrorInvalidRequest        = "invalid_request"
	oidcErrorInvalidClient         = "invalid_client"
	oidcErrorInvalidGrant          = "invalid_grant"
	oidcErrorInvalidScope          = "invalid_scope"
	oidcErrorUnauthorizedClient    = "unauthorized_client"
	oidcErrorServerError           = sloRequestOutcomeServerError
	oidcErrorExpiredToken          = "expired_token"
	oidcErrorSlowDown              = "slow_down"
	oidcErrorAuthorizationPending  = "authorization_pending"
	oidcErrorAccessDenied          = "access_denied"
)

var oidcTokenSingleValueParameters = []string{
	oidcParamGrantType,
	oidcParamClientID,
	oidcParamClientSecret,
	oidcParamClientAssertionType,
	oidcParamClientAssertion,
	oidcParamCode,
	oidcParamRedirectURI,
	oidcParamCodeVerifier,
	oidcParamRefreshToken,
	oidcParamDeviceCode,
}

func rejectDuplicateOIDCTokenParameters(ctx *gin.Context) bool {
	if ctx == nil || ctx.Request == nil {
		return false
	}

	for _, key := range oidcTokenSingleValueParameters {
		if len(oidcRequestValues(ctx, key)) <= 1 {
			continue
		}

		ctx.JSON(http.StatusBadRequest, gin.H{definitions.LogKeyError: oidcErrorInvalidRequest, oidcJSONErrorDescriptionKey: "duplicate parameter: " + key})

		return true
	}

	return false
}

func oidcRequestValues(ctx *gin.Context, key string) []string {
	if ctx == nil || ctx.Request == nil {
		return nil
	}

	if ctx.Request.Method == http.MethodGet {
		return ctx.Request.URL.Query()[key]
	}

	if err := ctx.Request.ParseForm(); err != nil {
		return nil
	}

	return ctx.Request.PostForm[key]
}

// OIDCHandler handles OIDC protocol requests.
type OIDCHandler struct {
	deps        *deps.Deps
	idp         *idp.NauthilusIDP
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
func NewOIDCHandler(d *deps.Deps, idpInstance *idp.NauthilusIDP, frontendHandler *FrontendHandler) *OIDCHandler {
	prefix := d.Cfg.GetServer().GetRedis().GetPrefix()

	return &OIDCHandler{
		deps:        d,
		idp:         idpInstance,
		storage:     idp.NewRedisTokenStorageWithConfig(d.Redis, prefix, d.Cfg),
		deviceStore: idp.NewRedisDeviceCodeStoreWithConfig(d.Redis, prefix, d.Cfg),
		userCodeGen: &idp.DefaultUserCodeGenerator{},
		frontend:    frontendHandler,
		tracer:      monittrace.New("nauthilus/idp/oidc"),
	}
}

// Register registers the OIDC routes.
func (h *OIDCHandler) Register(router gin.IRouter) {
	router.Use(func(ctx *gin.Context) {
		ctx.Set(definitions.CtxServiceKey, definitions.ServIDP)
		ctx.Next()
	}, mdlua.ContextMiddleware())

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

	if h.deps.Cfg.GetIDP().OIDC.IsTokenEndpointGETAllowed() {
		router.GET("/oidc/token", h.Token)
	}

	router.GET("/oidc/userinfo", h.UserInfo)
	router.POST("/oidc/introspect", h.Introspect)
	router.GET("/oidc/jwks", h.JWKS)
	router.POST("/oidc/device", h.DeviceAuthorization)
	router.GET(frontendDeviceVerifyPath, securityMW, csrfMW, secureMW, i18nMW, h.DeviceVerifyPage)
	router.GET(frontendDeviceVerifyPath+"/:languageTag", securityMW, csrfMW, secureMW, i18nMW, h.DeviceVerifyPage)
	router.GET("/oidc/device/verify/failed", securityMW, csrfMW, secureMW, i18nMW, h.DeviceVerifyFailedPage)
	router.GET("/oidc/device/verify/failed/:languageTag", securityMW, csrfMW, secureMW, i18nMW, h.DeviceVerifyFailedPage)
	router.POST(frontendDeviceVerifyPath, securityMW, csrfMW, secureMW, i18nMW, h.DeviceVerify)
	router.POST(frontendDeviceVerifyPath+"/:languageTag", securityMW, csrfMW, secureMW, i18nMW, h.DeviceVerify)
	router.GET(frontendDeviceConsentPath, securityMW, csrfMW, secureMW, i18nMW, h.DeviceConsentGET)
	router.GET(frontendDeviceConsentPath+"/:languageTag", securityMW, csrfMW, secureMW, i18nMW, h.DeviceConsentGET)
	router.POST(frontendDeviceConsentPath, securityMW, csrfMW, secureMW, i18nMW, h.DeviceConsentPOST)
	router.POST(frontendDeviceConsentPath+"/:languageTag", securityMW, csrfMW, secureMW, i18nMW, h.DeviceConsentPOST)
	router.GET("/oidc/logout", securityMW, secureMW, h.Logout)
	router.GET("/logout", securityMW, secureMW, h.Logout)
	router.GET("/oidc/consent", securityMW, csrfMW, secureMW, i18nMW, h.ConsentGET)
	router.GET("/oidc/consent/:languageTag", securityMW, csrfMW, secureMW, i18nMW, h.ConsentGET)
	router.POST("/oidc/consent", securityMW, csrfMW, secureMW, i18nMW, h.ConsentPOST)
	router.POST("/oidc/consent/:languageTag", securityMW, csrfMW, secureMW, i18nMW, h.ConsentPOST)
}

// Discovery returns the OIDC discovery document.
func (h *OIDCHandler) Discovery(ctx *gin.Context) {
	oidcCfg := h.deps.Cfg.GetIDP().OIDC
	issuer := oidcCfg.Issuer

	scopesSupported := oidcCfg.GetScopesSupported()
	tokenEndpointAuthMethodsSupported := oidcCfg.GetTokenEndpointAuthMethodsSupported()
	discoveryDocument := gin.H{
		"issuer":                                        issuer,
		"authorization_endpoint":                        issuer + "/oidc/authorize",
		"token_endpoint":                                issuer + oidcEndpointPathToken,
		"introspection_endpoint":                        issuer + oidcEndpointPathIntrospect,
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

	if signingAlgs := oidcCfg.GetIntrospectionEndpointAuthSigningAlgValuesSupported(); len(signingAlgs) > 0 {
		discoveryDocument["introspection_endpoint_auth_signing_alg_values_supported"] = signingAlgs
	}

	ctx.JSON(http.StatusOK, discoveryDocument)
}

// oidcClientCredentials carries the resolved client authentication envelope.
type oidcClientCredentials struct {
	clientID         string
	clientSecret     string
	authSource       string
	bodyClientID     string
	bodyClientSecret string
}

// authenticateClient extracts and authenticates the OIDC client.
func (h *OIDCHandler) authenticateClient(ctx *gin.Context) (*config.OIDCClient, bool) {
	credentials, ok := h.resolveOIDCClientCredentials(ctx)
	if !ok {
		return nil, false
	}

	if credentials.clientID == "" {
		writeOIDCInvalidClientResponse(ctx)
		return nil, false
	}

	client, ok := h.findOIDCClient(ctx, credentials.clientID)
	if !ok {
		return nil, false
	}

	completeOIDCClientAuthSource(ctx, client, &credentials)

	if !h.enforceOIDCClientAuthMethod(ctx, client, credentials) {
		return nil, false
	}

	if credentials.authSource == oidcClientAuthMethodNone {
		return client, true
	}

	if credentials.authSource == "" {
		writeOIDCInvalidClientResponse(ctx)
		return nil, false
	}

	if !h.verifyOIDCClientSecret(ctx, client, credentials) {
		return nil, false
	}

	return client, true
}

// resolveOIDCClientCredentials merges basic and form-based client credentials.
func (h *OIDCHandler) resolveOIDCClientCredentials(ctx *gin.Context) (oidcClientCredentials, bool) {
	credentials := basicOIDCClientCredentials(ctx)
	credentials.bodyClientID = formValue(ctx, oidcParamClientID)
	credentials.bodyClientSecret = formValue(ctx, oidcParamClientSecret)

	if credentials.bodyClientID == "" && credentials.bodyClientSecret == "" {
		return credentials, true
	}

	if credentials.authSource == "" {
		credentials.applyBodyCredentials()
		return credentials, true
	}

	if h.allowRefreshGrantCombinedClientAuth(
		ctx,
		credentials.authSource,
		credentials.clientID,
		credentials.clientSecret,
		credentials.bodyClientID,
		credentials.bodyClientSecret,
	) {
		h.logAcceptedCombinedClientAuth(ctx, credentials.clientID)
		return credentials, true
	}

	h.logMultipleOIDCClientAuthenticationMethods(ctx, credentials.authSource)
	writeOIDCInvalidClientResponse(ctx)

	return credentials, false
}

// basicOIDCClientCredentials extracts HTTP Basic credentials.
func basicOIDCClientCredentials(ctx *gin.Context) oidcClientCredentials {
	clientID, clientSecret, ok := ctx.Request.BasicAuth()
	if !ok {
		return oidcClientCredentials{}
	}

	return oidcClientCredentials{
		clientID:     decodeOIDCBasicAuthValue(clientID),
		clientSecret: decodeOIDCBasicAuthValue(clientSecret),
		authSource:   clientauth.MethodClientSecretBasic,
	}
}

// decodeOIDCBasicAuthValue preserves raw Basic values when percent decoding fails.
func decodeOIDCBasicAuthValue(value string) string {
	decoded, err := url.QueryUnescape(value)
	if err != nil {
		return value
	}

	return decoded
}

// applyBodyCredentials applies form credentials when no other method was used.
func (credentials *oidcClientCredentials) applyBodyCredentials() {
	if credentials.bodyClientID != "" {
		credentials.clientID = credentials.bodyClientID
	}

	credentials.clientSecret = credentials.bodyClientSecret

	if credentials.bodyClientSecret != "" {
		credentials.authSource = clientauth.MethodClientSecretPost
	}
}

// logAcceptedCombinedClientAuth records refresh-token compatibility auth handling.
func (h *OIDCHandler) logAcceptedCombinedClientAuth(ctx *gin.Context, clientID string) {
	clientType := "confidential"
	if candidate, ok := h.idp.FindClient(clientID); ok && candidate.IsPublicClient() {
		clientType = "public"
	}

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "Accepting combined OIDC client authentication for refresh token compatibility",
		definitions.LogKeyClientID, clientID,
		"client_type", clientType,
	)
}

// logMultipleOIDCClientAuthenticationMethods records mixed client auth methods.
func (h *OIDCHandler) logMultipleOIDCClientAuthenticationMethods(ctx *gin.Context, authSource string) {
	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "Multiple OIDC client authentication methods used",
		"methods", authSource+","+clientauth.MethodClientSecretPost,
	)
}

// findOIDCClient resolves a configured client or writes the invalid_client response.
func (h *OIDCHandler) findOIDCClient(ctx *gin.Context, clientID string) (*config.OIDCClient, bool) {
	client, ok := h.idp.FindClient(clientID)
	if ok {
		return client, true
	}

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "OIDC client not found",
		definitions.LogKeyClientID, clientID,
	)

	writeOIDCInvalidClientResponse(ctx)

	return nil, false
}

// completeOIDCClientAuthSource derives the effective auth method for the client.
func completeOIDCClientAuthSource(ctx *gin.Context, client *config.OIDCClient, credentials *oidcClientCredentials) {
	if credentials.authSource == "" && credentials.bodyClientID != "" && clientAllowsNoSecretAuth(client) {
		credentials.authSource = oidcClientAuthMethodNone
	}

	if client.IsPublicClient() && credentials.clientID == client.ClientID && secretBasedAuthSource(credentials.authSource) {
		// Public clients cannot keep a secret. Some clients still include
		// one for compatibility; ignore it and treat the request as "none".
		credentials.authSource = oidcClientAuthMethodNone
		credentials.clientSecret = ""
	}

	if credentials.authSource != "" {
		ctx.Set(definitions.CtxAuthMethodKey, credentials.authSource)
	}
}

// clientAllowsNoSecretAuth reports whether the client may authenticate with none.
func clientAllowsNoSecretAuth(client *config.OIDCClient) bool {
	return client.TokenEndpointAuthMethod == oidcClientAuthMethodNone || client.IsPublicClient()
}

// secretBasedAuthSource reports whether the method carries a client secret.
func secretBasedAuthSource(authSource string) bool {
	return authSource == clientauth.MethodClientSecretBasic || authSource == clientauth.MethodClientSecretPost
}

// enforceOIDCClientAuthMethod checks the configured token endpoint auth method.
func (h *OIDCHandler) enforceOIDCClientAuthMethod(ctx *gin.Context, client *config.OIDCClient, credentials oidcClientCredentials) bool {
	if client.TokenEndpointAuthMethod == "" {
		return true
	}

	if oidcClientAuthMethodAllowed(client.TokenEndpointAuthMethod, credentials.authSource) {
		return true
	}

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "OIDC client authentication method not allowed",
		definitions.LogKeyClientID, credentials.clientID,
		"auth_source", credentials.authSource,
		"expected_method", client.TokenEndpointAuthMethod,
	)

	writeOIDCInvalidClientResponse(ctx)

	return false
}

// oidcClientAuthMethodAllowed evaluates the configured auth method contract.
func oidcClientAuthMethodAllowed(expected string, actual string) bool {
	switch expected {
	case clientauth.MethodClientSecretBasic:
		return actual == clientauth.MethodClientSecretBasic
	case clientauth.MethodClientSecretPost:
		return actual == clientauth.MethodClientSecretPost
	case clientauth.MethodPrivateKeyJWT:
		return actual == clientauth.MethodPrivateKeyJWT
	case oidcClientAuthMethodNone:
		return actual == oidcClientAuthMethodNone
	default:
		return secretBasedAuthSource(actual)
	}
}

// verifyOIDCClientSecret checks the provided secret in constant time.
func (h *OIDCHandler) verifyOIDCClientSecret(ctx *gin.Context, client *config.OIDCClient, credentials oidcClientCredentials) bool {
	expectedSecret := oidcClientSecretBytes(client)

	receivedSecret := []byte(credentials.clientSecret)
	if subtle.ConstantTimeCompare(expectedSecret, receivedSecret) == 1 {
		return true
	}

	h.logOIDCClientSecretMismatch(ctx, credentials.clientID, credentials.clientSecret, len(expectedSecret), len(receivedSecret))
	writeOIDCInvalidClientResponse(ctx)

	return false
}

// oidcClientSecretBytes clones the configured client secret for comparison.
func oidcClientSecretBytes(client *config.OIDCClient) []byte {
	var expectedSecret []byte

	client.ClientSecret.WithBytes(func(value []byte) {
		if len(value) == 0 {
			return
		}

		expectedSecret = bytes.Clone(value)
	})

	return expectedSecret
}

// logOIDCClientSecretMismatch records safe diagnostics for secret mismatches.
func (h *OIDCHandler) logOIDCClientSecretMismatch(ctx *gin.Context, clientID string, clientSecret string, expectedLength int, receivedLength int) {
	keyvals := []any{
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "OIDC client secret mismatch",
		definitions.LogKeyClientID, clientID,
		"expected_len", expectedLength,
		"received_len", receivedLength,
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
}

// writeOIDCInvalidClientResponse writes the standard invalid_client response.
func writeOIDCInvalidClientResponse(ctx *gin.Context) {
	ctx.JSON(http.StatusUnauthorized, gin.H{definitions.LogKeyError: oidcErrorInvalidClient})
}

func (h *OIDCHandler) allowRefreshGrantCombinedClientAuth(
	ctx *gin.Context,
	authSource string,
	headerClientID string,
	headerClientSecret string,
	bodyClientID string,
	bodyClientSecret string,
) bool {
	if h == nil {
		return false
	}

	if !combinedClientAuthRequestMatches(ctx, authSource, headerClientID, bodyClientID) {
		return false
	}

	client, ok := h.idp.FindClient(headerClientID)
	if !ok || !client.AllowsRefreshTokenCombinedClientAuth() {
		return false
	}

	return combinedClientAuthSecretMatches(client, headerClientSecret, bodyClientSecret)
}

// combinedClientAuthRequestMatches checks the refresh-token compatibility envelope.
func combinedClientAuthRequestMatches(ctx *gin.Context, authSource string, headerClientID string, bodyClientID string) bool {
	if ctx == nil || ctx.Request == nil {
		return false
	}

	return formValue(ctx, oidcParamGrantType) == oidcGrantTypeRefreshToken &&
		authSource == clientauth.MethodClientSecretBasic &&
		headerClientID != "" &&
		bodyClientID != "" &&
		headerClientID == bodyClientID
}

// combinedClientAuthSecretMatches checks public and confidential compatibility secrets.
func combinedClientAuthSecretMatches(client *config.OIDCClient, headerClientSecret string, bodyClientSecret string) bool {
	if client.IsPublicClient() {
		return bodyClientSecret == ""
	}

	return bodyClientSecret != "" && headerClientSecret == bodyClientSecret
}

// privateKeyJWTClientAuthRequest carries the resolved client assertion context.
type privateKeyJWTClientAuthRequest struct {
	client        *config.OIDCClient
	assertionType string
	assertion     string
	clientID      string
	audience      string
}

// authenticateClientPrivateKeyJWT authenticates a client assertion for an endpoint audience.
func (h *OIDCHandler) authenticateClientPrivateKeyJWT(ctx *gin.Context, audience string) (*config.OIDCClient, bool) {
	request, ok := h.parsePrivateKeyJWTClientAuthRequest(ctx, audience)
	if !ok {
		return nil, false
	}

	if !h.verifyPrivateKeyJWTClientAssertion(ctx, request) {
		return nil, false
	}

	return request.client, true
}

// parsePrivateKeyJWTClientAuthRequest resolves and validates the client assertion envelope.
func (h *OIDCHandler) parsePrivateKeyJWTClientAuthRequest(ctx *gin.Context, audience string) (privateKeyJWTClientAuthRequest, bool) {
	var request privateKeyJWTClientAuthRequest

	assertionType := formValue(ctx, oidcParamClientAssertionType)
	assertion := formValue(ctx, oidcParamClientAssertion)
	clientID := formValue(ctx, oidcParamClientID)

	if assertionType == "" || assertion == "" {
		return request, false
	}

	ctx.Set(definitions.CtxAuthMethodKey, clientauth.MethodPrivateKeyJWT)

	if assertionType != clientauth.AssertionTypeJWTBearer {
		ctx.JSON(http.StatusUnauthorized, gin.H{definitions.LogKeyError: oidcErrorInvalidClient, oidcJSONErrorDescriptionKey: "unsupported client_assertion_type"})

		return request, false
	}

	// If client_id not in form, try to extract from the assertion's iss claim.
	if clientID == "" {
		clientID = extractIssFromJWT(assertion)
	}

	if clientID == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{definitions.LogKeyError: oidcErrorInvalidClient})

		return request, false
	}

	client, ok := h.idp.FindClient(clientID)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{definitions.LogKeyError: oidcErrorInvalidClient})

		return request, false
	}

	if client.TokenEndpointAuthMethod != clientauth.MethodPrivateKeyJWT {
		ctx.JSON(http.StatusUnauthorized, gin.H{definitions.LogKeyError: oidcErrorInvalidClient, oidcJSONErrorDescriptionKey: "client not configured for private_key_jwt"})

		return request, false
	}

	return privateKeyJWTClientAuthRequest{
		client:        client,
		assertionType: assertionType,
		assertion:     assertion,
		clientID:      clientID,
		audience:      audience,
	}, true
}

// verifyPrivateKeyJWTClientAssertion verifies the assertion and reserves its scoped jti.
func (h *OIDCHandler) verifyPrivateKeyJWTClientAssertion(ctx *gin.Context, request privateKeyJWTClientAuthRequest) bool {
	verifier, ok := h.privateKeyJWTVerifier(ctx, request)
	if !ok {
		return false
	}

	claims, ok := h.authenticatePrivateKeyJWTAssertion(ctx, request, verifier)
	if !ok {
		return false
	}

	return h.reservePrivateKeyJWTAssertion(ctx, request, claims)
}

// privateKeyJWTVerifier builds the configured client assertion verifier.
func (h *OIDCHandler) privateKeyJWTVerifier(ctx *gin.Context, request privateKeyJWTClientAuthRequest) (signing.Verifier, bool) {
	verifier, err := h.buildClientVerifier(request.client)
	if err == nil {
		return verifier, true
	}

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "Failed to build client verifier",
		definitions.LogKeyClientID, request.clientID,
		definitions.LogKeyError, err,
	)

	writeOIDCInvalidClientResponse(ctx)

	return nil, false
}

// authenticatePrivateKeyJWTAssertion verifies the JWT assertion claims.
func (h *OIDCHandler) authenticatePrivateKeyJWTAssertion(
	ctx *gin.Context,
	request privateKeyJWTClientAuthRequest,
	verifier signing.Verifier,
) (*clientauth.PrivateKeyJWTClaims, bool) {
	auth := clientauth.NewPrivateKeyJWTAuthenticator(verifier, request.clientID, request.audience)

	claims, err := auth.AuthenticateAssertion(&clientauth.AuthRequest{
		ClientID:            request.clientID,
		ClientAssertionType: request.assertionType,
		ClientAssertion:     request.assertion,
		TokenEndpointURL:    request.audience,
	})
	if err == nil {
		return claims, true
	}

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "private_key_jwt authentication failed",
		definitions.LogKeyClientID, request.clientID,
		definitions.LogKeyError, err,
	)

	writeOIDCInvalidClientResponse(ctx)

	return nil, false
}

// reservePrivateKeyJWTAssertion reserves the scoped jti to reject replay.
func (h *OIDCHandler) reservePrivateKeyJWTAssertion(
	ctx *gin.Context,
	request privateKeyJWTClientAuthRequest,
	claims *clientauth.PrivateKeyJWTClaims,
) bool {
	err := h.storage.ReserveClientAssertionJWTID(
		ctx.Request.Context(),
		claims.ClientID,
		claims.Audience,
		claims.JWTID,
		claims.ExpiresAt,
	)
	if err == nil {
		return true
	}

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "private_key_jwt replay reservation failed",
		definitions.LogKeyClientID, request.clientID,
		"replay_status", clientAssertionReplayStatus(err),
		definitions.LogKeyError, err,
	)

	writeOIDCInvalidClientResponse(ctx)

	return false
}

// clientAssertionReplayStatus classifies assertion reservation failures.
func clientAssertionReplayStatus(err error) string {
	if errors.Is(err, idp.ErrClientAssertionReplayDetected) {
		return "detected"
	}

	return "unavailable"
}

// oidcEndpointURL builds a public endpoint URL from the configured issuer.
func (h *OIDCHandler) oidcEndpointURL(path string) string {
	return h.deps.Cfg.GetIDP().OIDC.Issuer + path
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

	if err := jsoniter.ConfigFastest.Unmarshal(payload, &claims); err != nil {
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

	if formValue(ctx, oidcParamClientAssertion) != "" {
		return clientauth.MethodPrivateKeyJWT
	}

	if formValue(ctx, oidcParamClientSecret) != "" {
		return clientauth.MethodClientSecretPost
	}

	if formValue(ctx, oidcParamClientID) != "" {
		return oidcClientAuthMethodNone
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

func oidcTokenFailureReason(ctx *gin.Context) string {
	if ctx == nil {
		return ""
	}

	return strings.TrimSpace(ctx.GetString(definitions.CtxFailureReasonKey))
}

func setOIDCTokenFailureReason(ctx *gin.Context, reason string) {
	if ctx == nil {
		return
	}

	reason = strings.TrimSpace(reason)
	if reason == "" {
		return
	}

	ctx.Set(definitions.CtxFailureReasonKey, reason)
}

func oidcTokenStatusMessageWithReason(result string, httpStatus int, failureReason string) string {
	statusMessage := oidcTokenStatusMessage(result, httpStatus)
	failureReason = strings.TrimSpace(failureReason)

	if failureReason == "" || result == sloRequestOutcomeSuccess {
		return statusMessage
	}

	return fmt.Sprintf("%s: %s", statusMessage, failureReason)
}

func oidcRefreshTokenFailureReason(err error) string {
	switch {
	case errors.Is(err, idp.ErrInvalidRefreshToken):
		return "refresh token unknown, expired, or already rotated"
	case errors.Is(err, idp.ErrRefreshTokenClientMismatch):
		return "refresh token was not issued to the requesting client"
	default:
		return ""
	}
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

// fillOIDCTokenPostActionAuthState copies AuthState fields into the Lua request.
func fillOIDCTokenPostActionAuthState(ctx *gin.Context, auth *core.AuthState, service string, clientID string, request *lualib.CommonRequest) {
	if auth == nil {
		return
	}

	auth.Runtime.GUID = ctx.GetString(definitions.CtxGUIDKey)
	auth.Request.Service = service
	auth.SetStatusCodes(service)
	auth.SetOIDCCID(clientID)
	auth.SetProtocol(config.NewProtocol(definitions.ProtoOIDC))
	auth.FillCommonRequest(request)
}

// fillOIDCTokenPostActionBase sets token-endpoint metadata for Lua post-actions.
func (h *OIDCHandler) fillOIDCTokenPostActionBase(
	ctx *gin.Context,
	request *lualib.CommonRequest,
	service string,
	grantType string,
	clientID string,
	authMethod string,
	httpStatus int,
	result string,
	latency time.Duration,
) {
	request.Debug = h.deps.Cfg.GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
	request.NoAuth = true
	request.Authenticated = result == sloRequestOutcomeSuccess
	request.UserFound = false
	request.Service = service
	request.Session = ctx.GetString(definitions.CtxGUIDKey)
	request.ClientIP = util.RequestClientIPWithConfig(ctx, h.deps.Cfg, h.deps.Logger)
	request.ClientPort = oidcTokenClientPort(ctx.Request.RemoteAddr)
	request.ClientID = clientID
	request.UserAgent = ctx.Request.UserAgent()
	request.Protocol = definitions.ProtoOIDC
	request.Method = authMethod
	request.OIDCCID = clientID
	request.GrantType = grantType
	request.EnvironmentStageExpected = false
	request.SubjectStageExpected = false
	request.Latency = float64(latency.Milliseconds())
	request.HTTPStatus = httpStatus
}

// applyOIDCTokenPostActionSubject copies resolved subject data into the request.
func applyOIDCTokenPostActionSubject(ctx *gin.Context, request *lualib.CommonRequest) {
	subject, ok := oidcTokenPostActionSubjectFromContext(ctx)
	if !ok {
		return
	}

	request.Username = subject.Username
	request.UniqueUserID = subject.UniqueUserID
	request.DisplayName = subject.DisplayName
	request.UserFound = subject.UserFound
	request.MFACompleted = subject.MFACompleted
	request.MFAMethod = subject.MFAMethod
}

// applyOIDCTokenPostActionMFAOverrides applies explicit MFA context overrides.
func applyOIDCTokenPostActionMFAOverrides(ctx *gin.Context, request *lualib.CommonRequest) {
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
}

// buildOIDCTokenPostActionRequest creates the Lua request snapshot for OIDC
// token endpoint post-actions without exposing token secrets.
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

	fillOIDCTokenPostActionAuthState(ctx, auth, service, clientID, &request)
	h.fillOIDCTokenPostActionBase(ctx, &request, service, grantType, clientID, authMethod, httpStatus, result, latency)
	applyOIDCTokenPostActionSubject(ctx, &request)
	applyOIDCTokenPostActionMFAOverrides(ctx, &request)

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
		service = definitions.ServIDP
	}

	failureReason := oidcTokenFailureReason(ctx)

	auth.Request.Service = service

	args := core.PostActionArgs{
		Context:       oidcTokenDataContext(ctx),
		HTTPRequest:   util.DetachedHTTPRequest(context.TODO(), ctx.Request),
		ParentSpan:    trace.SpanContextFromContext(ctx.Request.Context()),
		StatusMessage: oidcTokenStatusMessageWithReason(result, httpStatus, failureReason),
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
	failureReason := oidcTokenFailureReason(ctx)
	statusMessage := oidcTokenStatusMessageWithReason(result, httpStatus, failureReason)

	keyvals := []any{
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "OIDC Token request completed",
		oidcParamGrantType, util.WithNotAvailable(grantType),
		definitions.LogKeyClientID, util.WithNotAvailable(clientID),
		"auth_method", util.WithNotAvailable(authMethod),
		definitions.LogKeyHTTPStatus, httpStatus,
		"result", result,
		definitions.LogKeyStatusMessage, statusMessage,
	}

	if failureReason != "" {
		keyvals = append(keyvals, definitions.LogKeyFailureReason, failureReason)
	}

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		keyvals...,
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
		oidcParamGrantType, grantType,
		definitions.LogKeyClientID, clientID,
		definitions.LogKeyError, err,
	)

	ctx.JSON(http.StatusInternalServerError, gin.H{definitions.LogKeyError: oidcErrorServerError})
}

// sendTokenResponse writes the common OIDC token response JSON.
func (h *OIDCHandler) sendTokenResponse(ctx *gin.Context, clientID, grantType string, resp *tokenResponse) {
	stats.GetMetrics().GetIdpTokensIssuedTotal().WithLabelValues("oidc", clientID, grantType).Inc()

	result := gin.H{
		oidcJSONFieldAccessToken: resp.accessToken,
		oidcJSONFieldTokenType:   oidcJSONTokenTypeBearer,
		oidcJSONFieldExpiresIn:   int(resp.expiresIn.Seconds()),
	}

	// Per OIDC Core 1.0 §3.1.2.1: id_token is only present when "openid" scope was requested.
	// Client Credentials Grant also never returns an id_token (RFC 6749 §4.4).
	if resp.idToken != "" {
		result["id_token"] = resp.idToken
	}

	if resp.refreshToken != "" {
		result[oidcParamRefreshToken] = resp.refreshToken
	}

	ctx.JSON(http.StatusOK, result)
}

// beginOIDCTokenRequest captures common token request metadata.
func (h *OIDCHandler) beginOIDCTokenRequest(ctx *gin.Context) (time.Time, string, string, string) {
	startedAt := time.Now()
	grantType := formValue(ctx, oidcParamGrantType)

	ctx.Set(definitions.CtxOIDCGrantTypeKey, grantType)

	clientID := oidcTokenRequestClientID(ctx)

	flow := strings.TrimSpace(grantType)
	if flow == "" {
		flow = "token"
	}

	h.logIncomingOIDCFlowRequest(ctx, flow, grantType, clientID)

	return startedAt, grantType, clientID, flow
}

// authenticateOIDCTokenClient resolves the token endpoint client auth method.
func (h *OIDCHandler) authenticateOIDCTokenClient(ctx *gin.Context) (*config.OIDCClient, bool) {
	if formValue(ctx, oidcParamClientAssertion) != "" {
		return h.authenticateClientPrivateKeyJWT(ctx, h.oidcEndpointURL(oidcEndpointPathToken))
	}

	return h.authenticateClient(ctx)
}

// logOIDCTokenRequest records the accepted token request envelope.
func (h *OIDCHandler) logOIDCTokenRequest(ctx *gin.Context, grantType string, clientID string) {
	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "OIDC Token request",
		oidcParamGrantType, grantType,
		definitions.LogKeyClientID, clientID,
	)
}

// dispatchOIDCTokenGrant routes a token request by grant type.
func (h *OIDCHandler) dispatchOIDCTokenGrant(ctx *gin.Context, client *config.OIDCClient, grantType string) {
	switch grantType {
	case definitions.OIDCFlowAuthorizationCode:
		h.handleAuthorizationCodeTokenExchange(ctx, client, grantType)
	case oidcGrantTypeRefreshToken:
		h.handleRefreshTokenExchange(ctx, client, grantType)
	case oidcGrantTypeClientCredentials:
		h.handleClientCredentialsTokenExchange(ctx, client, grantType)
	case definitions.OIDCGrantTypeDeviceCode:
		h.dispatchDeviceCodeTokenGrant(ctx, client)
	default:
		ctx.JSON(http.StatusBadRequest, gin.H{definitions.LogKeyError: "unsupported_grant_type"})
	}
}

// dispatchDeviceCodeTokenGrant enforces device-code grant support before exchange.
func (h *OIDCHandler) dispatchDeviceCodeTokenGrant(ctx *gin.Context, client *config.OIDCClient) {
	if !client.SupportsGrantType(definitions.OIDCGrantTypeDeviceCode) {
		ctx.JSON(http.StatusBadRequest, gin.H{definitions.LogKeyError: oidcErrorUnauthorizedClient})

		return
	}

	h.handleDeviceCodeTokenExchange(ctx, client)
}

// Token handles the OIDC token request.
func (h *OIDCHandler) Token(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "oidc.token")
	defer sp.End()

	if rejectDuplicateOIDCTokenParameters(ctx) {
		return
	}

	startedAt, grantType, clientID, flow := h.beginOIDCTokenRequest(ctx)
	defer func() {
		h.logCompletedOIDCFlowRequest(ctx, flow, grantType, clientID)
		h.finishOIDCTokenRequest(ctx, grantType, clientID, startedAt)
	}()

	client, ok := h.authenticateOIDCTokenClient(ctx)
	if !ok {
		return
	}

	clientID = client.ClientID

	h.logOIDCTokenRequest(ctx, grantType, clientID)
	sp.SetAttributes(attribute.String(definitions.LogKeyClientID, clientID))
	h.dispatchOIDCTokenGrant(ctx, client, grantType)
}

// UserInfo handles the OIDC userinfo request.
func (h *OIDCHandler) UserInfo(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "oidc.userinfo")
	defer sp.End()

	authHeader := ctx.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		ctx.JSON(http.StatusUnauthorized, gin.H{definitions.LogKeyError: "missing_token"})

		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Validate token and retrieve IDTokenClaims for the UserInfo endpoint.
	claims, err := h.idp.ValidateTokenForUserInfo(ctx.Request.Context(), tokenString)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{definitions.LogKeyError: "invalid_token"})

		return
	}

	// Return user info from IDToken claims
	ctx.JSON(http.StatusOK, claims)
}

// Introspect handles the OIDC token introspection request.
func (h *OIDCHandler) Introspect(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "oidc.introspect")
	defer sp.End()

	client, ok := h.authenticateIntrospectionClient(ctx)
	if !ok {
		return
	}

	token := ctx.PostForm("token")
	if token == "" {
		ctx.JSON(http.StatusOK, gin.H{oidcJSONFieldActive: false})

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
			definitions.LogKeyError, err,
		)

		ctx.JSON(http.StatusOK, gin.H{oidcJSONFieldActive: false})

		return
	}

	// Verify that the token was issued to the client making the request,
	// or that the client is otherwise authorized to introspect this token.
	if aud, ok := claims["aud"].(string); ok && aud != client.ClientID {
		ctx.JSON(http.StatusOK, gin.H{oidcJSONFieldActive: false})

		return
	}

	response := gin.H{
		oidcJSONFieldActive: true,
	}

	maps.Copy(response, claims)
	response[oidcJSONFieldActive] = true

	ctx.JSON(http.StatusOK, response)
}

// authenticateIntrospectionClient selects the configured client authentication path for introspection.
func (h *OIDCHandler) authenticateIntrospectionClient(ctx *gin.Context) (*config.OIDCClient, bool) {
	if formValue(ctx, oidcParamClientAssertion) != "" {
		return h.authenticateClientPrivateKeyJWT(ctx, h.oidcEndpointURL(oidcEndpointPathIntrospect))
	}

	return h.authenticateClient(ctx)
}

// JWKS handles the OIDC JWKS request.
func (h *OIDCHandler) JWKS(ctx *gin.Context) {
	var keys []gin.H

	rsaKeys, err := h.idp.GetKeyManager().GetAllKeys(ctx.Request.Context())
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{definitions.LogKeyError: "failed to get keys"})

		return
	}

	for kid, key := range rsaKeys {
		publicKey := key.PublicKey
		n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

		keys = append(keys, gin.H{
			oidcJSONFieldKeyType:   oidcJSONWebKeyTypeRSA,
			oidcJSONFieldAlgorithm: oidcJSONWebKeyAlgorithmRS256,
			oidcJSONFieldKeyUse:    oidcJSONWebKeyUseSignature,
			oidcJSONFieldKeyID:     kid,
			"n":                    n,
			"e":                    e,
		})
	}

	edKeys, err := h.idp.GetKeyManager().GetAllEdKeys(ctx.Request.Context())
	if err == nil {
		for kid, key := range edKeys {
			pubKey := key.Public().(ed25519.PublicKey)
			x := base64.RawURLEncoding.EncodeToString(pubKey)

			keys = append(keys, gin.H{
				oidcJSONFieldKeyType:   oidcJSONWebKeyTypeOKP,
				oidcJSONFieldAlgorithm: oidcJSONWebKeyAlgorithmEdDSA,
				oidcJSONFieldKeyUse:    oidcJSONWebKeyUseSignature,
				oidcJSONFieldKeyID:     kid,
				"crv":                  "Ed25519",
				"x":                    x,
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
	rawTasks, err := jsoniter.ConfigFastest.Marshal(tasks)
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

// prepareSAMLFrontChannelLogoutTransaction creates and advances the SAML fanout transaction.
func (h *OIDCHandler) prepareSAMLFrontChannelLogoutTransaction(
	ctx context.Context,
	samlHandler *SAMLHandler,
	account string,
) (*slodomain.Transaction, bool) {
	sloTransaction, err := samlHandler.newIDPInitiatedSLOTransaction(account, slodomain.SLOBindingRedirect)
	if err != nil {
		util.DebugModuleWithCfg(
			ctx,
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyMsg, "Failed to initialize SAML SLO fanout transaction",
			"account", util.WithNotAvailable(account),
			definitions.LogKeyError, err.Error(),
		)

		return nil, false
	}

	if err = sloTransaction.TransitionTo(slodomain.SLOStatusLocalDone, time.Now().UTC()); err != nil {
		util.DebugModuleWithCfg(
			ctx,
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyMsg, "Failed to transition SAML SLO fanout transaction to local_done",
			"transaction_id", sloTransaction.TransactionID,
			definitions.LogKeyError, err.Error(),
		)

		return nil, false
	}

	return sloTransaction, true
}

// planSAMLFrontChannelLogoutFanout prepares front-channel tasks and persists state.
func (h *OIDCHandler) planSAMLFrontChannelLogoutFanout(
	ctx context.Context,
	samlHandler *SAMLHandler,
	sloTransaction *slodomain.Transaction,
	account string,
) (*sloFanoutResult, bool) {
	result, err := samlHandler.orchestrateIDPInitiatedSLOFanout(ctx, sloTransaction, account)
	if err == nil && !h.persistSAMLFrontChannelLogoutState(ctx, samlHandler, sloTransaction, result) {
		return nil, false
	}

	h.cleanupSAMLFrontChannelLogoutParticipants(ctx, samlHandler, sloTransaction, account)

	if err != nil {
		util.DebugModuleWithCfg(
			ctx,
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyMsg, "Failed to orchestrate SAML SLO fanout",
			"transaction_id", sloTransaction.TransactionID,
			definitions.LogKeyError, err.Error(),
		)

		return nil, false
	}

	return result, true
}

// persistSAMLFrontChannelLogoutState stores pending fanout state for browser completion.
func (h *OIDCHandler) persistSAMLFrontChannelLogoutState(
	ctx context.Context,
	samlHandler *SAMLHandler,
	sloTransaction *slodomain.Transaction,
	result *sloFanoutResult,
) bool {
	if stateErr := samlHandler.storeSLOFanoutTransactionState(ctx, sloTransaction, result); stateErr != nil {
		util.DebugModuleWithCfg(
			ctx,
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyMsg, "Failed to persist SAML SLO fanout transaction state",
			"transaction_id", sloTransaction.TransactionID,
			definitions.LogKeyError, stateErr.Error(),
		)

		return false
	}

	return true
}

// cleanupSAMLFrontChannelLogoutParticipants removes consumed SAML participant sessions.
func (h *OIDCHandler) cleanupSAMLFrontChannelLogoutParticipants(
	ctx context.Context,
	samlHandler *SAMLHandler,
	sloTransaction *slodomain.Transaction,
	account string,
) {
	if cleanupErr := samlHandler.deleteSLOParticipantSessionsByAccount(ctx, account); cleanupErr != nil {
		util.DebugModuleWithCfg(
			ctx,
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyMsg, "Failed to cleanup SAML SLO participant sessions after fanout planning",
			"transaction_id", sloTransaction.TransactionID,
			"account", util.WithNotAvailable(account),
			definitions.LogKeyError, cleanupErr.Error(),
		)
	}
}

// logPreparedSAMLFrontChannelLogoutTasks records successful SAML fanout planning.
func (h *OIDCHandler) logPreparedSAMLFrontChannelLogoutTasks(ctx context.Context, sloTransaction *slodomain.Transaction, result *sloFanoutResult) {
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

	sloTransaction, ok := h.prepareSAMLFrontChannelLogoutTransaction(ctx, samlHandler, account)
	if !ok {
		return nil
	}

	result, ok := h.planSAMLFrontChannelLogoutFanout(ctx, samlHandler, sloTransaction, account)
	if !ok {
		return nil
	}

	h.logPreparedSAMLFrontChannelLogoutTasks(ctx, sloTransaction, result)

	return buildSAMLFrontChannelLogoutTasks(result)
}

// oidcLogoutSession captures session-derived identity data for logout.
type oidcLogoutSession struct {
	manager      cookie.Manager
	account      string
	uniqueUserID string
	userID       string
}

// oidcLogoutRequest carries query parameters relevant to logout.
type oidcLogoutRequest struct {
	idTokenHint           string
	postLogoutRedirectURI string
	state                 string
}

// readOIDCLogoutRequest captures logout query parameters.
func readOIDCLogoutRequest(ctx *gin.Context) oidcLogoutRequest {
	return oidcLogoutRequest{
		idTokenHint:           ctx.Query("id_token_hint"),
		postLogoutRedirectURI: ctx.Query("post_logout_redirect_uri"),
		state:                 ctx.Query("state"),
	}
}

// readOIDCLogoutSession captures cookie-backed logout identity data.
func readOIDCLogoutSession(ctx *gin.Context) oidcLogoutSession {
	session := oidcLogoutSession{manager: cookie.GetManager(ctx)}
	if session.manager == nil {
		return session
	}

	session.account = session.manager.GetString(definitions.SessionKeyAccount, "")
	session.uniqueUserID = session.manager.GetString(definitions.SessionKeyUniqueUserID, "")
	session.userID = oidcLogoutUserID(session.account, session.uniqueUserID)

	return session
}

// oidcLogoutUserID prefers unique user IDs over account names.
func oidcLogoutUserID(account string, uniqueUserID string) string {
	if uniqueUserID != "" {
		return uniqueUserID
	}

	return account
}

// applyOIDCLogoutIDTokenHint validates id_token_hint and fills client/user context.
func (h *OIDCHandler) applyOIDCLogoutIDTokenHint(ctx *gin.Context, request oidcLogoutRequest, session *oidcLogoutSession) *config.OIDCClient {
	if request.idTokenHint == "" {
		return nil
	}

	claims, err := h.idp.ValidateToken(ctx.Request.Context(), request.idTokenHint)
	if err != nil {
		return nil
	}

	client := h.oidcLogoutClientFromClaims(claims)
	if session.userID == "" {
		if sub, ok := claims["sub"].(string); ok {
			session.userID = sub
		}
	}

	return client
}

// oidcLogoutClientFromClaims resolves the client referenced by token claims.
func (h *OIDCHandler) oidcLogoutClientFromClaims(claims map[string]any) *config.OIDCClient {
	cid, ok := claims["aud"].(string)
	if !ok {
		return nil
	}

	client, _ := h.idp.FindClient(cid)

	return client
}

// oidcLogoutClientIDs returns tracked OIDC clients from the session.
func (h *OIDCHandler) oidcLogoutClientIDs(ctx *gin.Context, session oidcLogoutSession) []string {
	if session.manager == nil {
		return nil
	}

	oidcClients := session.manager.GetString(definitions.SessionKeyOIDCClients, "")
	session.manager.Debug(ctx, h.deps.Logger, "OIDC logout initiated - session data before cleanup")

	if oidcClients == "" {
		return nil
	}

	return strings.Split(oidcClients, ",")
}

// oidcFrontChannelLogoutTask builds a browser logout task for an OIDC client.
func (h *OIDCHandler) oidcFrontChannelLogoutTask(
	ctx *gin.Context,
	clientID string,
	client *config.OIDCClient,
	index int,
) (frontChannelLogoutTask, bool) {
	if client.FrontChannelLogoutURI == "" {
		return frontChannelLogoutTask{}, false
	}

	parsedURI, err := parseAbsoluteURL(client.FrontChannelLogoutURI)
	if err != nil {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyMsg, "Skipping invalid OIDC front-channel logout URI",
			definitions.LogKeyClientID, util.WithNotAvailable(clientID),
			"uri", util.WithNotAvailable(client.FrontChannelLogoutURI),
			definitions.LogKeyError, err.Error(),
		)

		return frontChannelLogoutTask{}, false
	}

	return frontChannelLogoutTask{
		ID:          fmt.Sprintf("oidc-%d", index),
		DisplayName: clientID,
		Protocol:    frontChannelLogoutTaskProtocolOIDC,
		Method:      frontChannelLogoutTaskMethodGET,
		URL:         parsedURI.String(),
	}, true
}

// oidcFrontChannelLogoutTasks triggers back-channel logout and builds OIDC browser tasks.
func (h *OIDCHandler) oidcFrontChannelLogoutTasks(ctx *gin.Context, clientIDs []string, userID string) []frontChannelLogoutTask {
	frontChannelTasks := make([]frontChannelLogoutTask, 0)

	for _, clientID := range clientIDs {
		client, ok := h.idp.FindClient(clientID)
		if !ok {
			continue
		}

		if client.BackChannelLogoutURI != "" && userID != "" {
			go h.doBackChannelLogout(clientID, userID, client.BackChannelLogoutURI)
		}

		task, ok := h.oidcFrontChannelLogoutTask(ctx, clientID, client, len(frontChannelTasks)+1)
		if ok {
			frontChannelTasks = append(frontChannelTasks, task)
		}
	}

	return frontChannelTasks
}

// oidcLogoutTarget resolves the final redirect target.
func (h *OIDCHandler) oidcLogoutTarget(client *config.OIDCClient, clientIDs []string, request oidcLogoutRequest) string {
	logoutTarget := h.calculateLogoutTarget(client, clientIDs)
	if client == nil || request.postLogoutRedirectURI == "" {
		return logoutTarget
	}

	if h.idp.ValidatePostLogoutRedirectURI(client, request.postLogoutRedirectURI) {
		return appendStateToLogoutTarget(request.postLogoutRedirectURI, request.state)
	}

	return logoutTarget
}

// oidcLogoutPageData builds template data for browser-based logout orchestration.
func (h *OIDCHandler) oidcLogoutPageData(ctx *gin.Context, tasks []frontChannelLogoutTask, logoutTarget string) gin.H {
	data := BasePageData(ctx, h.deps.Cfg, h.deps.LangManager)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Logout")
	data["LoggingOutFromAllApplications"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Logging out from all applications...")
	data["PleaseWaitWhileLogoutProcessIsCompleted"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please wait while the logout process is completed.")
	data["FrontChannelLogoutTasks"] = tasks
	data["FrontChannelLogoutTaskConfig"] = encodeFrontChannelLogoutTasks(tasks)
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

	return data
}

// Logout handles the OIDC logout request.
func (h *OIDCHandler) Logout(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "oidc.logout")
	defer sp.End()

	h.logIncomingOIDCFlowRequest(ctx, "logout", "", "")
	defer h.logCompletedOIDCFlowRequest(ctx, "logout", "", "")

	request := readOIDCLogoutRequest(ctx)
	session := readOIDCLogoutSession(ctx)

	client := h.applyOIDCLogoutIDTokenHint(ctx, request, &session)
	if session.userID != "" {
		_ = h.storage.DeleteUserRefreshTokens(ctx.Request.Context(), session.userID)
	}

	clientIDs := h.oidcLogoutClientIDs(ctx, session)
	frontChannelTasks := h.oidcFrontChannelLogoutTasks(ctx, clientIDs, session.userID)
	frontChannelTasks = append(frontChannelTasks, h.samlFrontChannelLogoutTasks(ctx.Request.Context(), session.account)...)
	logoutTarget := h.oidcLogoutTarget(client, clientIDs, request)

	if len(frontChannelTasks) > 0 {
		core.SessionCleaner(ctx)
		core.ClearBrowserCookies(ctx)

		ctx.HTML(http.StatusOK, "idp_logout_frames.html", h.oidcLogoutPageData(ctx, frontChannelTasks, logoutTarget))

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

	defer func() { _ = resp.Body.Close() }()
}

// CleanupIDPFlowState removes all temporary IDP flow state keys from the cookie.
// These keys are only needed during the login redirect cycle
// (e.g. /oidc/authorize → /login → /oidc/authorize or /saml/sso → /login → /saml/sso)
// and should be cleaned up after the flow completes successfully.
// This covers OIDC (authorization code, device code) and SAML flows.
func CleanupIDPFlowState(mgr cookie.Manager) {
	flow.CleanupIDPState(mgr)
}

// CleanupMFAState removes all temporary MFA flow keys from the cookie.
// These keys are only needed during MFA verification and should be cleaned up
// after the MFA flow completes successfully (in finalizeMFALogin).
func CleanupMFAState(mgr cookie.Manager) {
	flow.CleanupMFAState(mgr)
}
