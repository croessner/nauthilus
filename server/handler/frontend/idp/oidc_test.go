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
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/idp"
	slodomain "github.com/croessner/nauthilus/server/idp/slo"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/secret"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

type mockOIDCCfg struct {
	issuer                string
	signingKey            secret.Value
	signingKeyID          string
	clients               []config.OIDCClient
	tokenEndpointAllowGET bool
}

func (m *mockOIDCCfg) GetIdP() *config.IdPSection {
	return &config.IdPSection{
		OIDC: config.OIDCConfig{
			Issuer:                m.issuer,
			TokenEndpointAllowGET: m.tokenEndpointAllowGET,
			SigningKeys: []config.OIDCKey{
				{ID: m.signingKeyID, Key: m.signingKey, Active: true},
			},
			Clients: m.clients,
		},
	}
}

func TestFormValue(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("post does not use query string", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = httptest.NewRequest(http.MethodPost, "/oidc/token?client_id=query-client", strings.NewReader("grant_type=client_credentials"))
		ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		assert.Equal(t, "", formValue(ctx, "client_id"))
		assert.Equal(t, "client_credentials", formValue(ctx, "grant_type"))
	})

	t.Run("get reads query string", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/oidc/token?client_id=query-client", nil)

		assert.Equal(t, "query-client", formValue(ctx, "client_id"))
	})
}

func TestOIDCTokenAuthMethod(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name        string
		ctxMethod   string
		authHeader  string
		postForm    url.Values
		expectedVal string
	}{
		{
			name:        "context override wins",
			ctxMethod:   "client_secret_post",
			authHeader:  "Basic dGVzdDp0ZXN0",
			expectedVal: "client_secret_post",
		},
		{
			name:        "basic auth header",
			authHeader:  "Basic dGVzdDp0ZXN0",
			expectedVal: "client_secret_basic",
		},
		{
			name:        "private_key_jwt",
			postForm:    url.Values{"client_assertion": {"assertion"}},
			expectedVal: "private_key_jwt",
		},
		{
			name:        "client_secret_post",
			postForm:    url.Values{"client_secret": {"secret"}},
			expectedVal: "client_secret_post",
		},
		{
			name:        "none for public client style",
			postForm:    url.Values{"client_id": {"public-client"}},
			expectedVal: "none",
		},
		{
			name:        "empty when no auth hints",
			expectedVal: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)
			ctx.Request = httptest.NewRequest(http.MethodPost, "/oidc/token", nil)
			ctx.Request.PostForm = tc.postForm

			if tc.authHeader != "" {
				ctx.Request.Header.Set("Authorization", tc.authHeader)
			}

			if tc.ctxMethod != "" {
				ctx.Set(definitions.CtxAuthMethodKey, tc.ctxMethod)
			}

			assert.Equal(t, tc.expectedVal, oidcTokenAuthMethod(ctx))
		})
	}
}

func TestOIDCHandlerTokenSetsGrantTypeContext(t *testing.T) {
	definitions.SetDbgModuleMapping(definitions.NewDbgModuleMapping())
	gin.SetMode(gin.TestMode)

	cfg := &mockOIDCCfg{
		issuer:     "https://auth.example.com",
		signingKey: secret.New(generateTestKey()),
		clients: []config.OIDCClient{
			{
				ClientID:     "test-client",
				ClientSecret: secret.New("test-secret"),
				RedirectURIs: []string{"https://app.com/callback"},
			},
		},
	}

	db, _ := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)

	d := &deps.Deps{
		Cfg:    cfg,
		Redis:  rClient,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	idpInstance := idp.NewNauthilusIdP(d)
	h := NewOIDCHandler(d, idpInstance, nil)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	form := url.Values{}
	form.Add("grant_type", "client_credentials")
	form.Add("client_id", "test-client")

	req, _ := http.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx.Request = req

	h.Token(ctx)

	grantType, exists := ctx.Get(definitions.CtxOIDCGrantTypeKey)
	if !exists {
		t.Fatalf("expected context key %q to be set", definitions.CtxOIDCGrantTypeKey)
	}

	if grantTypeString, ok := grantType.(string); !ok || grantTypeString != "client_credentials" {
		t.Fatalf("unexpected grant_type context value: %#v", grantType)
	}
}

func generateTestKey() string {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	return string(pemData)
}

func (m *mockOIDCCfg) GetServer() *config.ServerSection {
	var log config.Log
	_ = log.Level.Set("debug")
	all := &config.DbgModule{}
	_ = all.Set("all")
	log.DbgModules = []*config.DbgModule{all}

	return &config.ServerSection{
		Redis: config.Redis{
			Prefix: "test:",
		},
		Log: log,
		DefaultHTTPRequestHeader: config.DefaultHTTPRequestHeader{
			OIDCCID:    "X-Nauthilus-OIDC-ClientID",
			ClientIP:   "X-Real-IP",
			ClientPort: "X-Real-Port",
			ClientID:   "X-Nauthilus-Client-ID",
			ClientHost: "X-Nauthilus-Client-Host",
		},
		DNS: config.DNS{
			ResolveClientIP: false,
		},
	}
}

func (m *mockOIDCCfg) GetLDAPConfigEncryptionSecret() secret.Value {
	return secret.Value{}
}

func (m *mockOIDCCfg) GetLDAPConfigBindPW() secret.Value {
	return secret.Value{}
}

func (m *mockOIDCCfg) GetOIDCCID() string    { return "X-Nauthilus-OIDC-ClientID" }
func (m *mockOIDCCfg) GetClientIP() string   { return "X-Real-IP" }
func (m *mockOIDCCfg) GetClientPort() string { return "X-Real-Port" }
func (m *mockOIDCCfg) GetClientID() string   { return "X-Nauthilus-Client-ID" }
func (m *mockOIDCCfg) GetClientHost() string { return "X-Nauthilus-Client-Host" }
func (m *mockOIDCCfg) GetLocalIP() string    { return "X-Local-IP" }
func (m *mockOIDCCfg) GetLocalPort() string  { return "X-Local-Port" }
func (m *mockOIDCCfg) GetUsername() string   { return "X-Nauthilus-Username" }
func (m *mockOIDCCfg) GetPassword() string   { return "X-Nauthilus-Password" }
func (m *mockOIDCCfg) HandleFile() error     { return nil }
func (m *mockOIDCCfg) GetConfigFileAsJSON() ([]byte, error) {
	return []byte("{}"), nil
}
func (m *mockOIDCCfg) HaveLuaFeatures() bool { return false }
func (m *mockOIDCCfg) HaveLuaFilters() bool  { return false }
func (m *mockOIDCCfg) HaveLuaHooks() bool    { return false }
func (m *mockOIDCCfg) HaveLuaActions() bool  { return false }
func (m *mockOIDCCfg) HaveLua() bool         { return false }
func (m *mockOIDCCfg) HaveLuaBackend() bool  { return false }
func (m *mockOIDCCfg) HaveLDAPBackend() bool { return false }
func (m *mockOIDCCfg) GetLDAP() *config.LDAPSection {
	return &config.LDAPSection{}
}
func (m *mockOIDCCfg) GetLua() *config.LuaSection {
	return &config.LuaSection{}
}
func (m *mockOIDCCfg) GetBruteForce() *config.BruteForceSection {
	return &config.BruteForceSection{}
}
func (m *mockOIDCCfg) GetRBLs() *config.RBLSection {
	return &config.RBLSection{}
}
func (m *mockOIDCCfg) GetRelayDomains() *config.RelayDomainsSection {
	return &config.RelayDomainsSection{}
}
func (m *mockOIDCCfg) GetClearTextList() []string {
	return []string{}
}
func (m *mockOIDCCfg) GetBackendServerMonitoring() *config.BackendServerMonitoring {
	return &config.BackendServerMonitoring{}
}
func (m *mockOIDCCfg) GetBackendServers() []*config.BackendServer {
	return []*config.BackendServer{}
}
func (m *mockOIDCCfg) GetBackendServer() *config.BackendServer {
	return &config.BackendServer{}
}
func (m *mockOIDCCfg) HaveServer() bool {
	return true
}
func (m *mockOIDCCfg) HaveLuaInit() bool            { return false }
func (m *mockOIDCCfg) GetLuaInitScriptPath() string { return "" }
func (m *mockOIDCCfg) GetLuaInitScriptPaths() []string {
	return []string{}
}
func (m *mockOIDCCfg) GetLuaPackagePath() string          { return "" }
func (m *mockOIDCCfg) GetLuaScriptPath() string           { return "" }
func (m *mockOIDCCfg) GetLuaCacheFlushScriptPath() string { return "" }
func (m *mockOIDCCfg) RetrieveGetterMap() map[definitions.Backend]config.GetterHandler {
	return nil
}
func (m *mockOIDCCfg) GetConfig() any { return nil }
func (m *mockOIDCCfg) GetProtocols() any {
	return nil
}
func (m *mockOIDCCfg) GetSection() any {
	return nil
}
func (m *mockOIDCCfg) GetBruteForceRules() []config.BruteForceRule {
	return nil
}
func (m *mockOIDCCfg) GetAllProtocols() []string { return nil }
func (m *mockOIDCCfg) HasFeature(string) bool {
	return false
}
func (m *mockOIDCCfg) ShouldRunFeature(string, bool) bool {
	return false
}
func (m *mockOIDCCfg) GetPasswordEncoded() string { return "" }
func (m *mockOIDCCfg) GetProtocol() string        { return "" }
func (m *mockOIDCCfg) GetLoginAttempt() string    { return "" }
func (m *mockOIDCCfg) GetAuthMethod() string      { return "" }
func (m *mockOIDCCfg) GetSSL() string             { return "" }
func (m *mockOIDCCfg) GetSSLSessionID() string    { return "" }
func (m *mockOIDCCfg) GetSSLVerify() string       { return "" }
func (m *mockOIDCCfg) GetSSLSubject() string      { return "" }
func (m *mockOIDCCfg) GetSSLClientCN() string     { return "" }
func (m *mockOIDCCfg) GetSSLIssuer() string       { return "" }
func (m *mockOIDCCfg) GetSSLClientNotBefore() string {
	return ""
}
func (m *mockOIDCCfg) GetSSLClientNotAfter() string { return "" }
func (m *mockOIDCCfg) GetSSLSubjectDN() string      { return "" }
func (m *mockOIDCCfg) GetSSLIssuerDN() string       { return "" }
func (m *mockOIDCCfg) GetSSLClientSubjectDN() string {
	return ""
}
func (m *mockOIDCCfg) GetSSLClientIssuerDN() string     { return "" }
func (m *mockOIDCCfg) GetSSLCipher() string             { return "" }
func (m *mockOIDCCfg) GetSSLProtocol() string           { return "" }
func (m *mockOIDCCfg) GetSSLSerial() string             { return "" }
func (m *mockOIDCCfg) GetSSLFingerprint() string        { return "" }
func (m *mockOIDCCfg) GetLuaNumberOfWorkers() int       { return 0 }
func (m *mockOIDCCfg) GetLuaActionNumberOfWorkers() int { return 0 }
func (m *mockOIDCCfg) GetLuaFeatureVMPoolSize() int     { return 0 }
func (m *mockOIDCCfg) GetLuaFilterVMPoolSize() int      { return 0 }
func (m *mockOIDCCfg) GetLuaHookVMPoolSize() int        { return 0 }
func (m *mockOIDCCfg) GetLuaSearchProtocol(string, string) (*config.LuaSearchProtocol, error) {
	return nil, nil
}
func (m *mockOIDCCfg) GetLuaOptionalBackends() map[string]*config.LuaConf { return nil }
func (m *mockOIDCCfg) LDAPHavePoolOnly(string) bool                       { return false }
func (m *mockOIDCCfg) GetLDAPSearchProtocol(string, string) (*config.LDAPSearchProtocol, error) {
	return nil, nil
}
func (m *mockOIDCCfg) GetLDAPOptionalPools() map[string]*config.LDAPConf { return nil }
func (m *mockOIDCCfg) GetLDAPConfigLookupPoolSize() int                  { return 0 }
func (m *mockOIDCCfg) GetLDAPConfigAuthPoolSize() int                    { return 0 }
func (m *mockOIDCCfg) GetLDAPConfigConnectAbortTimeout() time.Duration   { return 0 }
func (m *mockOIDCCfg) GetLDAPConfigBindDN() string                       { return "" }
func (m *mockOIDCCfg) GetLDAPConfigTLSCAFile() string                    { return "" }
func (m *mockOIDCCfg) GetLDAPConfigTLSClientCert() string                { return "" }
func (m *mockOIDCCfg) GetLDAPConfigTLSClientKey() string                 { return "" }
func (m *mockOIDCCfg) GetLDAPConfigServerURIs() []string                 { return nil }
func (m *mockOIDCCfg) GetLDAPConfigNumberOfWorkers() int                 { return 0 }
func (m *mockOIDCCfg) GetLDAPConfigStartTLS() bool                       { return false }
func (m *mockOIDCCfg) GetLDAPConfigTLSSkipVerify() bool                  { return false }
func (m *mockOIDCCfg) GetLDAPConfigSASLExternal() bool                   { return false }
func (m *mockOIDCCfg) GetLDAPConfigLookupIdlePoolSize() int              { return 0 }
func (m *mockOIDCCfg) GetLDAPConfigAuthIdlePoolSize() int                { return 0 }

func TestOIDCHandler_Discovery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	issuer := "https://auth.example.com"
	cfg := &mockOIDCCfg{issuer: issuer, signingKey: secret.New(generateTestKey())}

	db, _ := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)

	d := &deps.Deps{
		Cfg:   cfg,
		Redis: rClient,
	}

	h := NewOIDCHandler(d, nil, nil)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	h.Discovery(ctx)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, issuer, resp["issuer"])
	assert.Equal(t, issuer+"/oidc/authorize", resp["authorization_endpoint"])
	assert.Equal(t, issuer+"/oidc/token", resp["token_endpoint"])
	assert.Equal(t, issuer+"/oidc/introspect", resp["introspection_endpoint"])
	assert.Equal(t, issuer+"/oidc/logout", resp["end_session_endpoint"])
	scopes := resp["scopes_supported"].([]any)
	assert.Contains(t, scopes, "offline_access")
	assert.Contains(t, scopes, "groups")
	assert.Contains(t, scopes, "openid")
	responseTypes := resp["response_types_supported"].([]any)
	assert.Equal(t, []any{"code"}, responseTypes)
	grantTypes := resp["grant_types_supported"].([]any)
	assert.Contains(t, grantTypes, "authorization_code")
	assert.Contains(t, grantTypes, "refresh_token")
	assert.Contains(t, grantTypes, "client_credentials")
	assert.Contains(t, grantTypes, definitions.OIDCGrantTypeDeviceCode)
	tokenEndpointAuthMethods := resp["token_endpoint_auth_methods_supported"].([]any)
	assert.Contains(t, tokenEndpointAuthMethods, "client_secret_basic")
	assert.Contains(t, tokenEndpointAuthMethods, "client_secret_post")
	assert.Contains(t, tokenEndpointAuthMethods, "private_key_jwt")
	assert.Contains(t, tokenEndpointAuthMethods, "none")
	tokenEndpointAuthSigningAlgs := resp["token_endpoint_auth_signing_alg_values_supported"].([]any)
	assert.Contains(t, tokenEndpointAuthSigningAlgs, "RS256")
	assert.Contains(t, tokenEndpointAuthSigningAlgs, "EdDSA")
	introspectionAuthMethods := resp["introspection_endpoint_auth_methods_supported"].([]any)
	assert.Contains(t, introspectionAuthMethods, "client_secret_basic")
	assert.Contains(t, introspectionAuthMethods, "client_secret_post")
	assert.NotContains(t, introspectionAuthMethods, "private_key_jwt")
	assert.NotContains(t, introspectionAuthMethods, "none")
	codeChallengeMethods := resp["code_challenge_methods_supported"].([]any)
	assert.Contains(t, codeChallengeMethods, "S256")
	assert.NotContains(t, codeChallengeMethods, "plain")
}

func TestOIDCHandler_Register_DeviceVerifyLanguageRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	issuer := "https://auth.example.com"
	cfg := &mockOIDCCfg{issuer: issuer, signingKey: secret.New(generateTestKey())}

	db, _ := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)

	d := &deps.Deps{
		Cfg:         cfg,
		Env:         config.NewTestEnvironmentConfig(),
		LangManager: &mockLangManager{},
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:       rClient,
	}

	h := NewOIDCHandler(d, idp.NewNauthilusIdP(d), nil)
	r := gin.New()
	h.Register(r)

	routes := r.Routes()
	hasRoute := func(method, path string) bool {
		return slices.IndexFunc(routes, func(route gin.RouteInfo) bool {
			return route.Method == method && route.Path == path
		}) >= 0
	}

	assert.True(t, hasRoute(http.MethodGet, "/oidc/device/verify/:languageTag"))
	assert.True(t, hasRoute(http.MethodPost, "/oidc/device/verify/:languageTag"))
}

func TestOIDCHandler_Register_TokenGETRouteConfigurable(t *testing.T) {
	gin.SetMode(gin.TestMode)

	newHandler := func(allowGET bool) *gin.Engine {
		cfg := &mockOIDCCfg{
			issuer:                "https://auth.example.com",
			signingKey:            secret.New(generateTestKey()),
			tokenEndpointAllowGET: allowGET,
		}
		db, _ := redismock.NewClientMock()
		rClient := rediscli.NewTestClient(db)

		d := &deps.Deps{
			Cfg:         cfg,
			Env:         config.NewTestEnvironmentConfig(),
			LangManager: &mockLangManager{},
			Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
			Redis:       rClient,
		}

		h := NewOIDCHandler(d, idp.NewNauthilusIdP(d), nil)
		r := gin.New()
		h.Register(r)

		return r
	}

	hasRoute := func(routes []gin.RouteInfo, method, path string) bool {
		return slices.IndexFunc(routes, func(route gin.RouteInfo) bool {
			return route.Method == method && route.Path == path
		}) >= 0
	}

	rStrict := newHandler(false)
	assert.True(t, hasRoute(rStrict.Routes(), http.MethodPost, "/oidc/token"))
	assert.False(t, hasRoute(rStrict.Routes(), http.MethodGet, "/oidc/token"))

	rLegacy := newHandler(true)
	assert.True(t, hasRoute(rLegacy.Routes(), http.MethodPost, "/oidc/token"))
	assert.True(t, hasRoute(rLegacy.Routes(), http.MethodGet, "/oidc/token"))
}

func TestOIDCHandler_JWKS(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name        string
		signingKID  string
		expectedKID string
	}{
		{
			name:        "DefaultKid",
			signingKID:  "default",
			expectedKID: "default",
		},
		{
			name:        "CustomKid",
			signingKID:  "custom-kid",
			expectedKID: "custom-kid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &mockOIDCCfg{issuer: "https://auth.example.com", signingKey: secret.New(generateTestKey()), signingKeyID: tt.signingKID}
			db, _ := redismock.NewClientMock()
			rClient := rediscli.NewTestClient(db)
			d := &deps.Deps{Cfg: cfg, Redis: rClient}
			h := NewOIDCHandler(d, idp.NewNauthilusIdP(d), nil)

			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)
			ctx.Request = httptest.NewRequest(http.MethodGet, "/oidc/jwks", nil)

			h.JWKS(ctx)

			assert.Equal(t, http.StatusOK, w.Code)

			var resp map[string]any
			err := json.Unmarshal(w.Body.Bytes(), &resp)
			assert.NoError(t, err)
			assert.NotNil(t, resp["keys"])

			keys := resp["keys"].([]any)
			assert.Len(t, keys, 1)

			key := keys[0].(map[string]any)
			assert.Equal(t, tt.expectedKID, key["kid"])
		})
	}
}

func TestOIDCHandler_Logout(t *testing.T) {
	gin.SetMode(gin.TestMode)
	issuer := "https://auth.example.com"
	signingKey := secret.New(generateTestKey())
	client := config.OIDCClient{
		ClientID:               "test-client",
		PostLogoutRedirectURIs: []string{"https://app.com/post-logout"},
	}

	cfg := &mockOIDCCfg{
		issuer:     issuer,
		signingKey: signingKey,
		clients:    []config.OIDCClient{client},
	}

	db, mock := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)

	d := &deps.Deps{
		Cfg:    cfg,
		Redis:  rClient,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	idpInstance := idp.NewNauthilusIdP(d)
	h := NewOIDCHandler(d, idpInstance, nil)

	// Set up default environment for util.ShouldSetSecureCookie
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	t.Run("Logout without session redirects to logged_out", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := gin.New()
		r.GET("/logout", func(c *gin.Context) {
			mgr := &mockCookieManager{data: make(map[string]any)}
			c.Set(definitions.CtxSecureDataKey, mgr)
			h.Logout(c)
		})

		req, _ := http.NewRequest(http.MethodGet, "/logout", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "/logged_out", w.Header().Get("Location"))
	})

	t.Run("Logout with valid post_logout_redirect_uri", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := gin.New()
		r.GET("/logout", func(c *gin.Context) {
			mgr := &mockCookieManager{data: make(map[string]any)}
			c.Set(definitions.CtxSecureDataKey, mgr)
			h.Logout(c)
		})

		// Create a mock ID token hint (openid scope required per OIDC Core 1.0 §3.1.2.1)
		idToken, _, _, _, _ := idpInstance.IssueTokens(context.Background(), &idp.OIDCSession{
			ClientID: "test-client",
			UserID:   "user123",
			Scopes:   []string{definitions.ScopeOpenId},
			AuthTime: time.Now(),
		})

		// Expectations for DeleteUserRefreshTokens
		userKey := "test:oidc:user_refresh_tokens:user123"
		mock.ExpectSMembers(userKey).SetVal([]string{})

		logoutURL := "/logout?id_token_hint=" + idToken + "&post_logout_redirect_uri=https://app.com/post-logout"
		req, _ := http.NewRequest(http.MethodGet, logoutURL, nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "https://app.com/post-logout", w.Header().Get("Location"))
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Logout with client in session and LogoutRedirectURI", func(t *testing.T) {
		clientWithLogout := config.OIDCClient{
			ClientID:          "logout-client",
			LogoutRedirectURI: "https://custom-logout.com",
		}
		cfg.clients = append(cfg.clients, clientWithLogout)

		w := httptest.NewRecorder()
		r := gin.New()
		r.GET("/logout", func(c *gin.Context) {
			mgr := &mockCookieManager{data: map[string]any{
				definitions.SessionKeyOIDCClients: "logout-client",
			}}
			c.Set(definitions.CtxSecureDataKey, mgr)
			h.Logout(c)
		})

		req, _ := http.NewRequest(http.MethodGet, "/logout", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "https://custom-logout.com", w.Header().Get("Location"))
	})

	t.Run("Logout with front-channel task renders orchestration page", func(t *testing.T) {
		clientWithFrontChannel := config.OIDCClient{
			ClientID:               "frontchannel-client",
			FrontChannelLogoutURI:  "https://frontchannel.example.com/logout",
			PostLogoutRedirectURIs: []string{"https://app.com/post-logout"},
		}
		cfg.clients = append(cfg.clients, clientWithFrontChannel)

		w := httptest.NewRecorder()
		r := gin.New()
		r.SetHTMLTemplate(template.Must(template.New("idp_logout_frames.html").Parse("{{ .LogoutTarget }}|{{ .FrontChannelLogoutTaskConfig }}")))
		r.GET("/logout", func(c *gin.Context) {
			mgr := &mockCookieManager{data: map[string]any{
				definitions.SessionKeyOIDCClients: "frontchannel-client",
			}}
			c.Set(definitions.CtxSecureDataKey, mgr)
			h.Logout(c)
		})

		idToken, _, _, _, _ := idpInstance.IssueTokens(context.Background(), &idp.OIDCSession{
			ClientID: "frontchannel-client",
			UserID:   "user-front",
			Scopes:   []string{definitions.ScopeOpenId},
			AuthTime: time.Now(),
		})

		userKey := "test:oidc:user_refresh_tokens:user-front"
		mock.ExpectSMembers(userKey).SetVal([]string{})

		req, _ := http.NewRequest(
			http.MethodGet,
			"/logout?id_token_hint="+url.QueryEscape(idToken)+"&post_logout_redirect_uri="+url.QueryEscape("https://app.com/post-logout")+"&state=s-1",
			nil,
		)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		body := html.UnescapeString(w.Body.String())
		assert.Contains(t, body, "https://app.com/post-logout?state=s-1")
		assert.Contains(t, body, "frontchannel.example.com/logout")
		assert.Contains(t, body, "\"protocol\":\"oidc\"")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestBuildSAMLFrontChannelLogoutTasks(t *testing.T) {
	postBody := "<html><body><form id=\"SAMLRequestForm\"></form></body></html>"
	result := &sloFanoutResult{
		Dispatches: []sloFanoutDispatch{
			{
				Participant: slodomain.SLOParticipant{
					EntityID: "https://sp-a.example.com/metadata",
				},
				RedirectURL: "https://sp-a.example.com/saml/slo?SAMLRequest=req-a",
			},
			{
				Participant: slodomain.SLOParticipant{
					EntityID: "https://sp-b.example.com/metadata",
				},
				PostBody: postBody,
			},
		},
		Failures: []sloFanoutFailure{
			{
				EntityID: "https://sp-c.example.com/metadata",
				Err:      fmt.Errorf("missing endpoint"),
			},
		},
	}

	tasks := buildSAMLFrontChannelLogoutTasks(result)
	if assert.Len(t, tasks, 3) {
		assert.Equal(t, frontChannelLogoutTaskProtocolSAML, tasks[0].Protocol)
		assert.Equal(t, frontChannelLogoutTaskMethodGET, tasks[0].Method)
		assert.Equal(t, "https://sp-a.example.com/saml/slo?SAMLRequest=req-a", tasks[0].URL)

		assert.Equal(t, frontChannelLogoutTaskMethodPOST, tasks[1].Method)
		rawPayload, err := base64.StdEncoding.DecodeString(tasks[1].PayloadBase64)
		if assert.NoError(t, err) {
			assert.Equal(t, postBody, string(rawPayload))
		}

		assert.Equal(t, frontChannelLogoutTaskMethodNone, tasks[2].Method)
		assert.Equal(t, frontChannelLogoutTaskStatusError, tasks[2].InitialStatus)
		assert.Contains(t, tasks[2].InitialDetail, "missing endpoint")
	}
}

func TestAppendStateToLogoutTarget(t *testing.T) {
	assert.Equal(t, "https://app.example.com/logout?state=abc", appendStateToLogoutTarget("https://app.example.com/logout", "abc"))
	assert.Equal(t, "https://app.example.com/logout?foo=bar&state=abc", appendStateToLogoutTarget("https://app.example.com/logout?foo=bar", "abc"))
	assert.Equal(t, "/logged_out?state=abc", appendStateToLogoutTarget("/logged_out", "abc"))
	assert.Equal(t, "not a url", appendStateToLogoutTarget("not a url", "abc"))
	assert.Equal(t, "https://app.example.com/logout", appendStateToLogoutTarget("https://app.example.com/logout", ""))
}

func Test_oidcAuthorizeFlowContext_HasClientConsent(t *testing.T) {
	t.Run("returns false when no clients in cookie", func(t *testing.T) {
		mgr := &mockCookieManager{data: make(map[string]any)}
		flowContext := newOIDCAuthorizeFlowContext(mgr)

		assert.False(t, flowContext.HasClientConsent("client1", []string{"openid"}))
	})

	t.Run("returns true when client is in cookie", func(t *testing.T) {
		mgr := &mockCookieManager{data: map[string]any{
			definitions.SessionKeyOIDCClients: "client1,client2",
		}}
		flowContext := newOIDCAuthorizeFlowContext(mgr)

		assert.True(t, flowContext.HasClientConsent("client1", []string{"openid"}))
		assert.True(t, flowContext.HasClientConsent("client2", []string{"openid"}))
		assert.False(t, flowContext.HasClientConsent("client3", []string{"openid"}))
	})

	t.Run("returns false when consent entry has expired", func(t *testing.T) {
		expired := time.Now().Add(-time.Minute).Unix()
		mgr := &mockCookieManager{data: map[string]any{
			definitions.SessionKeyOIDCConsentExpiries: `{"client1":[{"scopes":["openid","profile"],"expiry":` + strconv.FormatInt(expired, 10) + `}]}`,
		}}
		flowContext := newOIDCAuthorizeFlowContext(mgr)

		assert.False(t, flowContext.HasClientConsent("client1", []string{"openid"}))
	})

	t.Run("returns true when requested scopes are covered by granted scopes", func(t *testing.T) {
		valid := time.Now().Add(time.Minute).Unix()
		mgr := &mockCookieManager{data: map[string]any{
			definitions.SessionKeyOIDCConsentExpiries: `{"client1":[{"scopes":["email","openid","profile"],"expiry":` + strconv.FormatInt(valid, 10) + `}]}`,
		}}
		flowContext := newOIDCAuthorizeFlowContext(mgr)

		assert.True(t, flowContext.HasClientConsent("client1", []string{"openid", "profile"}))
		assert.False(t, flowContext.HasClientConsent("client1", []string{"openid", "groups"}))
	})
}

func Test_oidcAuthorizeFlowContext_AddClientConsent(t *testing.T) {
	t.Run("adds client to empty cookie", func(t *testing.T) {
		mgr := &mockCookieManager{data: make(map[string]any)}
		flowContext := newOIDCAuthorizeFlowContext(mgr)

		flowContext.AddClientConsent("client1", []string{"openid", "profile"}, time.Hour)

		assert.Equal(t, "client1", mgr.data[definitions.SessionKeyOIDCClients])
	})

	t.Run("appends client to existing cookie", func(t *testing.T) {
		mgr := &mockCookieManager{data: map[string]any{
			definitions.SessionKeyOIDCClients: "client1",
		}}
		flowContext := newOIDCAuthorizeFlowContext(mgr)

		flowContext.AddClientConsent("client2", []string{"openid"}, time.Hour)

		assert.Equal(t, "client1,client2", mgr.data[definitions.SessionKeyOIDCClients])
	})

	t.Run("does not duplicate client in cookie", func(t *testing.T) {
		mgr := &mockCookieManager{data: map[string]any{
			definitions.SessionKeyOIDCClients: "client1,client2",
		}}
		flowContext := newOIDCAuthorizeFlowContext(mgr)

		flowContext.AddClientConsent("client1", []string{"openid"}, time.Hour)

		assert.Equal(t, "client1,client2", mgr.data[definitions.SessionKeyOIDCClients])
	})
}

func Test_oidcAuthorizeFlowContext_StoreRequest(t *testing.T) {
	mgr := &mockCookieManager{data: make(map[string]any)}
	flowContext := newOIDCAuthorizeFlowContext(mgr)

	flowContext.StoreRequest("my-client", "https://app.example.com/cb", "openid profile", "state-1", "nonce-1", "code", "consent")

	// Flow request data is stored via FlowController metadata; context keeps protocol only.
	assert.Equal(t, definitions.ProtoOIDC, mgr.GetString(definitions.SessionKeyProtocol, ""))
}

func Test_oidcDeviceFlowContext(t *testing.T) {
	t.Run("stores and reads device flow values", func(t *testing.T) {
		mgr := &mockCookieManager{data: make(map[string]any)}
		flowContext := newOIDCDeviceFlowContext(mgr)

		flowContext.StoreMFAContext("alice", "uid-1", "dc-1", "client-1", definitions.ProtoOIDC, definitions.AuthResultOK, true)

		assert.Equal(t, "", flowContext.DeviceCode())
		assert.Equal(t, "uid-1", flowContext.UniqueUserID())
		assert.Equal(t, "alice", mgr.GetString(definitions.SessionKeyUsername, ""))
		assert.Equal(t, definitions.ProtoOIDC, mgr.GetString(definitions.SessionKeyProtocol, ""))
	})

	t.Run("clear device code is a no-op in context helper", func(t *testing.T) {
		mgr := &mockCookieManager{data: map[string]any{definitions.SessionKeyDeviceCode: "dc-1"}}
		flowContext := newOIDCDeviceFlowContext(mgr)

		flowContext.ClearDeviceCode()

		assert.Equal(t, "dc-1", flowContext.DeviceCode())
	})
}

func Test_cleanupIdPFlowState(t *testing.T) {
	flowKeys := []string{
		// Common IdP flow keys
		definitions.SessionKeyIdPFlowType,
		definitions.SessionKeyIdPFlowID,
		// OIDC-specific flow keys
		definitions.SessionKeyOIDCGrantType,
		definitions.SessionKeyIdPClientID,
		definitions.SessionKeyIdPRedirectURI,
		definitions.SessionKeyIdPScope,
		definitions.SessionKeyIdPState,
		definitions.SessionKeyIdPNonce,
		definitions.SessionKeyIdPResponseType,
		definitions.SessionKeyIdPPrompt,
		// SAML-specific flow keys
		definitions.SessionKeyIdPSAMLRequest,
		definitions.SessionKeyIdPSAMLRelayState,
		definitions.SessionKeyIdPSAMLEntityID,
		definitions.SessionKeyIdPOriginalURL,
		definitions.SessionKeyRequireMFAParentFlowID,
	}

	t.Run("removes all IdP flow state keys including OIDC and SAML", func(t *testing.T) {
		mgr := &mockCookieManager{data: map[string]any{
			// OIDC keys
			definitions.SessionKeyIdPFlowType:     definitions.ProtoOIDC,
			definitions.SessionKeyIdPFlowID:       "flow-oidc-cleanup",
			definitions.SessionKeyOIDCGrantType:   definitions.OIDCFlowAuthorizationCode,
			definitions.SessionKeyIdPClientID:     "my-app",
			definitions.SessionKeyIdPRedirectURI:  "https://app.example.com/callback",
			definitions.SessionKeyIdPScope:        "openid profile email",
			definitions.SessionKeyIdPState:        "state123",
			definitions.SessionKeyIdPNonce:        "nonce456",
			definitions.SessionKeyIdPResponseType: "code",
			definitions.SessionKeyIdPPrompt:       "consent",
			// SAML keys
			definitions.SessionKeyIdPSAMLRequest:         "<saml-request>",
			definitions.SessionKeyIdPSAMLRelayState:      "relay-state",
			definitions.SessionKeyIdPSAMLEntityID:        "https://sp.example.com",
			definitions.SessionKeyIdPOriginalURL:         "/saml/sso?SAMLRequest=abc",
			definitions.SessionKeyRequireMFAParentFlowID: "flow-parent",
			// Non-flow keys (must survive)
			definitions.SessionKeyAccount:     "user@example.com",
			definitions.SessionKeyOIDCClients: "my-app",
		}}

		CleanupIdPFlowState(mgr)

		for _, key := range flowKeys {
			_, exists := mgr.data[key]
			assert.False(t, exists, "key %q should have been deleted", key)
		}

		// Non-flow keys must be preserved
		assert.Equal(t, "user@example.com", mgr.data[definitions.SessionKeyAccount])
		assert.Equal(t, "my-app", mgr.data[definitions.SessionKeyOIDCClients])
	})

	t.Run("handles nil manager gracefully", func(t *testing.T) {
		assert.NotPanics(t, func() {
			CleanupIdPFlowState(nil)
		})
	})

	t.Run("handles empty manager gracefully", func(t *testing.T) {
		mgr := &mockCookieManager{data: make(map[string]any)}

		assert.NotPanics(t, func() {
			CleanupIdPFlowState(mgr)
		})
	})
}

func Test_cleanupMFAState(t *testing.T) {
	mfaKeys := []string{
		definitions.SessionKeyUsername,
		definitions.SessionKeyAuthResult,
		definitions.SessionKeyMFAMulti,
		definitions.SessionKeyMFAMethod,
		definitions.SessionKeyMFACompleted,
	}

	t.Run("removes all MFA state keys", func(t *testing.T) {
		mgr := &mockCookieManager{data: map[string]any{
			definitions.SessionKeyUsername:     "user@example.com",
			definitions.SessionKeyAuthResult:   uint8(1),
			definitions.SessionKeyMFAMulti:     true,
			definitions.SessionKeyMFAMethod:    "totp",
			definitions.SessionKeyMFACompleted: true,
			// Non-MFA keys (must survive)
			definitions.SessionKeyAccount:     "user@example.com",
			definitions.SessionKeyOIDCClients: "my-app",
			definitions.SessionKeyProtocol:    definitions.ProtoOIDC,
		}}

		CleanupMFAState(mgr)

		for _, key := range mfaKeys {
			_, exists := mgr.data[key]
			assert.False(t, exists, "key %q should have been deleted", key)
		}

		// Non-MFA keys must be preserved
		assert.Equal(t, "user@example.com", mgr.data[definitions.SessionKeyAccount])
		assert.Equal(t, "my-app", mgr.data[definitions.SessionKeyOIDCClients])
		assert.Equal(t, definitions.ProtoOIDC, mgr.data[definitions.SessionKeyProtocol])
	})

	t.Run("handles nil manager gracefully", func(t *testing.T) {
		assert.NotPanics(t, func() {
			CleanupMFAState(nil)
		})
	})

	t.Run("handles empty manager gracefully", func(t *testing.T) {
		mgr := &mockCookieManager{data: make(map[string]any)}

		assert.NotPanics(t, func() {
			CleanupMFAState(mgr)
		})
	})
}

// mockCookieManager implements cookie.Manager for testing.
type mockCookieManager struct {
	data map[string]any
}

func (m *mockCookieManager) Set(key string, value any) {
	m.data[key] = value
}

func (m *mockCookieManager) Get(key string) (any, bool) {
	val, ok := m.data[key]
	return val, ok
}

func (m *mockCookieManager) Delete(key string) {
	delete(m.data, key)
}

func (m *mockCookieManager) Clear() {
	m.data = make(map[string]any)
}

func (m *mockCookieManager) Save(_ *gin.Context) error {
	return nil
}

func (m *mockCookieManager) Load(_ *gin.Context) error {
	return nil
}

func (m *mockCookieManager) GetString(key string, defaultValue string) string {
	if val, ok := m.data[key]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return defaultValue
}

func (m *mockCookieManager) GetInt(key string, defaultValue int) int {
	if val, ok := m.data[key]; ok {
		if i, ok := val.(int); ok {
			return i
		}
	}
	return defaultValue
}

func (m *mockCookieManager) GetInt64(key string, defaultValue int64) int64 {
	if val, ok := m.data[key]; ok {
		if i, ok := val.(int64); ok {
			return i
		}
	}
	return defaultValue
}

func (m *mockCookieManager) GetUint8(key string, defaultValue uint8) uint8 {
	if val, ok := m.data[key]; ok {
		if i, ok := val.(uint8); ok {
			return i
		}
	}
	return defaultValue
}

func (m *mockCookieManager) GetBool(key string, defaultValue bool) bool {
	if val, ok := m.data[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return defaultValue
}

func (m *mockCookieManager) GetStringSlice(key string, defaultValue []string) []string {
	if val, ok := m.data[key]; ok {
		if s, ok := val.([]string); ok {
			return s
		}
	}
	return defaultValue
}

func (m *mockCookieManager) GetDuration(key string, defaultValue time.Duration) time.Duration {
	if val, ok := m.data[key]; ok {
		if d, ok := val.(time.Duration); ok {
			return d
		}
	}
	return defaultValue
}

func (m *mockCookieManager) Debug(_ *gin.Context, _ *slog.Logger, _ string) {}

func (m *mockCookieManager) HasKey(key string) bool {
	_, ok := m.data[key]
	return ok
}

func (m *mockCookieManager) GetBytes(key string, defaultValue []byte) []byte {
	if val, ok := m.data[key]; ok {
		if b, ok := val.([]byte); ok {
			return b
		}
	}
	return defaultValue
}

func (m *mockCookieManager) SetMaxAge(_ int) {}

func (m *mockCookieManager) ComputeHMAC(data []byte) []byte {
	// Deterministic mock HMAC for testing: SHA256 of data with a fixed test key.
	h := hmac.New(sha256.New, []byte("test-hmac-key-for-mock"))
	h.Write(data)

	return h.Sum(nil)
}

func TestOIDCHandler_Consent(t *testing.T) {
	t.Run("Authorize redirects to consent when not authorized", func(t *testing.T) {
		t.Skip("Skipping integration test due to complex IdP dependencies. hasClientConsent is covered by unit tests.")
	})

	t.Run("Authorize skips consent when already authorized", func(t *testing.T) {
		t.Skip("Skipping integration test due to complex IdP dependencies. hasClientConsent is covered by unit tests.")
	})

	t.Run("ConsentPOST redirects with code and state", func(t *testing.T) {
		t.Skip("Skipping integration test due to complex IdP dependencies. addClientToSession is covered by unit tests.")
	})

	t.Run("ConsentPOST with state in query", func(t *testing.T) {
		t.Skip("Skipping integration test due to complex IdP dependencies. addClientToSession is covered by unit tests.")
	})
}

func TestOIDCHandler_Introspect(t *testing.T) {
	gin.SetMode(gin.TestMode)
	issuer := "https://auth.example.com"
	signingKey := secret.New(generateTestKey())
	client := config.OIDCClient{
		ClientID:     "test-client",
		ClientSecret: secret.New("test-secret"),
	}

	cfg := &mockOIDCCfg{
		issuer:     issuer,
		signingKey: signingKey,
		clients:    []config.OIDCClient{client},
	}

	db, mock := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)

	d := &deps.Deps{
		Cfg:    cfg,
		Redis:  rClient,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	idpInstance := idp.NewNauthilusIdP(d)
	h := NewOIDCHandler(d, idpInstance, nil)

	// Issue a token first
	accessToken, _, _, _, _ := idpInstance.IssueTokens(context.Background(), &idp.OIDCSession{
		ClientID: "test-client",
		UserID:   "user123",
		AuthTime: time.Now(),
		Scopes:   []string{"openid", "profile"},
	})

	t.Run("Valid token introspection", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = httptest.NewRequest(http.MethodPost, "/oidc/introspect", nil)
		ctx.Request.PostForm = url.Values{
			"token": {accessToken},
		}
		ctx.Request.SetBasicAuth("test-client", "test-secret")

		h.Introspect(ctx)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.True(t, resp["active"].(bool))
		assert.Equal(t, "user123", resp["sub"])
		assert.Equal(t, "test-client", resp["aud"])
	})

	t.Run("Invalid token introspection", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = httptest.NewRequest(http.MethodPost, "/oidc/introspect", nil)
		ctx.Request.PostForm = url.Values{
			"token": {"invalid-token"},
		}
		ctx.Request.SetBasicAuth("test-client", "test-secret")

		h.Introspect(ctx)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.False(t, resp["active"].(bool))
	})

	t.Run("Unauthorized client", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = httptest.NewRequest(http.MethodPost, "/oidc/introspect", nil)
		ctx.Request.PostForm = url.Values{
			"token": {accessToken},
		}
		ctx.Request.SetBasicAuth("other-client", "wrong-secret")

		h.Introspect(ctx)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOIDCHandler_Token(t *testing.T) {
	definitions.SetDbgModuleMapping(definitions.NewDbgModuleMapping())
	gin.SetMode(gin.TestMode)
	issuer := "https://auth.example.com"
	signingKey := secret.New(generateTestKey())
	client := config.OIDCClient{
		ClientID:     "test-client",
		ClientSecret: secret.New("test-secret"),
		RedirectURIs: []string{"https://app.com/callback"},
	}

	cfg := &mockOIDCCfg{
		issuer:     issuer,
		signingKey: signingKey,
		clients:    []config.OIDCClient{client},
	}

	db, mock := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)

	d := &deps.Deps{
		Cfg:    cfg,
		Redis:  rClient,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	idpInstance := idp.NewNauthilusIdP(d)
	h := NewOIDCHandler(d, idpInstance, nil)

	t.Run("Token request with Basic Auth", func(t *testing.T) {
		code := "code123"
		oidcSession := &idp.OIDCSession{
			ClientID:    "test-client",
			UserID:      "user123",
			Scopes:      []string{definitions.ScopeOpenId},
			RedirectURI: "https://app.com/callback",
			Nonce:       "test-nonce",
		}
		sessionData, _ := json.Marshal(oidcSession)

		mock.ExpectGet("test:oidc:code:" + code).SetVal(string(sessionData))
		mock.ExpectDel("test:oidc:code:" + code).SetVal(1)

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		form := url.Values{}
		form.Add("grant_type", "authorization_code")
		form.Add("code", code)
		form.Add("redirect_uri", "https://app.com/callback")

		req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("test-client", "test-secret")
		ctx.Request = req

		h.Token(ctx)

		assert.Equal(t, http.StatusOK, w.Code)

		// Verifiziere ID-Token Inhalt (optional, da wir IssueTokens bereits separat testen)
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NotEmpty(t, resp["id_token"])

		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Token request with client_id in body and secret in Basic Auth (should fail)", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		form := url.Values{}
		form.Add("grant_type", "authorization_code")
		form.Add("code", "any-code")
		form.Add("client_id", "test-client") // client_id im Body

		req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("test-client", "test-secret") // secret im Header
		ctx.Request = req

		h.Token(ctx)

		// MUST NOT use more than one authentication method
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Token request with URL-encoded characters in Basic Auth", func(t *testing.T) {
		code := "code789"
		specialClientID := "client@test"
		specialSecret := "pass+word"
		oidcSession := &idp.OIDCSession{
			ClientID:    specialClientID,
			UserID:      "user123",
			Scopes:      []string{definitions.ScopeOpenId},
			RedirectURI: "https://app.com/callback",
		}
		sessionData, _ := json.Marshal(oidcSession)

		// Mock client with special characters
		cfg.clients = append(cfg.clients, config.OIDCClient{
			ClientID:     specialClientID,
			ClientSecret: secret.New(specialSecret),
			RedirectURIs: []string{"https://app.com/callback"},
		})

		mock.ExpectGet("test:oidc:code:" + code).SetVal(string(sessionData))
		mock.ExpectDel("test:oidc:code:" + code).SetVal(1)

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		form := url.Values{}
		form.Add("grant_type", "authorization_code")
		form.Add("code", code)
		form.Add("redirect_uri", "https://app.com/callback")

		req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// URL-encode parts manually to simulate RFC 6749 Section 2.3.1
		authValue := url.QueryEscape(specialClientID) + ":" + url.QueryEscape(specialSecret)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(authValue)))
		ctx.Request = req

		h.Token(ctx)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Token request with both Header and Body (matching - should fail)", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		form := url.Values{}
		form.Add("grant_type", "authorization_code")
		form.Add("code", "any-code")
		form.Add("client_id", "test-client")
		form.Add("client_secret", "test-secret")

		req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("test-client", "test-secret")
		ctx.Request = req

		h.Token(ctx)

		// MUST NOT use more than one authentication method
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Token request with 11 vs 6 chars mismatch (reproduce user log)", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		form := url.Values{}
		form.Add("grant_type", "authorization_code")
		form.Add("code", "any-code")

		req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("test-client", "secret") // 6 chars
		ctx.Request = req

		h.Token(ctx)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Token request with multiple methods (should fail)", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		form := url.Values{}
		form.Add("grant_type", "authorization_code")
		form.Add("code", "any-code")
		form.Add("client_id", "test-client")
		form.Add("client_secret", "test-secret")

		req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("test-client", "test-secret")
		ctx.Request = req

		h.Token(ctx)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Equal(t, "invalid_client", resp["error"])
	})

	t.Run("Token request with enforced method (mismatch should fail)", func(t *testing.T) {
		// Update client to enforce basic auth
		cfg.clients[0].TokenEndpointAuthMethod = "client_secret_basic"

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		form := url.Values{}
		form.Add("grant_type", "authorization_code")
		form.Add("code", "any-code")
		form.Add("client_id", "test-client")
		form.Add("client_secret", "test-secret") // Post Body

		req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		ctx.Request = req

		h.Token(ctx)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Equal(t, "invalid_client", resp["error"])
	})

	t.Run("Token request with public client and client_id only in body", func(t *testing.T) {
		code := "public-client-code"
		verifier := strings.Repeat("c", 43)
		sum := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(sum[:])
		publicClient := config.OIDCClient{
			ClientID:                "public-client",
			RedirectURIs:            []string{"https://app.com/public-callback"},
			TokenEndpointAuthMethod: "none",
		}
		cfg.clients = append(cfg.clients, publicClient)

		oidcSession := &idp.OIDCSession{
			ClientID:            publicClient.ClientID,
			UserID:              "user123",
			Scopes:              []string{definitions.ScopeOpenId},
			RedirectURI:         "https://app.com/public-callback",
			CodeChallenge:       challenge,
			CodeChallengeMethod: "S256",
		}
		sessionData, _ := json.Marshal(oidcSession)

		mock.ExpectGet("test:oidc:code:" + code).SetVal(string(sessionData))
		mock.ExpectDel("test:oidc:code:" + code).SetVal(1)

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		form := url.Values{}
		form.Add("grant_type", "authorization_code")
		form.Add("client_id", publicClient.ClientID)
		form.Add("code", code)
		form.Add("redirect_uri", "https://app.com/public-callback")
		form.Add("code_verifier", verifier)

		req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		ctx.Request = req

		h.Token(ctx)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NotEmpty(t, resp["id_token"])
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Token request with PKCE S256 (valid verifier)", func(t *testing.T) {
		code := "pkce-s256-code"
		verifier := strings.Repeat("a", 43)
		sum := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(sum[:])
		oidcSession := &idp.OIDCSession{
			ClientID:            "test-client",
			UserID:              "user123",
			Scopes:              []string{definitions.ScopeOpenId},
			RedirectURI:         "https://app.com/callback",
			CodeChallenge:       challenge,
			CodeChallengeMethod: "S256",
		}
		sessionData, _ := json.Marshal(oidcSession)

		mock.ExpectGet("test:oidc:code:" + code).SetVal(string(sessionData))
		mock.ExpectDel("test:oidc:code:" + code).SetVal(1)

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		form := url.Values{}
		form.Add("grant_type", "authorization_code")
		form.Add("code", code)
		form.Add("redirect_uri", "https://app.com/callback")
		form.Add("code_verifier", verifier)

		req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("test-client", "test-secret")
		ctx.Request = req

		h.Token(ctx)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Token request with mismatched redirect_uri (must be rejected)", func(t *testing.T) {
		code := "redirect-uri-mismatch-code"
		verifier := strings.Repeat("a", 43)
		sum := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(sum[:])
		oidcSession := &idp.OIDCSession{
			ClientID:            "test-client",
			UserID:              "user123",
			Scopes:              []string{definitions.ScopeOpenId},
			RedirectURI:         "https://app.com/callback",
			CodeChallenge:       challenge,
			CodeChallengeMethod: "S256",
		}
		sessionData, _ := json.Marshal(oidcSession)

		mock.ExpectGet("test:oidc:code:" + code).SetVal(string(sessionData))
		mock.ExpectDel("test:oidc:code:" + code).SetVal(1)

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		form := url.Values{}
		form.Add("grant_type", "authorization_code")
		form.Add("code", code)
		form.Add("redirect_uri", "https://evil.com/callback")
		form.Add("code_verifier", verifier)

		req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("test-client", "test-secret")
		ctx.Request = req

		h.Token(ctx)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Equal(t, "invalid_grant", resp["error"])
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Token request with PKCE S256 (missing verifier should fail)", func(t *testing.T) {
		code := "pkce-s256-missing-verifier"
		oidcSession := &idp.OIDCSession{
			ClientID:            "test-client",
			UserID:              "user123",
			Scopes:              []string{definitions.ScopeOpenId},
			RedirectURI:         "https://app.com/callback",
			CodeChallenge:       "dummy",
			CodeChallengeMethod: "S256",
		}
		sessionData, _ := json.Marshal(oidcSession)

		mock.ExpectGet("test:oidc:code:" + code).SetVal(string(sessionData))
		mock.ExpectDel("test:oidc:code:" + code).SetVal(1)

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		form := url.Values{}
		form.Add("grant_type", "authorization_code")
		form.Add("code", code)
		form.Add("redirect_uri", "https://app.com/callback")

		req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("test-client", "test-secret")
		ctx.Request = req

		h.Token(ctx)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Equal(t, "invalid_grant", resp["error"])
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Token request with PKCE plain (must be rejected)", func(t *testing.T) {
		code := "pkce-plain-code"
		verifier := strings.Repeat("b", 43)
		oidcSession := &idp.OIDCSession{
			ClientID:            "test-client",
			UserID:              "user123",
			Scopes:              []string{definitions.ScopeOpenId},
			RedirectURI:         "https://app.com/callback",
			CodeChallenge:       verifier,
			CodeChallengeMethod: "plain",
		}
		sessionData, _ := json.Marshal(oidcSession)

		mock.ExpectGet("test:oidc:code:" + code).SetVal(string(sessionData))
		mock.ExpectDel("test:oidc:code:" + code).SetVal(1)

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		form := url.Values{}
		form.Add("grant_type", "authorization_code")
		form.Add("code", code)
		form.Add("redirect_uri", "https://app.com/callback")
		form.Add("code_verifier", verifier)

		req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("test-client", "test-secret")
		ctx.Request = req

		h.Token(ctx)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Equal(t, "invalid_grant", resp["error"])
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
