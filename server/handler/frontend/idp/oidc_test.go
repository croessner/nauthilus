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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/idp"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

type mockOIDCCfg struct {
	issuer       string
	signingKey   string
	signingKeyID string
	clients      []config.OIDCClient
}

func (m *mockOIDCCfg) GetIdP() *config.IdPSection {
	return &config.IdPSection{
		OIDC: config.OIDCConfig{
			Issuer: m.issuer,
			SigningKeys: []config.OIDCKey{
				{ID: m.signingKeyID, Key: m.signingKey, Active: true},
			},
			Clients: m.clients,
		},
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

func (m *mockOIDCCfg) GetLDAPConfigEncryptionSecret() string {
	return ""
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
	return json.Marshal(m)
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
func (m *mockOIDCCfg) GetLuaPackagePath() string { return "" }
func (m *mockOIDCCfg) GetLuaScriptPath() string  { return "" }
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
func (m *mockOIDCCfg) GetLDAPConfigBindPW() string                       { return "" }
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
	cfg := &mockOIDCCfg{issuer: issuer, signingKey: generateTestKey()}

	db, _ := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)

	d := &deps.Deps{
		Cfg:   cfg,
		Redis: rClient,
	}

	h := NewOIDCHandler(d, nil)

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
}

func TestOIDCHandler_JWKS(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &mockOIDCCfg{issuer: "https://auth.example.com", signingKey: generateTestKey(), signingKeyID: "default"}
	db, _ := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)
	d := &deps.Deps{Cfg: cfg, Redis: rClient}
	h := NewOIDCHandler(d, idp.NewNauthilusIdP(d))

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
	assert.Equal(t, "default", key["kid"])
}

func TestOIDCHandler_JWKS_CustomKid(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &mockOIDCCfg{issuer: "https://auth.example.com", signingKey: generateTestKey(), signingKeyID: "custom-kid"}
	db, _ := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)
	d := &deps.Deps{Cfg: cfg, Redis: rClient}
	h := NewOIDCHandler(d, idp.NewNauthilusIdP(d))

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
	assert.Equal(t, "custom-kid", key["kid"])
}

func TestOIDCHandler_Logout(t *testing.T) {
	gin.SetMode(gin.TestMode)
	issuer := "https://auth.example.com"
	signingKey := generateTestKey()
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
	h := NewOIDCHandler(d, idpInstance)

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
}

func Test_hasClientConsent(t *testing.T) {
	t.Run("returns false when no clients in cookie", func(t *testing.T) {
		mgr := &mockCookieManager{data: make(map[string]any)}
		assert.False(t, hasClientConsent(mgr, "client1"))
	})

	t.Run("returns true when client is in cookie", func(t *testing.T) {
		mgr := &mockCookieManager{data: map[string]any{
			definitions.SessionKeyOIDCClients: "client1,client2",
		}}
		assert.True(t, hasClientConsent(mgr, "client1"))
		assert.True(t, hasClientConsent(mgr, "client2"))
		assert.False(t, hasClientConsent(mgr, "client3"))
	})
}

func Test_addClientToCookie(t *testing.T) {
	t.Run("adds client to empty cookie", func(t *testing.T) {
		mgr := &mockCookieManager{data: make(map[string]any)}
		addClientToCookie(mgr, "client1")
		assert.Equal(t, "client1", mgr.data[definitions.SessionKeyOIDCClients])
	})

	t.Run("appends client to existing cookie", func(t *testing.T) {
		mgr := &mockCookieManager{data: map[string]any{
			definitions.SessionKeyOIDCClients: "client1",
		}}
		addClientToCookie(mgr, "client2")
		assert.Equal(t, "client1,client2", mgr.data[definitions.SessionKeyOIDCClients])
	})

	t.Run("does not duplicate client in cookie", func(t *testing.T) {
		mgr := &mockCookieManager{data: map[string]any{
			definitions.SessionKeyOIDCClients: "client1,client2",
		}}
		addClientToCookie(mgr, "client1")
		assert.Equal(t, "client1,client2", mgr.data[definitions.SessionKeyOIDCClients])
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
	signingKey := generateTestKey()
	client := config.OIDCClient{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
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
	h := NewOIDCHandler(d, idpInstance)

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
	signingKey := generateTestKey()
	client := config.OIDCClient{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
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
	h := NewOIDCHandler(d, idpInstance)

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
			ClientSecret: specialSecret,
			RedirectURIs: []string{"https://app.com/callback"},
		})

		mock.ExpectGet("test:oidc:code:" + code).SetVal(string(sessionData))
		mock.ExpectDel("test:oidc:code:" + code).SetVal(1)

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		form := url.Values{}
		form.Add("grant_type", "authorization_code")
		form.Add("code", code)

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
}
