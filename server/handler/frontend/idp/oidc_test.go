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
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/idp"
	"github.com/croessner/nauthilus/v3/server/idp/clientauth"
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/croessner/nauthilus/v3/server/idp/signing"
	slodomain "github.com/croessner/nauthilus/v3/server/idp/slo"
	mdcors "github.com/croessner/nauthilus/v3/server/middleware/cors"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

type mockOIDCCfg struct {
	issuer                string
	signingKey            secret.Value
	signingKeyID          string
	clients               []config.OIDCClient
	tokenEndpointAllowGET bool
	cors                  config.CORS
	trustedProxies        []string
}

func (m *mockOIDCCfg) GetIDP() *config.IDPSection {
	return &config.IDPSection{
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

func (m *mockOIDCCfg) GetPlugins() *config.PluginsSection {
	return &config.PluginsSection{}
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

	idpInstance := idp.NewNauthilusIDP(d)
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

func TestOIDCHandlerAuthorizeRejectsDuplicateSensitiveQueryValues(t *testing.T) {
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

	idpInstance := idp.NewNauthilusIDP(d)
	h := NewOIDCHandler(d, idpInstance, nil)

	for _, duplicateKey := range duplicateSensitiveAuthorizeParameters() {
		t.Run(duplicateKey, func(t *testing.T) {
			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)
			ctx.Request = httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+authorizeValuesWithDuplicate(duplicateKey).Encode(), nil)

			h.Authorize(ctx)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), "duplicate parameter")
		})
	}
}

func duplicateSensitiveAuthorizeParameters() []string {
	return []string{
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
}

func authorizeValuesWithDuplicate(duplicateKey string) url.Values {
	values := url.Values{}
	values.Add(oidcParamResponseType, oidcResponseTypeCode)
	values.Add(oidcParamClientID, "test-client")
	values.Add(oidcParamRedirectURI, "https://app.com/callback")
	values.Add(oidcParamScope, definitions.ScopeOpenID)
	values.Add(oidcParamState, "state-1")
	values.Add(oidcParamNonce, "nonce-1")

	if duplicateKey == oidcParamPrompt {
		values.Add(oidcParamPrompt, "login")
	}

	if duplicateKey == oidcParamCodeChallenge || duplicateKey == oidcParamCodeChallengeMethod {
		values.Add(oidcParamCodeChallenge, strings.Repeat("a", 43))
		values.Add(oidcParamCodeChallengeMethod, "S256")
	}

	values.Add(duplicateKey, "attacker-value")

	return values
}

func generateTestKey() string {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	return string(pemData)
}

const oidcTestJWTClaimSubject = "sub"

// generateTestClientKeyPair creates an RSA key pair for private_key_jwt handler tests.
func generateTestClientKeyPair(t testing.TB) (*rsa.PrivateKey, string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}

	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal client public key: %v", err)
	}

	publicPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKey,
	})

	return key, string(publicPEM)
}

// signTestClientAssertion signs a private_key_jwt assertion for the given audience.
func signTestClientAssertion(t testing.TB, key *rsa.PrivateKey, clientID string, audience string) string {
	t.Helper()

	return signTestClientAssertionWithJWTID(t, key, clientID, audience, "test-client-assertion")
}

// signTestClientAssertionWithJWTID signs a private_key_jwt assertion with a caller-provided jti.
func signTestClientAssertionWithJWTID(t testing.TB, key *rsa.PrivateKey, clientID string, audience string, jwtID string) string {
	t.Helper()

	signer := signing.NewRS256Signer(key, "test-client-kid")

	assertion, err := signer.Sign(jwt.MapClaims{
		"iss":                   clientID,
		oidcTestJWTClaimSubject: clientID,
		"aud":                   audience,
		"exp":                   time.Now().Add(5 * time.Minute).Unix(),
		"iat":                   time.Now().Unix(),
		"jti":                   jwtID,
	})
	if err != nil {
		t.Fatalf("sign client assertion: %v", err)
	}

	return assertion
}

// expectedOIDCClientAssertionReplayKey mirrors the Redis replay key scope.
func expectedOIDCClientAssertionReplayKey(clientID string, audience string, jwtID string) string {
	replayScope := clientID + "\x1f" + audience + "\x1f" + jwtID
	sum := sha256.Sum256([]byte(replayScope))

	return "test:oidc:client_assertion:replay:" + fmt.Sprintf("%x", sum[:])
}

// expectOIDCClientAssertionReplayReservation matches private_key_jwt replay reservations.
func expectOIDCClientAssertionReplayReservation(t testing.TB, mock redismock.ClientMock, key string, stored bool) {
	t.Helper()

	mock.CustomMatch(func(_ []any, actual []any) error {
		if len(actual) != 6 {
			return fmt.Errorf("unexpected Redis command args: %v", actual)
		}

		actualKey, ok := actual[1].(string)
		if !ok {
			return fmt.Errorf("unexpected replay key type %T", actual[1])
		}

		if actual[0] != "set" || actualKey != key || !isLowerHexSuffix(actualKey, 64) ||
			actual[2] != "1" || actual[3] != "px" || actual[5] != "nx" {
			return fmt.Errorf("unexpected Redis SETNX command args: %v", actual)
		}

		ttlMillis, ok := actual[4].(int64)
		if !ok {
			return fmt.Errorf("unexpected Redis TTL type %T", actual[4])
		}

		ttl := time.Duration(ttlMillis) * time.Millisecond
		if ttl < 5*time.Minute+20*time.Second || ttl > 5*time.Minute+31*time.Second {
			return fmt.Errorf("unexpected Redis TTL %s", ttl)
		}

		return nil
	}).ExpectSetNX(key, "1", time.Minute).SetVal(stored)
}

// isLowerHexSuffix reports whether the key ends with a fixed-width lower-case hex digest.
func isLowerHexSuffix(key string, width int) bool {
	if len(key) < width {
		return false
	}

	suffix := key[len(key)-width:]
	for _, char := range suffix {
		if (char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') {
			continue
		}

		return false
	}

	return true
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
		CORS:           m.cors,
		TrustedProxies: m.trustedProxies,
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
func (m *mockOIDCCfg) GetExternalSessionID() string {
	return "X-External-Session-ID"
}
func (m *mockOIDCCfg) GetClientHost() string { return "X-Nauthilus-Client-Host" }
func (m *mockOIDCCfg) GetLocalIP() string    { return "X-Local-IP" }
func (m *mockOIDCCfg) GetLocalPort() string  { return "X-Local-Port" }
func (m *mockOIDCCfg) GetUsername() string   { return "X-Nauthilus-Username" }
func (m *mockOIDCCfg) GetPassword() string   { return "X-Nauthilus-Password" }
func (m *mockOIDCCfg) HandleFile() error     { return nil }
func (m *mockOIDCCfg) GetConfigFileAsJSON() ([]byte, error) {
	return []byte("{}"), nil
}
func (m *mockOIDCCfg) HaveLuaEnvironmentSources() bool { return false }
func (m *mockOIDCCfg) HaveLuaSubjectSources() bool     { return false }
func (m *mockOIDCCfg) HaveLuaHooks() bool              { return false }
func (m *mockOIDCCfg) HaveLuaActions() bool            { return false }
func (m *mockOIDCCfg) HaveLua() bool                   { return false }
func (m *mockOIDCCfg) HaveLuaBackend() bool            { return false }
func (m *mockOIDCCfg) HaveLDAPBackend() bool           { return false }
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
func (m *mockOIDCCfg) HasRuntimeModule(string) bool {
	return false
}
func (m *mockOIDCCfg) ShouldRunControl(string, bool) bool {
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
func (m *mockOIDCCfg) GetSSLClientIssuerDN() string           { return "" }
func (m *mockOIDCCfg) GetSSLCipher() string                   { return "" }
func (m *mockOIDCCfg) GetSSLProtocol() string                 { return "" }
func (m *mockOIDCCfg) GetSSLSerial() string                   { return "" }
func (m *mockOIDCCfg) GetSSLFingerprint() string              { return "" }
func (m *mockOIDCCfg) GetLuaNumberOfWorkers() int             { return 0 }
func (m *mockOIDCCfg) GetLuaActionNumberOfWorkers() int       { return 0 }
func (m *mockOIDCCfg) GetLuaEnvironmentSourceVMPoolSize() int { return 0 }
func (m *mockOIDCCfg) GetLuaSubjectSourceVMPoolSize() int     { return 0 }
func (m *mockOIDCCfg) GetLuaHookVMPoolSize() int              { return 0 }
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
	resp := mustGetOIDCDiscoveryResponse(t, issuer)

	assertOIDCDiscoveryEndpoints(t, resp, issuer)
	assertOIDCDiscoveryFlowSupport(t, resp)
	assertOIDCDiscoveryClientAuthSupport(t, resp)
	assertOIDCDiscoveryIntrospectionSupport(t, resp)
	assertOIDCDiscoveryPKCESupport(t, resp)
}

// mustGetOIDCDiscoveryResponse executes discovery and returns the JSON payload.
func mustGetOIDCDiscoveryResponse(t *testing.T, issuer string) map[string]any {
	t.Helper()

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

	return resp
}

// assertOIDCDiscoveryEndpoints verifies discovery endpoint metadata.
func assertOIDCDiscoveryEndpoints(t *testing.T, resp map[string]any, issuer string) {
	t.Helper()

	assert.Equal(t, issuer, resp["issuer"])
	assert.Equal(t, issuer+"/oidc/authorize", resp["authorization_endpoint"])
	assert.Equal(t, issuer+"/oidc/token", resp["token_endpoint"])
	assert.Equal(t, issuer+"/oidc/introspect", resp["introspection_endpoint"])
	assert.Equal(t, issuer+"/oidc/logout", resp["end_session_endpoint"])
}

// assertOIDCDiscoveryFlowSupport verifies flow and grant metadata.
func assertOIDCDiscoveryFlowSupport(t *testing.T, resp map[string]any) {
	t.Helper()

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
}

// assertOIDCDiscoveryClientAuthSupport verifies token endpoint auth metadata.
func assertOIDCDiscoveryClientAuthSupport(t *testing.T, resp map[string]any) {
	t.Helper()

	assertOIDCDiscoveryAuthMetadata(t, resp, "token_endpoint_auth_methods_supported", "token_endpoint_auth_signing_alg_values_supported", true)
}

// assertOIDCDiscoveryIntrospectionSupport verifies introspection auth metadata.
func assertOIDCDiscoveryIntrospectionSupport(t *testing.T, resp map[string]any) {
	t.Helper()

	assertOIDCDiscoveryAuthMetadata(t, resp, "introspection_endpoint_auth_methods_supported", "introspection_endpoint_auth_signing_alg_values_supported", false)
}

// assertOIDCDiscoveryAuthMetadata verifies endpoint auth methods and signing algorithms.
func assertOIDCDiscoveryAuthMetadata(t *testing.T, resp map[string]any, methodsKey string, signingAlgsKey string, allowsNone bool) {
	t.Helper()

	authMethods := resp[methodsKey].([]any)
	assert.Contains(t, authMethods, "client_secret_basic")
	assert.Contains(t, authMethods, "client_secret_post")
	assert.Contains(t, authMethods, "private_key_jwt")

	if allowsNone {
		assert.Contains(t, authMethods, "none")
	} else {
		assert.NotContains(t, authMethods, "none")
	}

	signingAlgs := resp[signingAlgsKey].([]any)
	assert.Contains(t, signingAlgs, "RS256")
	assert.Contains(t, signingAlgs, "EdDSA")
}

// assertOIDCDiscoveryPKCESupport verifies PKCE metadata.
func assertOIDCDiscoveryPKCESupport(t *testing.T, resp map[string]any) {
	t.Helper()

	codeChallengeMethods := resp["code_challenge_methods_supported"].([]any)
	assert.Contains(t, codeChallengeMethods, "S256")
	assert.NotContains(t, codeChallengeMethods, "plain")
}

func newOIDCTestRouter(t *testing.T, cfg *mockOIDCCfg, withCORS bool) *gin.Engine {
	t.Helper()

	db, _ := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)

	d := &deps.Deps{
		Cfg:         cfg,
		Env:         config.NewTestEnvironmentConfig(),
		LangManager: &mockLangManager{},
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:       rClient,
	}

	h := NewOIDCHandler(d, idp.NewNauthilusIDP(d), nil)

	r := gin.New()
	if withCORS {
		r.Use(mdcors.New(mdcors.MiddlewareConfig{Config: d.Cfg}).Handler())
	}

	h.Register(r)

	return r
}

func TestOIDCHandler_Discovery_EmitsCORSHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	issuer := "https://auth.example.com"
	allowedOrigin := "https://app.example.com"
	headersEnabled := true
	corsEnabled := true

	cfg := &mockOIDCCfg{
		issuer:     issuer,
		signingKey: secret.New(generateTestKey()),
		cors: config.CORS{
			Enabled: &headersEnabled,
			Policies: []config.CORSPolicy{
				{
					Name:         "oidc_discovery",
					Enabled:      &corsEnabled,
					PathPrefixes: []string{"/.well-known/"},
					AllowOrigins: []string{allowedOrigin},
					AllowMethods: []string{"GET", "OPTIONS"},
					AllowHeaders: []string{"Authorization", "Content-Type"},
					MaxAge:       600,
				},
			},
		},
	}

	r := newOIDCTestRouter(t, cfg, true)

	getReq := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	getReq.Header.Set("Origin", allowedOrigin)

	getResp := httptest.NewRecorder()
	r.ServeHTTP(getResp, getReq)

	assert.Equal(t, http.StatusOK, getResp.Code)
	assert.Equal(t, allowedOrigin, getResp.Header().Get("Access-Control-Allow-Origin"))

	optionsReq := httptest.NewRequest(http.MethodOptions, "/.well-known/openid-configuration", nil)
	optionsReq.Header.Set("Origin", allowedOrigin)
	optionsReq.Header.Set("Access-Control-Request-Method", "GET")
	optionsReq.Header.Set("Access-Control-Request-Headers", "Authorization")

	optionsResp := httptest.NewRecorder()
	r.ServeHTTP(optionsResp, optionsReq)

	assert.Equal(t, http.StatusNoContent, optionsResp.Code)
	assert.Equal(t, allowedOrigin, optionsResp.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "GET, OPTIONS", optionsResp.Header().Get("Access-Control-Allow-Methods"))
	assert.Equal(t, "Authorization, Content-Type", optionsResp.Header().Get("Access-Control-Allow-Headers"))
}

func TestOIDCHandler_Register_DeviceVerifyLanguageRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	issuer := "https://auth.example.com"
	cfg := &mockOIDCCfg{issuer: issuer, signingKey: secret.New(generateTestKey())}

	r := newOIDCTestRouter(t, cfg, false)

	routes := r.Routes()
	hasRoute := func(method, path string) bool {
		return slices.IndexFunc(routes, func(route gin.RouteInfo) bool {
			return route.Method == method && route.Path == path
		}) >= 0
	}

	assert.True(t, hasRoute(http.MethodGet, "/oidc/device/verify/:languageTag"))
	assert.True(t, hasRoute(http.MethodPost, "/oidc/device/verify/:languageTag"))
	assert.True(t, hasRoute(http.MethodGet, "/.well-known/openid-configuration"))
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

		h := NewOIDCHandler(d, idp.NewNauthilusIDP(d), nil)
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
			h := NewOIDCHandler(d, idp.NewNauthilusIDP(d), nil)

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
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	fixture := newOIDCLogoutTest(t)

	t.Run("Logout without session redirects to logged_out", fixture.assertNoSessionLogout)
	t.Run("Logout with valid post_logout_redirect_uri", fixture.assertPostLogoutRedirect)
	t.Run("Logout with client in session and LogoutRedirectURI", fixture.assertSessionClientLogoutRedirect)
	t.Run("Logout with front-channel task renders orchestration page", fixture.assertFrontChannelLogoutPage)
}

func TestOIDCBackChannelLogoutDoesNotFollowRedirect(t *testing.T) {
	gin.SetMode(gin.TestMode)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	originalDefaultClient := http.DefaultClient

	var (
		callbackRequests   atomic.Int32
		redirectedRequests atomic.Int32
	)

	t.Cleanup(func() {
		http.DefaultClient = originalDefaultClient
	})

	http.DefaultClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Host {
			case "callback.example":
				callbackRequests.Add(1)

				return redirectResponse(req, "https://redirect.example/target"), nil
			case "redirect.example":
				redirectedRequests.Add(1)

				return noContentResponse(req), nil
			default:
				return noContentResponse(req), nil
			}
		}),
	}

	fixture := newOIDCLogoutTest(t)
	fixture.handler.doBackChannelLogout("test-client", "user123", "https://callback.example/logout")

	assert.Equal(t, int32(1), callbackRequests.Load())
	assert.Equal(t, int32(0), redirectedRequests.Load())
}

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// redirectResponse builds a synthetic redirect for HTTP client policy tests.
func redirectResponse(req *http.Request, location string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusFound,
		Header: http.Header{
			"Location": []string{location},
		},
		Body:    io.NopCloser(strings.NewReader("")),
		Request: req,
	}
}

// noContentResponse builds a synthetic successful response for HTTP client policy tests.
func noContentResponse(req *http.Request) *http.Response {
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}
}

type oidcLogoutTest struct {
	handler     *OIDCHandler
	idpInstance *idp.NauthilusIDP
	mock        redismock.ClientMock
	cfg         *mockOIDCCfg
}

// newOIDCLogoutTest builds an isolated OIDC logout fixture.
func newOIDCLogoutTest(t *testing.T) *oidcLogoutTest {
	t.Helper()

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

	idpInstance := idp.NewNauthilusIDP(d)

	return &oidcLogoutTest{
		handler:     NewOIDCHandler(d, idpInstance, nil),
		idpInstance: idpInstance,
		mock:        mock,
		cfg:         cfg,
	}
}

// serveLogout executes the logout route with optional session data and template.
func (f *oidcLogoutTest) serveLogout(target string, sessionData map[string]any, templateText string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()

	r := gin.New()
	if templateText != "" {
		r.SetHTMLTemplate(template.Must(template.New("idp_logout_frames.html").Parse(templateText)))
	}

	r.GET("/logout", func(c *gin.Context) {
		mgr := &mockCookieManager{data: sessionData}
		c.Set(definitions.CtxSecureDataKey, mgr)
		f.handler.Logout(c)
	})

	req, _ := http.NewRequest(http.MethodGet, target, nil)
	r.ServeHTTP(w, req)

	return w
}

// issueLogoutIDToken creates an ID token hint for logout tests.
func (f *oidcLogoutTest) issueLogoutIDToken(clientID, userID string) string {
	idToken, _, _, _, _ := f.idpInstance.IssueTokens(context.Background(), &idp.OIDCSession{
		ClientID: clientID,
		UserID:   userID,
		Scopes:   []string{definitions.ScopeOpenID},
		AuthTime: time.Now(),
	})

	return idToken
}

// assertNoSessionLogout verifies the default no-session redirect.
func (f *oidcLogoutTest) assertNoSessionLogout(t *testing.T) {
	w := f.serveLogout("/logout", make(map[string]any), "")

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/logged_out", w.Header().Get("Location"))
}

// assertPostLogoutRedirect verifies a valid post_logout_redirect_uri redirect.
func (f *oidcLogoutTest) assertPostLogoutRedirect(t *testing.T) {
	idToken := f.issueLogoutIDToken("test-client", "user123")
	f.mock.ExpectSMembers("test:oidc:user_refresh_tokens:user123").SetVal([]string{})

	logoutURL := "/logout?id_token_hint=" + idToken + "&post_logout_redirect_uri=https://app.com/post-logout"
	w := f.serveLogout(logoutURL, make(map[string]any), "")

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://app.com/post-logout", w.Header().Get("Location"))
	assert.NoError(t, f.mock.ExpectationsWereMet())
}

// assertSessionClientLogoutRedirect verifies client-specific session redirects.
func (f *oidcLogoutTest) assertSessionClientLogoutRedirect(t *testing.T) {
	f.cfg.clients = append(f.cfg.clients, config.OIDCClient{
		ClientID:          "logout-client",
		LogoutRedirectURI: "https://custom-logout.com",
	})

	sessionData := map[string]any{definitions.SessionKeyOIDCClients: "logout-client"}
	w := f.serveLogout("/logout", sessionData, "")

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://custom-logout.com", w.Header().Get("Location"))
}

// assertFrontChannelLogoutPage verifies front-channel logout orchestration output.
func (f *oidcLogoutTest) assertFrontChannelLogoutPage(t *testing.T) {
	f.cfg.clients = append(f.cfg.clients, config.OIDCClient{
		ClientID:               "frontchannel-client",
		FrontChannelLogoutURI:  "https://frontchannel.example.com/logout",
		PostLogoutRedirectURIs: []string{"https://app.com/post-logout"},
	})

	idToken := f.issueLogoutIDToken("frontchannel-client", "user-front")
	f.mock.ExpectSMembers("test:oidc:user_refresh_tokens:user-front").SetVal([]string{})

	target := "/logout?id_token_hint=" + url.QueryEscape(idToken) +
		"&post_logout_redirect_uri=" + url.QueryEscape("https://app.com/post-logout") +
		"&state=s-1"
	sessionData := map[string]any{definitions.SessionKeyOIDCClients: "frontchannel-client"}
	w := f.serveLogout(target, sessionData, "{{ .LogoutTarget }}|{{ .FrontChannelLogoutTaskConfig }}")

	assert.Equal(t, http.StatusOK, w.Code)
	body := html.UnescapeString(w.Body.String())
	assert.Contains(t, body, "https://app.com/post-logout?state=s-1")
	assert.Contains(t, body, "frontchannel.example.com/logout")
	assert.Contains(t, body, "\"protocol\":\"oidc\"")
	assert.NoError(t, f.mock.ExpectationsWereMet())
}

func TestBuildSAMLFrontChannelLogoutTasks(t *testing.T) {
	postBody := "<html><body><form id=\"SAMLRequestForm\"></form></body></html>"
	result := &sloFanoutResult{
		Dispatches: []sloFanoutDispatch{
			{
				Participant: slodomain.Participant{
					EntityID: "https://sp-a.example.com/metadata",
				},
				RedirectURL: "https://sp-a.example.com/saml/slo?SAMLRequest=req-a",
			},
			{
				Participant: slodomain.Participant{
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

func Test_cleanupIDPFlowState(t *testing.T) {
	t.Run("removes all IDP flow state keys including OIDC and SAML", func(t *testing.T) {
		mgr := newIDPFlowCleanupCookieManager()

		CleanupIDPFlowState(mgr)

		assertIDPFlowStateRemoved(t, mgr)
		assertIDPFlowStatePreserved(t, mgr)
	})

	t.Run("handles nil manager gracefully", func(t *testing.T) {
		assert.NotPanics(t, func() {
			CleanupIDPFlowState(nil)
		})
	})

	t.Run("handles empty manager gracefully", func(t *testing.T) {
		mgr := &mockCookieManager{data: make(map[string]any)}

		assert.NotPanics(t, func() {
			CleanupIDPFlowState(mgr)
		})
	})
}

// newIDPFlowCleanupCookieManager creates mixed OIDC/SAML flow state.
func newIDPFlowCleanupCookieManager() *mockCookieManager {
	return &mockCookieManager{data: map[string]any{
		definitions.SessionKeyIDPFlowType:            definitions.ProtoOIDC,
		definitions.SessionKeyIDPFlowID:              "flow-oidc-cleanup",
		definitions.SessionKeyOIDCGrantType:          definitions.OIDCFlowAuthorizationCode,
		definitions.SessionKeyIDPClientID:            "my-app",
		definitions.SessionKeyIDPRedirectURI:         "https://app.example.com/callback",
		definitions.SessionKeyIDPScope:               "openid profile email",
		definitions.SessionKeyIDPState:               "state123",
		definitions.SessionKeyIDPNonce:               "nonce456",
		definitions.SessionKeyIDPResponseType:        "code",
		definitions.SessionKeyIDPPrompt:              "consent",
		definitions.SessionKeyIDPSAMLRequest:         "<saml-request>",
		definitions.SessionKeyIDPSAMLRelayState:      "relay-state",
		definitions.SessionKeyIDPSAMLEntityID:        "https://sp.example.com",
		definitions.SessionKeyIDPOriginalURL:         "/saml/sso?SAMLRequest=abc",
		definitions.SessionKeyRequireMFAParentFlowID: "flow-parent",
		definitions.SessionKeyAccount:                "user@example.com",
		definitions.SessionKeyOIDCClients:            "my-app",
	}}
}

// idpFlowCleanupKeys returns all flow-scoped session keys.
func idpFlowCleanupKeys() []string {
	return []string{
		definitions.SessionKeyIDPFlowType,
		definitions.SessionKeyIDPFlowID,
		definitions.SessionKeyOIDCGrantType,
		definitions.SessionKeyIDPClientID,
		definitions.SessionKeyIDPRedirectURI,
		definitions.SessionKeyIDPScope,
		definitions.SessionKeyIDPState,
		definitions.SessionKeyIDPNonce,
		definitions.SessionKeyIDPResponseType,
		definitions.SessionKeyIDPPrompt,
		definitions.SessionKeyIDPSAMLRequest,
		definitions.SessionKeyIDPSAMLRelayState,
		definitions.SessionKeyIDPSAMLEntityID,
		definitions.SessionKeyIDPOriginalURL,
		definitions.SessionKeyRequireMFAParentFlowID,
	}
}

// assertIDPFlowStateRemoved verifies that flow-scoped keys were cleared.
func assertIDPFlowStateRemoved(t *testing.T, mgr *mockCookieManager) {
	t.Helper()

	for _, key := range idpFlowCleanupKeys() {
		_, exists := mgr.data[key]
		assert.False(t, exists, "key %q should have been deleted", key)
	}
}

// assertIDPFlowStatePreserved verifies that non-flow keys survive cleanup.
func assertIDPFlowStatePreserved(t *testing.T, mgr *mockCookieManager) {
	t.Helper()

	assert.Equal(t, "user@example.com", mgr.data[definitions.SessionKeyAccount])
	assert.Equal(t, "my-app", mgr.data[definitions.SessionKeyOIDCClients])
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
	data  map[string]any
	saves int
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
	m.saves++
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
		t.Skip("Skipping integration test due to complex IDP dependencies. hasClientConsent is covered by unit tests.")
	})

	t.Run("Authorize skips consent when already authorized", func(t *testing.T) {
		t.Skip("Skipping integration test due to complex IDP dependencies. hasClientConsent is covered by unit tests.")
	})

	t.Run("ConsentPOST redirects with code and state", func(t *testing.T) {
		t.Skip("Skipping integration test due to complex IDP dependencies. addClientToSession is covered by unit tests.")
	})

	t.Run("ConsentPOST with state in query", func(t *testing.T) {
		t.Skip("Skipping integration test due to complex IDP dependencies. addClientToSession is covered by unit tests.")
	})
}

func TestOIDCConsentRedirectEncodesDelimiterState(t *testing.T) {
	gin.SetMode(gin.TestMode)

	state := "alpha&code=injected&state=shadow=value%25&client_id=evil"
	handler, mock := newOIDCConsentCallbackRedirectTestHandler(t)
	ctx, recorder := newOIDCConsentRedirectTestContext(state)

	handler.ConsentPOST(ctx)

	assertOIDCCallbackLocation(t, recorder.Header().Get("Location"), state)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOIDCConsentPOSTRequireMFABlocksMissingAssurance(t *testing.T) {
	gin.SetMode(gin.TestMode)

	client := latchedConsentOIDCClient()
	client.RequireMFA = []string{definitions.MFAMethodTOTP}
	handler, mock := newOIDCConsentCallbackRedirectTestHandlerWithClient(t, client, false)
	ctx, recorder := newOIDCConsentRedirectTestContext("state-requires-mfa")
	ctx.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: map[string]any{
		definitions.SessionKeyAccount:      latchedConsentUsername,
		definitions.SessionKeyUniqueUserID: latchedConsentUserID,
		definitions.SessionKeyDisplayName:  "Alice Example",
		definitions.SessionKeySubject:      latchedConsentUserID,
		definitions.SessionKeyIDPFlowType:  definitions.ProtoOIDC,
		definitions.SessionKeyIDPClientID:  client.ClientID,
	}})

	handler.ConsentPOST(ctx)

	assert.Equal(t, frontendMFASelectPath, recorder.Header().Get("Location"))
	assert.NotContains(t, recorder.Header().Get("Location"), oidcParamCode+"=")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOIDCCallbackRedirectDirectAndConsentParity(t *testing.T) {
	gin.SetMode(gin.TestMode)

	state := "direct&code=injected&state=duplicate=value%25"

	directHandler, directMock := newOIDCDirectCallbackRedirectTestHandler(t)
	directCtx, directRecorder := newOIDCDirectCallbackRedirectTestContext()
	request := oidcAuthorizeRequest{
		clientID:    latchedConsentClientID,
		redirectURI: "https://app.example.com/callback",
		scope:       definitions.ScopeOpenID,
		state:       state,
	}
	session := newOIDCCallbackRedirectSession(request.redirectURI)

	directHandler.issueOIDCAuthorizeCode(
		directCtx,
		nil,
		newOIDCAuthorizeFlowContext(nil),
		&config.OIDCClient{ClientID: latchedConsentClientID},
		request,
		session,
		[]string{definitions.ScopeOpenID},
	)

	assert.Equal(t, http.StatusFound, directRecorder.Code)
	assertOIDCCallbackLocation(t, directRecorder.Header().Get("Location"), state)
	assert.NoError(t, directMock.ExpectationsWereMet())

	consentHandler, consentMock := newOIDCConsentCallbackRedirectTestHandler(t)
	consentCtx, consentRecorder := newOIDCConsentRedirectTestContext(state)

	consentHandler.ConsentPOST(consentCtx)

	assertOIDCCallbackLocation(t, consentRecorder.Header().Get("Location"), state)
	assert.NoError(t, consentMock.ExpectationsWereMet())
}

func TestOIDCAuthorizationCodeRequireMFABlocksMissingAssurance(t *testing.T) {
	handler, mock := newOIDCAssuranceCodeHandler(t)
	ctx, recorder := newOIDCAssuranceCodeContext(map[string]any{
		definitions.SessionKeyAccount: "alice",
	})
	client := config.OIDCClient{
		ClientID:   latchedConsentClientID,
		RequireMFA: []string{definitions.MFAMethodTOTP},
	}
	request := newOIDCAssuranceCodeRequest()

	expectOIDCAuthorizationCodeStorage(mock)

	handler.issueOIDCAuthorizeCode(ctx, cookieManagerFromContext(t, ctx), newOIDCAuthorizeFlowContext(cookieManagerFromContext(t, ctx)), &client, request, newOIDCAssuranceCodeSession(false, ""), []string{definitions.ScopeOpenID})

	assert.Equal(t, http.StatusFound, recorder.Code)
	assert.NotContains(t, recorder.Header().Get("Location"), oidcParamCode+"=")
}

func TestOIDCAuthorizationCodeRequireMFAPreparesExistingSessionStepUp(t *testing.T) {
	handler, _ := newOIDCAssuranceCodeHandler(t)
	ctx, recorder := newOIDCAssuranceCodeContext(map[string]any{
		definitions.SessionKeyAccount:      "alice",
		definitions.SessionKeyUniqueUserID: "alice-id",
		definitions.SessionKeyDisplayName:  "Alice Example",
		definitions.SessionKeySubject:      "alice-id",
		definitions.SessionKeyIDPFlowType:  definitions.ProtoOIDC,
		definitions.SessionKeyIDPClientID:  latchedConsentClientID,
	})
	mgr := cookieManagerFromContext(t, ctx)
	client := config.OIDCClient{
		ClientID:   latchedConsentClientID,
		RequireMFA: []string{definitions.MFAMethodTOTP},
	}
	request := newOIDCAssuranceCodeRequest()

	handler.issueOIDCAuthorizeCode(ctx, mgr, newOIDCAuthorizeFlowContext(mgr), &client, request, newOIDCAssuranceCodeSession(false, ""), []string{definitions.ScopeOpenID})

	assert.Equal(t, http.StatusFound, recorder.Code)
	assert.NotContains(t, recorder.Header().Get("Location"), oidcParamCode+"=")
	assert.Equal(t, "alice", mgr.GetString(definitions.SessionKeyUsername, ""))
	assert.Equal(t, "alice", mgr.GetString(definitions.SessionKeyMFAAccount, ""))
	assert.Equal(t, "alice", mgr.GetString(definitions.SessionKeyMFAFactorAccount, ""))
	assert.Equal(t, definitions.ProtoOIDC, mgr.GetString(definitions.SessionKeyProtocol, ""))
	assert.Equal(t, latchedConsentClientID, mgr.GetString(definitions.SessionKeyIDPClientID, ""))
	assert.True(t, mgr.HasKey(definitions.SessionKeyAuthResult))
}

func TestOIDCAuthorizationCodeRequireMFABlocksStaleAssurance(t *testing.T) {
	handler, mock := newOIDCAssuranceCodeHandler(t)
	ctx, recorder := newOIDCAssuranceCodeContext(map[string]any{
		definitions.SessionKeyAccount:           "alice",
		definitions.SessionKeyMFACompleted:      true,
		definitions.SessionKeyMFAMethod:         definitions.MFAMethodTOTP,
		definitions.SessionKeyMFAAssuranceAt:    time.Now().Add(-25 * time.Hour).Unix(),
		definitions.SessionKeyMFAAssuranceScope: oidcMFAAssuranceScope(latchedConsentClientID),
	})
	client := config.OIDCClient{
		ClientID:   latchedConsentClientID,
		RequireMFA: []string{definitions.MFAMethodTOTP},
	}
	request := newOIDCAssuranceCodeRequest()

	expectOIDCAuthorizationCodeStorage(mock)

	handler.issueOIDCAuthorizeCode(ctx, cookieManagerFromContext(t, ctx), newOIDCAuthorizeFlowContext(cookieManagerFromContext(t, ctx)), &client, request, newOIDCAssuranceCodeSession(true, definitions.MFAMethodTOTP), []string{definitions.ScopeOpenID})

	assert.Equal(t, http.StatusFound, recorder.Code)
	assert.NotContains(t, recorder.Header().Get("Location"), oidcParamCode+"=")
}

func TestOIDCAuthorizationCodeRequireMFAPermitsFreshAssurance(t *testing.T) {
	handler, mock := newOIDCAssuranceCodeHandler(t)
	ctx, recorder := newOIDCAssuranceCodeContext(map[string]any{
		definitions.SessionKeyAccount:           "alice",
		definitions.SessionKeyMFACompleted:      true,
		definitions.SessionKeyMFAMethod:         definitions.MFAMethodTOTP,
		definitions.SessionKeyMFAAssuranceAt:    time.Now().Unix(),
		definitions.SessionKeyMFAAssuranceScope: oidcMFAAssuranceScope(latchedConsentClientID),
	})
	client := config.OIDCClient{
		ClientID:   latchedConsentClientID,
		RequireMFA: []string{definitions.MFAMethodTOTP},
	}
	request := newOIDCAssuranceCodeRequest()

	expectOIDCAuthorizationCodeStorage(mock)

	handler.issueOIDCAuthorizeCode(ctx, cookieManagerFromContext(t, ctx), newOIDCAuthorizeFlowContext(cookieManagerFromContext(t, ctx)), &client, request, newOIDCAssuranceCodeSession(true, definitions.MFAMethodTOTP), []string{definitions.ScopeOpenID})

	assert.Equal(t, http.StatusFound, recorder.Code)
	assert.Contains(t, recorder.Header().Get("Location"), oidcParamCode+"=")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOIDCAuthorizationCodeRequiredMFALevelBlocksLowerSSOAssurance(t *testing.T) {
	handler, _ := newOIDCAssuranceCodeHandler(t)
	ctx, recorder := newOIDCAssuranceCodeContext(map[string]any{
		definitions.SessionKeyAccount:            "alice",
		definitions.SessionKeyMFACompleted:       true,
		definitions.SessionKeyMFAMethod:          definitions.MFAMethodTOTP,
		definitions.SessionKeyMFAAssuranceMethod: definitions.MFAMethodTOTP,
		definitions.SessionKeyMFAAssuranceAt:     time.Now().Unix(),
		definitions.SessionKeyMFAAssuranceScope:  oidcMFAAssuranceScope("heimdal-client"),
		definitions.SessionKeyMFAAssuranceLevel:  2,
	})
	client := config.OIDCClient{
		ClientID:         latchedConsentClientID,
		RequiredMFALevel: 3,
	}
	request := newOIDCAssuranceCodeRequest()

	mgr := cookieManagerFromContext(t, ctx)
	handler.issueOIDCAuthorizeCode(ctx, mgr, newOIDCAuthorizeFlowContext(mgr), &client, request, newOIDCAssuranceCodeSession(true, definitions.MFAMethodTOTP), []string{definitions.ScopeOpenID})

	assert.Equal(t, http.StatusFound, recorder.Code)
	assert.Equal(t, frontendMFASelectPath, recorder.Header().Get("Location"))
	assert.NotContains(t, recorder.Header().Get("Location"), oidcParamCode+"=")
}

func TestOIDCAuthorizationCodeRequiredMFALevelPermitsFreshLevel(t *testing.T) {
	handler, mock := newOIDCAssuranceCodeHandler(t)
	ctx, recorder := newOIDCAssuranceCodeContext(map[string]any{
		definitions.SessionKeyAccount:            "alice",
		definitions.SessionKeyMFACompleted:       true,
		definitions.SessionKeyMFAMethod:          definitions.MFAMethodWebAuthn,
		definitions.SessionKeyMFAAssuranceMethod: definitions.MFAMethodWebAuthn,
		definitions.SessionKeyMFAAssuranceAt:     time.Now().Unix(),
		definitions.SessionKeyMFAAssuranceScope:  oidcMFAAssuranceScope("heimdal-client"),
		definitions.SessionKeyMFAAssuranceLevel:  3,
	})
	client := config.OIDCClient{
		ClientID:         latchedConsentClientID,
		RequiredMFALevel: 3,
	}
	request := newOIDCAssuranceCodeRequest()

	expectOIDCAuthorizationCodeStorage(mock)

	mgr := cookieManagerFromContext(t, ctx)
	handler.issueOIDCAuthorizeCode(ctx, mgr, newOIDCAuthorizeFlowContext(mgr), &client, request, newOIDCAssuranceCodeSession(true, definitions.MFAMethodWebAuthn), []string{definitions.ScopeOpenID})

	assert.Equal(t, http.StatusFound, recorder.Code)
	assert.Contains(t, recorder.Header().Get("Location"), oidcParamCode+"=")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOIDCAuthorizationCodeNoRequireMFAPreservesExistingSession(t *testing.T) {
	handler, mock := newOIDCAssuranceCodeHandler(t)
	ctx, recorder := newOIDCAssuranceCodeContext(map[string]any{
		definitions.SessionKeyAccount: "alice",
	})
	client := config.OIDCClient{ClientID: latchedConsentClientID}
	request := newOIDCAssuranceCodeRequest()

	expectOIDCAuthorizationCodeStorage(mock)

	handler.issueOIDCAuthorizeCode(ctx, cookieManagerFromContext(t, ctx), newOIDCAuthorizeFlowContext(cookieManagerFromContext(t, ctx)), &client, request, newOIDCAssuranceCodeSession(false, ""), []string{definitions.ScopeOpenID})

	assert.Equal(t, http.StatusFound, recorder.Code)
	assert.Contains(t, recorder.Header().Get("Location"), oidcParamCode+"=")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestOIDCConsentPOSTRejectsAllowWhenFlowAuthFailureLatched(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler, mock := newLatchedConsentPostHandler(t)
	ctx, recorder := newLatchedConsentPostContext()

	handler.ConsentPOST(ctx)

	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "Consent denied")
	assert.NoError(t, mock.ExpectationsWereMet())
}

const (
	latchedConsentChallenge = "consent-challenge"
	latchedConsentFlowID    = "flow-consent-latched"
	latchedConsentClientID  = "test-client"
	latchedConsentUserID    = "user-123"
	latchedConsentUsername  = "alice"
	consentSubmitAllow      = "allow"
)

func newLatchedConsentPostHandler(t *testing.T) (*OIDCHandler, redismock.ClientMock) {
	t.Helper()

	client := latchedConsentOIDCClient()
	db, mock := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)
	cfg := &mockOIDCCfg{
		issuer:     "https://auth.example.com",
		signingKey: secret.New(generateTestKey()),
		clients:    []config.OIDCClient{client},
	}
	d := &deps.Deps{
		Cfg:    cfg,
		Redis:  rClient,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	handler := NewOIDCHandler(d, idp.NewNauthilusIDP(d), nil)

	expectLatchedConsentPostRedis(t, mock, client)

	return handler, mock
}

func latchedConsentOIDCClient() config.OIDCClient {
	return config.OIDCClient{
		ClientID:     latchedConsentClientID,
		ClientSecret: secret.New("test-secret"),
		RedirectURIs: []string{"https://app.example.com/callback"},
		Scopes:       []string{definitions.ScopeOpenID, "profile"},
	}
}

func expectLatchedConsentPostRedis(t *testing.T, mock redismock.ClientMock, client config.OIDCClient) {
	t.Helper()

	oidcSession := &idp.OIDCSession{
		ClientID:    client.ClientID,
		UserID:      latchedConsentUserID,
		Username:    latchedConsentUsername,
		Scopes:      []string{definitions.ScopeOpenID, "profile"},
		RedirectURI: "https://app.example.com/callback",
	}
	sessionData, err := json.Marshal(oidcSession)
	assert.NoError(t, err)

	flowState := &flowdomain.State{
		FlowID:      latchedConsentFlowID,
		Type:        flowdomain.FlowTypeOIDCAuthorization,
		Protocol:    flowdomain.FlowProtocolOIDC,
		CurrentStep: flowdomain.FlowStepConsent,
		GrantType:   definitions.OIDCFlowAuthorizationCode,
		AuthOutcome: flowdomain.AuthOutcomeFailLatched,
	}
	flowData, err := json.Marshal(flowState)
	assert.NoError(t, err)

	mock.ExpectGet("test:oidc:code:consent:" + latchedConsentChallenge).SetVal(string(sessionData))
	mock.ExpectGet("test:idp:flow:" + latchedConsentFlowID).SetVal(string(flowData))
	mock.ExpectDel("test:oidc:code:consent:" + latchedConsentChallenge).SetVal(1)
	mock.ExpectDel("test:idp:flow:" + latchedConsentFlowID).SetVal(1)
}

func newLatchedConsentPostContext() (*gin.Context, *httptest.ResponseRecorder) {
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyIDPFlowID:     latchedConsentFlowID,
		definitions.SessionKeyIDPFlowType:   definitions.ProtoOIDC,
		definitions.SessionKeyOIDCGrantType: definitions.OIDCFlowAuthorizationCode,
		definitions.SessionKeyIDPClientID:   latchedConsentClientID,
	}}
	ctx.Set(definitions.CtxSecureDataKey, mgr)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/oidc/consent", strings.NewReader(url.Values{
		"consent_challenge": {latchedConsentChallenge},
		"submit":            {consentSubmitAllow},
	}.Encode()))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return ctx, recorder
}

// newOIDCCallbackRedirectTestHandler builds a handler for callback redirect tests.
func newOIDCCallbackRedirectTestHandler(t *testing.T) (*OIDCHandler, redismock.ClientMock) {
	t.Helper()

	return newOIDCCallbackRedirectTestHandlerWithClient(t, latchedConsentOIDCClient())
}

func newOIDCCallbackRedirectTestHandlerWithClient(t *testing.T, client config.OIDCClient) (*OIDCHandler, redismock.ClientMock) {
	t.Helper()

	db, mock := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)
	cfg := &mockOIDCCfg{
		issuer:     "https://auth.example.com",
		signingKey: secret.New(generateTestKey()),
		clients:    []config.OIDCClient{client},
	}
	d := &deps.Deps{
		Cfg:    cfg,
		Redis:  rClient,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	handler := NewOIDCHandler(d, idp.NewNauthilusIDP(d), nil)

	return handler, mock
}

// newOIDCDirectCallbackRedirectTestHandler expects direct authorization-code storage.
func newOIDCDirectCallbackRedirectTestHandler(t *testing.T) (*OIDCHandler, redismock.ClientMock) {
	t.Helper()

	handler, mock := newOIDCCallbackRedirectTestHandler(t)
	expectOIDCAuthorizationCodeStorage(mock)

	return handler, mock
}

// newOIDCConsentCallbackRedirectTestHandler expects consent lookup, code storage, and cleanup.
func newOIDCConsentCallbackRedirectTestHandler(t *testing.T) (*OIDCHandler, redismock.ClientMock) {
	t.Helper()

	return newOIDCConsentCallbackRedirectTestHandlerWithClient(t, latchedConsentOIDCClient(), true)
}

func newOIDCConsentCallbackRedirectTestHandlerWithClient(t *testing.T, client config.OIDCClient, expectCode bool) (*OIDCHandler, redismock.ClientMock) {
	t.Helper()

	handler, mock := newOIDCCallbackRedirectTestHandlerWithClient(t, client)
	session := newOIDCCallbackRedirectSession("https://app.example.com/callback")
	session.ClientID = client.ClientID

	mock.ExpectGet("test:oidc:code:consent:" + latchedConsentChallenge).SetVal(mustMarshalOIDCSession(t, session))

	if expectCode {
		expectOIDCAuthorizationCodeStorage(mock)
		mock.ExpectDel("test:oidc:code:consent:" + latchedConsentChallenge).SetVal(1)
	}

	return handler, mock
}

// expectOIDCAuthorizationCodeStorage matches one generated authorization-code write.
func expectOIDCAuthorizationCodeStorage(mock redismock.ClientMock) {
	mock.Regexp().ExpectSet("test:oidc:code:.*", ".*", 10*time.Minute).SetVal("OK")
}

// newOIDCConsentRedirectTestContext creates a consent POST carrying a delimiter-heavy state.
func newOIDCConsentRedirectTestContext(state string) (*gin.Context, *httptest.ResponseRecorder) {
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/oidc/consent", strings.NewReader(url.Values{
		"consent_challenge": {latchedConsentChallenge},
		"state":             {state},
		"submit":            {consentSubmitAllow},
	}.Encode()))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return ctx, recorder
}

// newOIDCDirectCallbackRedirectTestContext creates a recorder-backed authorize context.
func newOIDCDirectCallbackRedirectTestContext() (*gin.Context, *httptest.ResponseRecorder) {
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/oidc/authorize", nil)

	return ctx, recorder
}

func newOIDCAssuranceCodeHandler(t *testing.T) (*OIDCHandler, redismock.ClientMock) {
	t.Helper()

	handler, mock := newOIDCCallbackRedirectTestHandler(t)

	return handler, mock
}

func newOIDCAssuranceCodeContext(data map[string]any) (*gin.Context, *httptest.ResponseRecorder) {
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/oidc/authorize", nil)
	ctx.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: data})

	return ctx, recorder
}

func cookieManagerFromContext(t *testing.T, ctx *gin.Context) cookie.Manager {
	t.Helper()

	mgr := cookie.GetManager(ctx)
	if mgr == nil {
		t.Fatal("expected cookie manager in context")
	}

	return mgr
}

func newOIDCAssuranceCodeRequest() oidcAuthorizeRequest {
	return oidcAuthorizeRequest{
		clientID:    latchedConsentClientID,
		redirectURI: "https://app.example.com/callback",
		scope:       definitions.ScopeOpenID,
		state:       "state-1",
	}
}

func newOIDCAssuranceCodeSession(mfaCompleted bool, mfaMethod string) *idp.OIDCSession {
	session := newOIDCCallbackRedirectSession("https://app.example.com/callback")
	session.MFACompleted = mfaCompleted
	session.MFAMethod = mfaMethod

	return session
}

// newOIDCCallbackRedirectSession creates a minimal authorization-code session.
func newOIDCCallbackRedirectSession(redirectURI string) *idp.OIDCSession {
	return &idp.OIDCSession{
		ClientID:    latchedConsentClientID,
		UserID:      latchedConsentUserID,
		Username:    latchedConsentUsername,
		Scopes:      []string{definitions.ScopeOpenID},
		RedirectURI: redirectURI,
	}
}

// assertOIDCCallbackLocation verifies that callback parameters are encoded as data.
func assertOIDCCallbackLocation(t *testing.T, location string, wantState string) {
	t.Helper()

	parsedLocation, err := url.Parse(location)
	if !assert.NoError(t, err) {
		return
	}

	query := parsedLocation.Query()
	assert.Len(t, query[oidcParamCode], 1)
	assert.NotEqual(t, "injected", query.Get(oidcParamCode))
	assert.Len(t, query[oidcParamState], 1)
	assert.Equal(t, wantState, query.Get(oidcParamState))
	assert.Empty(t, query["client_id"])
}

func TestOIDCHandler_Introspect(t *testing.T) {
	gin.SetMode(gin.TestMode)

	fixture := newOIDCIntrospectionTest(t)

	t.Run("Valid token introspection", fixture.assertValidTokenIntrospection)
	t.Run("Private key JWT token introspection", fixture.assertPrivateKeyJWTTokenIntrospection)
	t.Run("ID token introspection is inactive", fixture.assertIDTokenIntrospectionInactive)
	t.Run("Invalid token introspection", fixture.assertInvalidTokenIntrospection)
	t.Run("Unauthorized client", fixture.assertUnauthorizedClient)

	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

type oidcIntrospectionTest struct {
	handler                  *OIDCHandler
	mock                     redismock.ClientMock
	clientAssertionKey       *rsa.PrivateKey
	privateKeyJWTClient      config.OIDCClient
	issuer                   string
	idToken                  string
	accessToken              string
	privateKeyJWTAccessToken string
}

// newOIDCIntrospectionTest builds an isolated token introspection fixture.
func newOIDCIntrospectionTest(t *testing.T) *oidcIntrospectionTest {
	t.Helper()

	issuer := "https://auth.example.com"
	signingKey := secret.New(generateTestKey())
	clientAssertionKey, clientPublicKey := generateTestClientKeyPair(t)
	client := config.OIDCClient{
		ClientID:     "test-client",
		ClientSecret: secret.New("test-secret"),
	}
	privateKeyJWTClient := config.OIDCClient{
		ClientID:                 "jwt-client",
		TokenEndpointAuthMethod:  clientauth.MethodPrivateKeyJWT,
		ClientPublicKey:          clientPublicKey,
		ClientPublicKeyAlgorithm: signing.AlgorithmRS256,
	}

	cfg := &mockOIDCCfg{
		issuer:     issuer,
		signingKey: signingKey,
		clients:    []config.OIDCClient{client, privateKeyJWTClient},
	}

	db, mock := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)

	d := &deps.Deps{
		Cfg:    cfg,
		Redis:  rClient,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	idpInstance := idp.NewNauthilusIDP(d)
	h := NewOIDCHandler(d, idpInstance, nil)
	idToken, accessToken, _, _, _ := idpInstance.IssueTokens(context.Background(), &idp.OIDCSession{
		ClientID: "test-client",
		UserID:   "user123",
		AuthTime: time.Now(),
		Scopes:   []string{"openid", "profile"},
	})
	_, privateKeyJWTAccessToken, _, _, _ := idpInstance.IssueTokens(context.Background(), &idp.OIDCSession{
		ClientID: privateKeyJWTClient.ClientID,
		UserID:   "jwt-user",
		AuthTime: time.Now(),
		Scopes:   []string{"openid", "profile"},
	})

	return &oidcIntrospectionTest{
		handler:                  h,
		mock:                     mock,
		clientAssertionKey:       clientAssertionKey,
		privateKeyJWTClient:      privateKeyJWTClient,
		issuer:                   issuer,
		idToken:                  idToken,
		accessToken:              accessToken,
		privateKeyJWTAccessToken: privateKeyJWTAccessToken,
	}
}

// postIntrospection submits an introspection request with optional Basic auth.
func (f *oidcIntrospectionTest) postIntrospection(t *testing.T, form url.Values, basicID, basicSecret string) *httptest.ResponseRecorder {
	t.Helper()

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/oidc/introspect", nil)

	ctx.Request.PostForm = form
	if basicID != "" || basicSecret != "" {
		ctx.Request.SetBasicAuth(basicID, basicSecret)
	}

	f.handler.Introspect(ctx)

	return w
}

// assertValidTokenIntrospection verifies an active token for a secret client.
func (f *oidcIntrospectionTest) assertValidTokenIntrospection(t *testing.T) {
	w := f.postIntrospection(t, url.Values{"token": {f.accessToken}}, "test-client", "test-secret")
	resp := mustDecodeOIDCTestJSON(t, w)
	claims := f.mustValidateAccessTokenClaims(t, f.accessToken)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, resp["active"].(bool))
	assert.Equal(t, oidcJSONTokenTypeBearer, resp[oidcJSONFieldTokenType])
	assert.Equal(t, definitions.TokenTypeAccessToken, claims[definitions.ClaimTokenType])
	assert.Equal(t, "user123", resp["sub"])
	assert.Equal(t, "test-client", resp["aud"])
}

// assertPrivateKeyJWTTokenIntrospection verifies endpoint-specific JWT auth.
func (f *oidcIntrospectionTest) assertPrivateKeyJWTTokenIntrospection(t *testing.T) {
	audience := f.issuer + "/oidc/introspect"
	assertion := signTestClientAssertion(t, f.clientAssertionKey, f.privateKeyJWTClient.ClientID, audience)
	form := url.Values{
		"token":                      {f.privateKeyJWTAccessToken},
		oidcParamClientID:            {f.privateKeyJWTClient.ClientID},
		oidcParamClientAssertionType: {clientauth.AssertionTypeJWTBearer},
		oidcParamClientAssertion:     {assertion},
	}

	expectOIDCClientAssertionReplayReservation(
		t,
		f.mock,
		expectedOIDCClientAssertionReplayKey(f.privateKeyJWTClient.ClientID, audience, "test-client-assertion"),
		true,
	)

	w := f.postIntrospection(t, form, "", "")
	resp := mustDecodeOIDCTestJSON(t, w)
	claims := f.mustValidateAccessTokenClaims(t, f.privateKeyJWTAccessToken)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, resp["active"].(bool))
	assert.Equal(t, oidcJSONTokenTypeBearer, resp[oidcJSONFieldTokenType])
	assert.Equal(t, definitions.TokenTypeAccessToken, claims[definitions.ClaimTokenType])
	assert.Equal(t, "jwt-user", resp[oidcTestJWTClaimSubject])
	assert.Equal(t, f.privateKeyJWTClient.ClientID, resp["aud"])
}

// assertIDTokenIntrospectionInactive verifies identity assertions are not exposed as bearer access tokens.
func (f *oidcIntrospectionTest) assertIDTokenIntrospectionInactive(t *testing.T) {
	w := f.postIntrospection(t, url.Values{"token": {f.idToken}}, "test-client", "test-secret")
	resp := mustDecodeOIDCTestJSON(t, w)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.False(t, resp["active"].(bool))
	assert.Nil(t, resp[oidcJSONFieldTokenType])
}

// mustValidateAccessTokenClaims returns the internally validated token claims.
func (f *oidcIntrospectionTest) mustValidateAccessTokenClaims(t *testing.T, token string) map[string]any {
	t.Helper()

	claims, err := f.handler.idp.ValidateToken(context.Background(), token)
	assert.NoError(t, err)

	return claims
}

// assertInvalidTokenIntrospection verifies inactive responses for unknown tokens.
func (f *oidcIntrospectionTest) assertInvalidTokenIntrospection(t *testing.T) {
	w := f.postIntrospection(t, url.Values{"token": {"invalid-token"}}, "test-client", "test-secret")
	resp := mustDecodeOIDCTestJSON(t, w)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.False(t, resp["active"].(bool))
}

// assertUnauthorizedClient verifies rejected introspection client credentials.
func (f *oidcIntrospectionTest) assertUnauthorizedClient(t *testing.T) {
	w := f.postIntrospection(t, url.Values{"token": {f.accessToken}}, "other-client", "wrong-secret")

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// mustDecodeOIDCTestJSON decodes a test JSON response body.
func mustDecodeOIDCTestJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	var resp map[string]any

	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)

	return resp
}

func TestOIDCHandler_PrivateKeyJWTTokenReplayProtection(t *testing.T) {
	gin.SetMode(gin.TestMode)

	fixture := newPrivateKeyJWTReplayOIDCTest(t)
	audience := fixture.issuer + oidcEndpointPathToken
	jwtID := "token-replay-jti"
	assertion := signTestClientAssertionWithJWTID(t, fixture.clientKey, fixture.client.ClientID, audience, jwtID)
	replayKey := expectedOIDCClientAssertionReplayKey(fixture.client.ClientID, audience, jwtID)

	expectOIDCClientAssertionReplayReservation(t, fixture.mock, replayKey, true)
	fixture.mock.ExpectGet("test:oidc:code:token-code-1").SetVal(fixture.authorizationCodeSessionJSON(t))
	fixture.mock.ExpectDel("test:oidc:code:token-code-1").SetVal(1)

	first := fixture.postPrivateKeyJWTToken(t, "token-code-1", assertion)
	assert.Equal(t, http.StatusOK, first.Code)

	expectOIDCClientAssertionReplayReservation(t, fixture.mock, replayKey, false)

	replay := fixture.postPrivateKeyJWTToken(t, "token-code-2", assertion)
	assertInvalidClientResponse(t, replay)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

func TestOIDCHandler_PrivateKeyJWTIntrospectionReplayProtection(t *testing.T) {
	gin.SetMode(gin.TestMode)

	fixture := newPrivateKeyJWTReplayOIDCTest(t)
	audience := fixture.issuer + oidcEndpointPathIntrospect
	jwtID := "introspection-replay-jti"
	assertion := signTestClientAssertionWithJWTID(t, fixture.clientKey, fixture.client.ClientID, audience, jwtID)
	replayKey := expectedOIDCClientAssertionReplayKey(fixture.client.ClientID, audience, jwtID)
	accessToken := fixture.issuePrivateKeyJWTAccessToken(t)

	expectOIDCClientAssertionReplayReservation(t, fixture.mock, replayKey, true)
	fixture.mock.ExpectGet("test:oidc:denied_access_token:" + accessToken).RedisNil()

	first := fixture.postPrivateKeyJWTIntrospection(t, accessToken, assertion)
	assert.Equal(t, http.StatusOK, first.Code)

	expectOIDCClientAssertionReplayReservation(t, fixture.mock, replayKey, false)

	replay := fixture.postPrivateKeyJWTIntrospection(t, accessToken, assertion)
	assertInvalidClientResponse(t, replay)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

func TestOIDCHandler_PrivateKeyJWTReplayScopeIncludesEndpointAudience(t *testing.T) {
	gin.SetMode(gin.TestMode)

	fixture := newPrivateKeyJWTReplayOIDCTest(t)
	jwtID := "shared-endpoint-jti"
	tokenAudience := fixture.issuer + oidcEndpointPathToken
	introspectionAudience := fixture.issuer + oidcEndpointPathIntrospect
	tokenAssertion := signTestClientAssertionWithJWTID(t, fixture.clientKey, fixture.client.ClientID, tokenAudience, jwtID)
	introspectionAssertion := signTestClientAssertionWithJWTID(t, fixture.clientKey, fixture.client.ClientID, introspectionAudience, jwtID)
	accessToken := fixture.issuePrivateKeyJWTAccessToken(t)

	expectOIDCClientAssertionReplayReservation(
		t,
		fixture.mock,
		expectedOIDCClientAssertionReplayKey(fixture.client.ClientID, tokenAudience, jwtID),
		true,
	)
	fixture.mock.ExpectGet("test:oidc:code:audience-code").SetVal(fixture.authorizationCodeSessionJSON(t))
	fixture.mock.ExpectDel("test:oidc:code:audience-code").SetVal(1)

	tokenResponse := fixture.postPrivateKeyJWTToken(t, "audience-code", tokenAssertion)
	assert.Equal(t, http.StatusOK, tokenResponse.Code)

	expectOIDCClientAssertionReplayReservation(
		t,
		fixture.mock,
		expectedOIDCClientAssertionReplayKey(fixture.client.ClientID, introspectionAudience, jwtID),
		true,
	)
	fixture.mock.ExpectGet("test:oidc:denied_access_token:" + accessToken).RedisNil()

	introspectionResponse := fixture.postPrivateKeyJWTIntrospection(t, accessToken, introspectionAssertion)
	assert.Equal(t, http.StatusOK, introspectionResponse.Code)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

type privateKeyJWTReplayOIDCTest struct {
	handler   *OIDCHandler
	issuerID  *idp.NauthilusIDP
	mock      redismock.ClientMock
	clientKey *rsa.PrivateKey
	client    config.OIDCClient
	issuer    string
}

// newPrivateKeyJWTReplayOIDCTest builds an isolated OIDC handler with one private_key_jwt client.
func newPrivateKeyJWTReplayOIDCTest(t testing.TB) *privateKeyJWTReplayOIDCTest {
	t.Helper()

	issuer := "https://auth.example.com"
	signingKey := secret.New(generateTestKey())
	clientKey, clientPublicKey := generateTestClientKeyPair(t)
	client := config.OIDCClient{
		ClientID:                 "jwt-client",
		RedirectURIs:             []string{"https://app.example.com/callback"},
		TokenEndpointAuthMethod:  clientauth.MethodPrivateKeyJWT,
		ClientPublicKey:          clientPublicKey,
		ClientPublicKeyAlgorithm: signing.AlgorithmRS256,
	}
	cfg := &mockOIDCCfg{
		issuer:     issuer,
		signingKey: signingKey,
		clients:    []config.OIDCClient{client},
	}

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	dependencies := &deps.Deps{
		Cfg:    cfg,
		Redis:  redisClient,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	issuerID := idp.NewNauthilusIDP(dependencies)

	return &privateKeyJWTReplayOIDCTest{
		handler:   NewOIDCHandler(dependencies, issuerID, nil),
		issuerID:  issuerID,
		mock:      mock,
		clientKey: clientKey,
		client:    client,
		issuer:    issuer,
	}
}

// authorizationCodeSessionJSON serializes a stored authorization-code session.
func (f *privateKeyJWTReplayOIDCTest) authorizationCodeSessionJSON(t testing.TB) string {
	t.Helper()

	session := &idp.OIDCSession{
		ClientID:    f.client.ClientID,
		UserID:      "jwt-user",
		Scopes:      []string{definitions.ScopeOpenID},
		RedirectURI: "https://app.example.com/callback",
		AuthTime:    time.Now(),
	}
	sessionData, err := json.Marshal(session)
	assert.NoError(t, err)

	return string(sessionData)
}

// issuePrivateKeyJWTAccessToken issues a JWT access token for introspection replay tests.
func (f *privateKeyJWTReplayOIDCTest) issuePrivateKeyJWTAccessToken(t testing.TB) string {
	t.Helper()

	_, accessToken, _, _, err := f.issuerID.IssueTokens(context.Background(), &idp.OIDCSession{
		ClientID: f.client.ClientID,
		UserID:   "jwt-user",
		AuthTime: time.Now(),
		Scopes:   []string{definitions.ScopeOpenID, "profile"},
	})
	assert.NoError(t, err)

	return accessToken
}

// postPrivateKeyJWTToken submits an authorization-code token request with a client assertion.
func (f *privateKeyJWTReplayOIDCTest) postPrivateKeyJWTToken(t testing.TB, code string, assertion string) *httptest.ResponseRecorder {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	form := url.Values{}
	form.Add(oidcParamGrantType, definitions.OIDCFlowAuthorizationCode)
	form.Add(oidcParamCode, code)
	form.Add(oidcParamRedirectURI, "https://app.example.com/callback")
	form.Add(oidcParamClientID, f.client.ClientID)
	form.Add(oidcParamClientAssertionType, clientauth.AssertionTypeJWTBearer)
	form.Add(oidcParamClientAssertion, assertion)

	req, _ := http.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx.Request = req

	f.handler.Token(ctx)

	return recorder
}

// postPrivateKeyJWTIntrospection submits an introspection request with a client assertion.
func (f *privateKeyJWTReplayOIDCTest) postPrivateKeyJWTIntrospection(
	t testing.TB,
	token string,
	assertion string,
) *httptest.ResponseRecorder {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	form := url.Values{}
	form.Add("token", token)
	form.Add(oidcParamClientID, f.client.ClientID)
	form.Add(oidcParamClientAssertionType, clientauth.AssertionTypeJWTBearer)
	form.Add(oidcParamClientAssertion, assertion)

	req, _ := http.NewRequest(http.MethodPost, "/oidc/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx.Request = req

	f.handler.Introspect(ctx)

	return recorder
}

// assertInvalidClientResponse verifies the OAuth invalid_client error shape.
func assertInvalidClientResponse(t testing.TB, recorder *httptest.ResponseRecorder) {
	t.Helper()

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)

	var response map[string]any

	err := json.Unmarshal(recorder.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, oidcErrorInvalidClient, response[definitions.LogKeyError])
}

type oidcTokenTest struct {
	handler *OIDCHandler
	mock    redismock.ClientMock
	cfg     *mockOIDCCfg
	deps    *deps.Deps
}

// newOIDCTokenTest builds an isolated token endpoint fixture.
func newOIDCTokenTest(t *testing.T) *oidcTokenTest {
	t.Helper()

	client := config.OIDCClient{
		ClientID:     "test-client",
		ClientSecret: secret.New("test-secret"),
		RedirectURIs: []string{"https://app.com/callback"},
	}
	cfg := &mockOIDCCfg{
		issuer:     "https://auth.example.com",
		signingKey: secret.New(generateTestKey()),
		clients:    []config.OIDCClient{client},
	}

	db, mock := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)
	d := &deps.Deps{
		Cfg:    cfg,
		Redis:  rClient,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	return &oidcTokenTest{
		handler: NewOIDCHandler(d, idp.NewNauthilusIDP(d), nil),
		mock:    mock,
		cfg:     cfg,
		deps:    d,
	}
}

// postToken submits a token request and returns the response recorder.
func (f *oidcTokenTest) postToken(
	t *testing.T,
	form url.Values,
	configure func(*http.Request),
) *httptest.ResponseRecorder {
	t.Helper()

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if configure != nil {
		configure(req)
	}

	ctx.Request = req
	f.handler.Token(ctx)

	return w
}

// withBasicTokenAuth configures Basic auth for token endpoint requests.
func withBasicTokenAuth(clientID, clientSecret string) func(*http.Request) {
	return func(req *http.Request) {
		req.SetBasicAuth(clientID, clientSecret)
	}
}

// withRawBasicTokenAuth configures a pre-encoded Basic auth value.
func withRawBasicTokenAuth(clientID, clientSecret string) func(*http.Request) {
	authValue := url.QueryEscape(clientID) + ":" + url.QueryEscape(clientSecret)
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(authValue))

	return func(req *http.Request) {
		req.Header.Set("Authorization", "Basic "+encodedAuth)
	}
}

// tokenAuthCodeForm builds an authorization-code token request body.
func tokenAuthCodeForm(code, redirectURI string) url.Values {
	form := url.Values{}
	form.Add(oidcParamGrantType, definitions.OIDCFlowAuthorizationCode)
	form.Add(oidcParamCode, code)
	form.Add(oidcParamRedirectURI, redirectURI)

	return form
}

// tokenRefreshForm builds a refresh-token request body.
func tokenRefreshForm(refreshToken string) url.Values {
	form := url.Values{}
	form.Add(oidcParamGrantType, "refresh_token")
	form.Add("refresh_token", refreshToken)

	return form
}

// mustMarshalOIDCSession serializes a test OIDC session.
func mustMarshalOIDCSession(t *testing.T, session *idp.OIDCSession) string {
	t.Helper()

	sessionData, err := json.Marshal(session)
	if !assert.NoError(t, err) {
		return ""
	}

	return string(sessionData)
}

// expectAuthorizationCodeSession registers Redis expectations for an auth code.
func (f *oidcTokenTest) expectAuthorizationCodeSession(t *testing.T, code string, session *idp.OIDCSession) {
	t.Helper()

	f.mock.ExpectGet("test:oidc:code:" + code).SetVal(mustMarshalOIDCSession(t, session))
	f.mock.ExpectDel("test:oidc:code:" + code).SetVal(1)
}

// expectRefreshTokenSession registers one refresh-token lookup expectation.
func (f *oidcTokenTest) expectRefreshTokenSession(t *testing.T, refreshToken string, session *idp.OIDCSession) {
	t.Helper()

	f.mock.ExpectGet("test:oidc:refresh_token:" + refreshToken).SetVal(mustMarshalOIDCSession(t, session))
}

// expectRefreshTokenRotation registers successful refresh-token rotation expectations.
func (f *oidcTokenTest) expectRefreshTokenRotation(t *testing.T, refreshToken string, session *idp.OIDCSession) {
	t.Helper()

	f.expectRefreshTokenSession(t, refreshToken, session)
	f.expectRefreshTokenSession(t, refreshToken, session)
	f.mock.ExpectSRem("test:oidc:user_refresh_tokens:user123", refreshToken).SetVal(1)
	f.mock.ExpectDel("test:oidc:refresh_token:" + refreshToken).SetVal(1)
	f.mock.Regexp().ExpectSet("test:oidc:refresh_token:na_rt_.*", ".*", 30*24*time.Hour).SetVal("OK")
	f.mock.Regexp().ExpectSAdd("test:oidc:user_refresh_tokens:user123", "na_rt_.*").SetVal(1)
	f.expectUserTokenIndexTTL("test:oidc:user_refresh_tokens:user123", 30*24*time.Hour)
}

// expectUserTokenIndexTTL expects monotonic TTL updates for Redis user-token indexes.
func (f *oidcTokenTest) expectUserTokenIndexTTL(userKey string, ttl time.Duration) {
	f.mock.ExpectExpireNX(userKey, ttl).SetVal(true)
	f.mock.ExpectExpireGT(userKey, ttl).SetVal(false)
}

// newRefreshTokenSession creates a common refresh-token session fixture.
func newRefreshTokenSession(clientID string) *idp.OIDCSession {
	return &idp.OIDCSession{
		ClientID: clientID,
		UserID:   "user123",
		Scopes:   []string{definitions.ScopeOpenID, definitions.ScopeOfflineAccess},
		AuthTime: time.Now(),
	}
}

// assertTokenError verifies an OAuth error response.
func assertTokenError(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()

	assert.Equal(t, status, w.Code)
	resp := mustDecodeOIDCTestJSON(t, w)
	assert.Equal(t, code, resp[definitions.LogKeyError])
}

// assertTokenHasFields verifies successful token fields.
func assertTokenHasFields(t *testing.T, w *httptest.ResponseRecorder, fields ...string) {
	t.Helper()

	assert.Equal(t, http.StatusOK, w.Code)

	resp := mustDecodeOIDCTestJSON(t, w)
	for _, field := range fields {
		assert.NotEmpty(t, resp[field])
	}
}

// pkceS256Challenge returns the S256 challenge for a verifier.
func pkceS256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// newPKCEAuthCodeSession creates an authorization-code session with PKCE data.
func newPKCEAuthCodeSession(clientID, redirectURI, verifier, method string) *idp.OIDCSession {
	challenge := verifier
	if method == "S256" {
		challenge = pkceS256Challenge(verifier)
	}

	return &idp.OIDCSession{
		ClientID:            clientID,
		UserID:              "user123",
		Scopes:              []string{definitions.ScopeOpenID},
		RedirectURI:         redirectURI,
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
	}
}

// assertDuplicateSensitiveFormValuesRejected verifies duplicate parameter rejection.
func (f *oidcTokenTest) assertDuplicateSensitiveFormValuesRejected(t *testing.T) {
	for _, duplicateKey := range []string{
		oidcParamGrantType,
		oidcParamClientID,
		oidcParamClientSecret,
		oidcParamCode,
		oidcParamRedirectURI,
	} {
		t.Run(duplicateKey, func(t *testing.T) {
			f.assertInvalidRequestForDuplicateTokenParameter(t, duplicateKey)
		})
	}
}

// assertInvalidRequestForDuplicateTokenParameter checks one duplicate form key.
func (f *oidcTokenTest) assertInvalidRequestForDuplicateTokenParameter(t *testing.T, duplicateKey string) {
	form := tokenAuthCodeForm("valid-code", "https://app.com/callback")
	form.Add(oidcParamClientID, "test-client")
	form.Add(oidcParamClientSecret, "test-secret")
	form.Add(duplicateKey, "attacker-value")

	w := f.postToken(t, form, nil)

	assertTokenError(t, w, http.StatusBadRequest, "invalid_request")
}

// assertInvalidClientForCombinedClientAuth checks double client authentication.
func (f *oidcTokenTest) assertInvalidClientForCombinedClientAuth(
	t *testing.T,
	grantType string,
	grantValueKey string,
	grantValue string,
) {
	form := url.Values{}
	form.Add(oidcParamGrantType, grantType)
	form.Add(grantValueKey, grantValue)
	form.Add(oidcParamClientID, "test-client")
	form.Add(oidcParamClientSecret, "test-secret")

	w := f.postToken(t, form, withBasicTokenAuth("test-client", "test-secret"))

	assertTokenError(t, w, http.StatusUnauthorized, "invalid_client")
}

// assertAuthorizationCodeBasicAuth verifies a confidential authorization-code exchange.
func (f *oidcTokenTest) assertAuthorizationCodeBasicAuth(t *testing.T) {
	code := "code123"
	session := &idp.OIDCSession{
		ClientID:    "test-client",
		UserID:      "user123",
		Scopes:      []string{definitions.ScopeOpenID},
		RedirectURI: "https://app.com/callback",
		Nonce:       "test-nonce",
	}
	f.expectAuthorizationCodeSession(t, code, session)

	w := f.postToken(t, tokenAuthCodeForm(code, "https://app.com/callback"), withBasicTokenAuth("test-client", "test-secret"))

	assertTokenHasFields(t, w, "id_token")
	assert.NoError(t, f.mock.ExpectationsWereMet())
}

// assertBodyClientIDWithBasicSecretRejected verifies mixed auth method rejection.
func (f *oidcTokenTest) assertBodyClientIDWithBasicSecretRejected(t *testing.T) {
	form := url.Values{}
	form.Add(oidcParamGrantType, definitions.OIDCFlowAuthorizationCode)
	form.Add(oidcParamCode, "any-code")
	form.Add(oidcParamClientID, "test-client")

	w := f.postToken(t, form, withBasicTokenAuth("test-client", "test-secret"))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// assertURLEncodedBasicAuth verifies RFC 6749 encoded Basic auth credentials.
func (f *oidcTokenTest) assertURLEncodedBasicAuth(t *testing.T) {
	code := "code789"
	specialClientID := "client@test"
	specialSecret := "pass+word"
	f.cfg.clients = append(f.cfg.clients, config.OIDCClient{
		ClientID:     specialClientID,
		ClientSecret: secret.New(specialSecret),
		RedirectURIs: []string{"https://app.com/callback"},
	})
	f.expectAuthorizationCodeSession(t, code, &idp.OIDCSession{
		ClientID:    specialClientID,
		UserID:      "user123",
		Scopes:      []string{definitions.ScopeOpenID},
		RedirectURI: "https://app.com/callback",
	})

	w := f.postToken(t, tokenAuthCodeForm(code, "https://app.com/callback"), withRawBasicTokenAuth(specialClientID, specialSecret))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, f.mock.ExpectationsWereMet())
}

// assertSecretLengthMismatchRejected verifies invalid Basic auth credentials.
func (f *oidcTokenTest) assertSecretLengthMismatchRejected(t *testing.T) {
	form := url.Values{}
	form.Add(oidcParamGrantType, definitions.OIDCFlowAuthorizationCode)
	form.Add(oidcParamCode, "any-code")

	w := f.postToken(t, form, withBasicTokenAuth("test-client", "secret"))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// assertMultipleMethodsRejected verifies explicit duplicate auth method rejection.
func (f *oidcTokenTest) assertMultipleMethodsRejected(t *testing.T) {
	form := url.Values{}
	form.Add(oidcParamGrantType, definitions.OIDCFlowAuthorizationCode)
	form.Add(oidcParamCode, "any-code")
	form.Add(oidcParamClientID, "test-client")
	form.Add(oidcParamClientSecret, "test-secret")

	w := f.postToken(t, form, withBasicTokenAuth("test-client", "test-secret"))

	assertTokenError(t, w, http.StatusUnauthorized, "invalid_client")
}

// assertRefreshCombinedAuthAcceptedForConfidentialClient verifies compatibility mode.
func (f *oidcTokenTest) assertRefreshCombinedAuthAcceptedForConfidentialClient(t *testing.T) {
	origCompat := f.cfg.clients[0].AllowRefreshTokenCombinedClientAuth

	f.cfg.clients[0].AllowRefreshTokenCombinedClientAuth = true
	defer func() { f.cfg.clients[0].AllowRefreshTokenCombinedClientAuth = origCompat }()

	refreshToken := "refresh-token-combined-auth-compat-confidential"
	f.expectRefreshTokenRotation(t, refreshToken, newRefreshTokenSession("test-client"))

	form := tokenRefreshForm(refreshToken)
	form.Add(oidcParamClientID, "test-client")
	form.Add(oidcParamClientSecret, "test-secret")
	w := f.postToken(t, form, withBasicTokenAuth("test-client", "test-secret"))

	assertTokenHasFields(t, w, "access_token", "refresh_token")
	assert.NoError(t, f.mock.ExpectationsWereMet())
}

// assertInvalidRefreshToken verifies invalid_grant for a missing refresh token.
func (f *oidcTokenTest) assertInvalidRefreshToken(t *testing.T) {
	refreshToken := "missing-refresh-token"
	f.mock.ExpectGet("test:oidc:refresh_token:" + refreshToken).RedisNil()

	w := f.postToken(t, tokenRefreshForm(refreshToken), withBasicTokenAuth("test-client", "test-secret"))

	assertTokenError(t, w, http.StatusBadRequest, "invalid_grant")
	assert.NoError(t, f.mock.ExpectationsWereMet())
}

// assertRefreshWithoutRotation verifies refresh-token reuse when rotation is disabled.
func (f *oidcTokenTest) assertRefreshWithoutRotation(t *testing.T) {
	origRevoke := f.cfg.clients[0].RevokeRefreshToken
	disabled := false

	f.cfg.clients[0].RevokeRefreshToken = &disabled
	defer func() { f.cfg.clients[0].RevokeRefreshToken = origRevoke }()

	refreshToken := "stable-refresh-token"
	oldAccessToken := "header.payload.signature"
	session := newRefreshTokenSession("test-client")
	session.AccessToken = oldAccessToken
	f.expectRefreshTokenSession(t, refreshToken, session)
	f.mock.ExpectSet("test:oidc:denied_access_token:"+oldAccessToken, "1", time.Hour).SetVal("OK")
	f.mock.Regexp().ExpectSet("test:oidc:refresh_token:"+refreshToken, ".*", 30*24*time.Hour).SetVal("OK")
	f.mock.ExpectSAdd("test:oidc:user_refresh_tokens:user123", refreshToken).SetVal(0)
	f.expectUserTokenIndexTTL("test:oidc:user_refresh_tokens:user123", 30*24*time.Hour)

	w := f.postToken(t, tokenRefreshForm(refreshToken), withBasicTokenAuth("test-client", "test-secret"))
	resp := mustDecodeOIDCTestJSON(t, w)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, resp["access_token"])
	_, hasRefreshToken := resp["refresh_token"]
	assert.False(t, hasRefreshToken)
	assert.NoError(t, f.mock.ExpectationsWereMet())
}

// assertRefreshInvalidTokenLogsFailureReason verifies the notice failure reason.
func (f *oidcTokenTest) assertRefreshInvalidTokenLogsFailureReason(t *testing.T) {
	refreshToken := "missing-refresh-token-log-reason"
	f.mock.ExpectGet("test:oidc:refresh_token:" + refreshToken).RedisNil()

	handler := &noticeCaptureHandler{}
	previousLogger := f.deps.Logger

	f.deps.Logger = slog.New(handler)
	defer func() { f.deps.Logger = previousLogger }()

	w := f.postToken(t, tokenRefreshForm(refreshToken), withBasicTokenAuth("test-client", "test-secret"))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertRefreshFailureReasonLogged(t, handler)
	assert.NoError(t, f.mock.ExpectationsWereMet())
}

// assertRefreshFailureReasonLogged verifies the captured refresh failure notice.
func assertRefreshFailureReasonLogged(t *testing.T, handler *noticeCaptureHandler) {
	t.Helper()

	foundFailureLog := false

	for _, record := range handler.records {
		if record.message != "IDP request has failed" {
			continue
		}

		assert.Equal(t, "refresh token unknown, expired, or already rotated", record.attrs["failure_reason"])

		foundFailureLog = true

		break
	}

	assert.True(t, foundFailureLog, "expected failed OIDC flow notice log with failure_reason")
}

// assertRefreshClientMismatch verifies invalid_grant for mismatched client state.
func (f *oidcTokenTest) assertRefreshClientMismatch(t *testing.T) {
	refreshToken := "refresh-token-client-mismatch"
	f.expectRefreshTokenSession(t, refreshToken, newRefreshTokenSession("other-client"))

	w := f.postToken(t, tokenRefreshForm(refreshToken), withBasicTokenAuth("test-client", "test-secret"))

	assertTokenError(t, w, http.StatusBadRequest, "invalid_grant")
	assert.NoError(t, f.mock.ExpectationsWereMet())
}

// assertPublicRefreshEmptySecretRejectedByDefault verifies public duplicate auth rejection.
func (f *oidcTokenTest) assertPublicRefreshEmptySecretRejectedByDefault(t *testing.T) {
	f.cfg.clients = append(f.cfg.clients, config.OIDCClient{
		ClientID:     "public-refresh-client-no-compat",
		RedirectURIs: []string{"http://127.0.0.1"},
	})

	form := tokenRefreshForm("any-token")
	form.Add(oidcParamClientID, "public-refresh-client-no-compat")
	form.Add(oidcParamClientSecret, "")
	w := f.postToken(t, form, withBasicTokenAuth("public-refresh-client-no-compat", ""))

	assertTokenError(t, w, http.StatusUnauthorized, "invalid_client")
}

// assertPublicRefreshEmptySecretAcceptedWithCompatibility verifies public-client compatibility.
func (f *oidcTokenTest) assertPublicRefreshEmptySecretAcceptedWithCompatibility(t *testing.T) {
	f.cfg.clients = append(f.cfg.clients, config.OIDCClient{
		ClientID:                            "public-refresh-client",
		RedirectURIs:                        []string{"http://127.0.0.1"},
		AllowRefreshTokenCombinedClientAuth: true,
	})

	refreshToken := "refresh-token-public-client-empty-body-secret"
	f.expectRefreshTokenRotation(t, refreshToken, newRefreshTokenSession("public-refresh-client"))

	form := tokenRefreshForm(refreshToken)
	form.Add(oidcParamClientID, "public-refresh-client")
	form.Add(oidcParamClientSecret, "")
	w := f.postToken(t, form, withBasicTokenAuth("public-refresh-client", ""))

	assertTokenHasFields(t, w, "access_token", "refresh_token")
	assert.NoError(t, f.mock.ExpectationsWereMet())
}

// assertConfidentialEmptySecretWithCompatibilityRejected verifies confidential-client exclusion.
func (f *oidcTokenTest) assertConfidentialEmptySecretWithCompatibilityRejected(t *testing.T) {
	origCompat := f.cfg.clients[0].AllowRefreshTokenCombinedClientAuth

	f.cfg.clients[0].AllowRefreshTokenCombinedClientAuth = true
	defer func() { f.cfg.clients[0].AllowRefreshTokenCombinedClientAuth = origCompat }()

	form := tokenRefreshForm("any-token")
	form.Add(oidcParamClientID, "test-client")
	form.Add(oidcParamClientSecret, "")
	w := f.postToken(t, form, withBasicTokenAuth("test-client", "test-secret"))

	assertTokenError(t, w, http.StatusUnauthorized, "invalid_client")
}

// assertEnforcedMethodMismatchRejected verifies configured auth method enforcement.
func (f *oidcTokenTest) assertEnforcedMethodMismatchRejected(t *testing.T) {
	f.cfg.clients[0].TokenEndpointAuthMethod = "client_secret_basic"
	form := tokenAuthCodeForm("any-code", "")
	form.Del(oidcParamRedirectURI)
	form.Add(oidcParamClientID, "test-client")
	form.Add(oidcParamClientSecret, "test-secret")

	w := f.postToken(t, form, nil)

	assertTokenError(t, w, http.StatusUnauthorized, "invalid_client")
}

// assertPrivateKeyJWTClientSecretDowngradeRejected verifies assertion auth is mandatory.
func (f *oidcTokenTest) assertPrivateKeyJWTClientSecretDowngradeRejected(t *testing.T) {
	originalClient := f.cfg.clients[0]
	defer func() {
		f.cfg.clients[0] = originalClient
	}()

	f.cfg.clients[0].TokenEndpointAuthMethod = clientauth.MethodPrivateKeyJWT

	w := f.postToken(t, tokenAuthCodeForm("private-key-jwt-downgrade-code", "https://app.com/callback"), withBasicTokenAuth("test-client", "test-secret"))

	assertTokenError(t, w, http.StatusUnauthorized, "invalid_client")
}

// assertPublicClientBodyOnlyToken verifies a public-client authorization code exchange.
func (f *oidcTokenTest) assertPublicClientBodyOnlyToken(t *testing.T) {
	code := "public-client-code"
	verifier := strings.Repeat("c", 43)
	publicClient := config.OIDCClient{
		ClientID:                "public-client",
		RedirectURIs:            []string{"https://app.com/public-callback"},
		TokenEndpointAuthMethod: "none",
	}
	f.cfg.clients = append(f.cfg.clients, publicClient)
	session := newPKCEAuthCodeSession(publicClient.ClientID, "https://app.com/public-callback", verifier, "S256")
	f.expectAuthorizationCodeSession(t, code, session)

	form := tokenAuthCodeForm(code, "https://app.com/public-callback")
	form.Add(oidcParamClientID, publicClient.ClientID)
	form.Add("code_verifier", verifier)
	w := f.postToken(t, form, nil)

	assertTokenHasFields(t, w, "id_token")
	assert.NoError(t, f.mock.ExpectationsWereMet())
}

// assertPKCES256Valid verifies a confidential-client PKCE S256 exchange.
func (f *oidcTokenTest) assertPKCES256Valid(t *testing.T) {
	code := "pkce-s256-code"
	verifier := strings.Repeat("a", 43)
	w := f.postPKCEAuthCode(t, code, verifier, "S256", "https://app.com/callback", "https://app.com/callback")

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, f.mock.ExpectationsWereMet())
}

// assertClientCredentialsOpenIDScopeRejected verifies service tokens cannot request identity scopes.
func (f *oidcTokenTest) assertClientCredentialsOpenIDScopeRejected(t *testing.T) {
	t.Helper()

	originalClient := f.cfg.clients[0]
	defer func() {
		f.cfg.clients[0] = originalClient
	}()

	f.cfg.clients[0].GrantTypes = []string{oidcGrantTypeClientCredentials}
	f.cfg.clients[0].Scopes = []string{definitions.ScopeOpenID, "api.read"}

	form := url.Values{}
	form.Add(oidcParamGrantType, oidcGrantTypeClientCredentials)
	form.Add(oidcParamScope, definitions.ScopeOpenID)

	w := f.postToken(t, form, withBasicTokenAuth("test-client", "test-secret"))
	resp := mustDecodeOIDCTestJSON(t, w)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, oidcErrorInvalidScope, resp[definitions.LogKeyError])
}

// assertPublicClientCredentialsRejected verifies public clients cannot use confidential grants.
func (f *oidcTokenTest) assertPublicClientCredentialsRejected(t *testing.T) {
	publicClient := config.OIDCClient{
		ClientID:                "public-client-credentials",
		TokenEndpointAuthMethod: oidcClientAuthMethodNone,
		GrantTypes:              []string{oidcGrantTypeClientCredentials},
		Scopes:                  []string{"api.read"},
	}
	f.cfg.clients = append(f.cfg.clients, publicClient)

	form := url.Values{}
	form.Add(oidcParamGrantType, oidcGrantTypeClientCredentials)
	form.Add(oidcParamClientID, publicClient.ClientID)
	form.Add(oidcParamScope, "api.read")

	w := f.postToken(t, form, nil)

	assertTokenError(t, w, http.StatusBadRequest, oidcErrorUnauthorizedClient)
}

// assertConfidentialClientCredentialsAccepted verifies legitimate confidential grants.
func (f *oidcTokenTest) assertConfidentialClientCredentialsAccepted(t *testing.T) {
	originalClient := f.cfg.clients[0]
	defer func() {
		f.cfg.clients[0] = originalClient
	}()

	f.cfg.clients[0].GrantTypes = []string{oidcGrantTypeClientCredentials}
	f.cfg.clients[0].Scopes = []string{"api.read"}

	form := url.Values{}
	form.Add(oidcParamGrantType, oidcGrantTypeClientCredentials)
	form.Add(oidcParamScope, "api.read")

	w := f.postToken(t, form, withBasicTokenAuth("test-client", "test-secret"))

	assertTokenHasFields(t, w, oidcJSONFieldAccessToken)
}

// assertRedirectURIMismatchRejected verifies redirect_uri replay protection.
func (f *oidcTokenTest) assertRedirectURIMismatchRejected(t *testing.T) {
	code := "redirect-uri-mismatch-code"
	verifier := strings.Repeat("a", 43)
	w := f.postPKCEAuthCode(t, code, verifier, "S256", "https://app.com/callback", "https://evil.com/callback")

	assertTokenError(t, w, http.StatusBadRequest, "invalid_grant")
	assert.NoError(t, f.mock.ExpectationsWereMet())
}

// assertMissingPKCEVerifierRejected verifies missing verifier rejection.
func (f *oidcTokenTest) assertMissingPKCEVerifierRejected(t *testing.T) {
	code := "pkce-s256-missing-verifier"
	session := &idp.OIDCSession{
		ClientID:            "test-client",
		UserID:              "user123",
		Scopes:              []string{definitions.ScopeOpenID},
		RedirectURI:         "https://app.com/callback",
		CodeChallenge:       "dummy",
		CodeChallengeMethod: "S256",
	}
	f.expectAuthorizationCodeSession(t, code, session)

	w := f.postToken(t, tokenAuthCodeForm(code, "https://app.com/callback"), withBasicTokenAuth("test-client", "test-secret"))

	assertTokenError(t, w, http.StatusBadRequest, "invalid_grant")
	assert.NoError(t, f.mock.ExpectationsWereMet())
}

// assertPlainPKCERejected verifies that plain PKCE remains unsupported.
func (f *oidcTokenTest) assertPlainPKCERejected(t *testing.T) {
	code := "pkce-plain-code"
	verifier := strings.Repeat("b", 43)
	w := f.postPKCEAuthCode(t, code, verifier, "plain", "https://app.com/callback", "https://app.com/callback")

	assertTokenError(t, w, http.StatusBadRequest, "invalid_grant")
	assert.NoError(t, f.mock.ExpectationsWereMet())
}

// postPKCEAuthCode posts an authorization-code token request with PKCE fixtures.
func (f *oidcTokenTest) postPKCEAuthCode(t *testing.T, code string, verifier string, method string, sessionRedirectURI string, formRedirectURI string) *httptest.ResponseRecorder {
	t.Helper()

	session := newPKCEAuthCodeSession("test-client", sessionRedirectURI, verifier, method)
	f.expectAuthorizationCodeSession(t, code, session)

	form := tokenAuthCodeForm(code, formRedirectURI)
	form.Add("code_verifier", verifier)

	return f.postToken(t, form, withBasicTokenAuth("test-client", "test-secret"))
}

func TestOIDCHandler_Token(t *testing.T) {
	definitions.SetDbgModuleMapping(definitions.NewDbgModuleMapping())
	gin.SetMode(gin.TestMode)

	fixture := newOIDCTokenTest(t)

	t.Run("Token request with duplicate sensitive form values is rejected", fixture.assertDuplicateSensitiveFormValuesRejected)
	t.Run("Token request with Basic Auth", fixture.assertAuthorizationCodeBasicAuth)
	t.Run("Token request with client_id in body and secret in Basic Auth (should fail)", fixture.assertBodyClientIDWithBasicSecretRejected)
	t.Run("Token request with URL-encoded characters in Basic Auth", fixture.assertURLEncodedBasicAuth)
	t.Run("Token request with both Header and Body (matching - should fail)", func(t *testing.T) {
		fixture.assertInvalidClientForCombinedClientAuth(t, "authorization_code", "code", "any-code")
	})
	t.Run("Token request with 11 vs 6 chars mismatch (reproduce user log)", fixture.assertSecretLengthMismatchRejected)
	t.Run("Token request with multiple methods (should fail)", fixture.assertMultipleMethodsRejected)

	t.Run("Refresh token request with basic and matching body credentials is rejected by default", func(t *testing.T) {
		fixture.assertInvalidClientForCombinedClientAuth(t, "refresh_token", "refresh_token", "any-token")
	})

	t.Run("Refresh token request with basic and matching body credentials is accepted when compatibility is enabled for confidential client", fixture.assertRefreshCombinedAuthAcceptedForConfidentialClient)
	t.Run("Refresh token request with invalid token returns invalid_grant", fixture.assertInvalidRefreshToken)
	t.Run("Refresh token request without rotation reuses token and omits refresh_token in response", fixture.assertRefreshWithoutRotation)
	t.Run("Refresh token request with invalid token logs failure reason", fixture.assertRefreshInvalidTokenLogsFailureReason)
	t.Run("Refresh token request with client mismatch returns invalid_grant", fixture.assertRefreshClientMismatch)

	t.Run("Refresh token request for public client with empty body client_secret and Basic Auth is rejected by default", fixture.assertPublicRefreshEmptySecretRejectedByDefault)
	t.Run("Refresh token request for public client with empty body client_secret and Basic Auth is accepted when compatibility is enabled", fixture.assertPublicRefreshEmptySecretAcceptedWithCompatibility)
	t.Run("Refresh token request for confidential client with empty body client_secret and Basic Auth still fails with compatibility enabled", fixture.assertConfidentialEmptySecretWithCompatibilityRejected)
	t.Run("Token request with enforced method (mismatch should fail)", fixture.assertEnforcedMethodMismatchRejected)
	t.Run("PrivateKeyJWT client cannot downgrade to client secret authentication", fixture.assertPrivateKeyJWTClientSecretDowngradeRejected)
	t.Run("Token request with public client and client_id only in body", fixture.assertPublicClientBodyOnlyToken)
	t.Run("Token request with PKCE S256 (valid verifier)", fixture.assertPKCES256Valid)
	t.Run("Client credentials request with openid scope is rejected", fixture.assertClientCredentialsOpenIDScopeRejected)
	t.Run("Public client credentials request is rejected", fixture.assertPublicClientCredentialsRejected)
	t.Run("Confidential client credentials request is accepted", fixture.assertConfidentialClientCredentialsAccepted)

	t.Run("Token request with mismatched redirect_uri (must be rejected)", fixture.assertRedirectURIMismatchRejected)
	t.Run("Token request with PKCE S256 (missing verifier should fail)", fixture.assertMissingPKCEVerifierRejected)
	t.Run("Token request with PKCE plain (must be rejected)", fixture.assertPlainPKCERejected)
}

func TestOIDCHandler_PrivateKeyJWTClientSecretDowngradeRejected(t *testing.T) {
	definitions.SetDbgModuleMapping(definitions.NewDbgModuleMapping())
	gin.SetMode(gin.TestMode)

	newOIDCTokenTest(t).assertPrivateKeyJWTClientSecretDowngradeRejected(t)
}

func TestOIDCHandler_PublicClientCredentialsRejected(t *testing.T) {
	definitions.SetDbgModuleMapping(definitions.NewDbgModuleMapping())
	gin.SetMode(gin.TestMode)

	newOIDCTokenTest(t).assertPublicClientCredentialsRejected(t)
}

func TestOIDCHandler_ConfidentialClientCredentialsAccepted(t *testing.T) {
	definitions.SetDbgModuleMapping(definitions.NewDbgModuleMapping())
	gin.SetMode(gin.TestMode)

	newOIDCTokenTest(t).assertConfidentialClientCredentialsAccepted(t)
}
