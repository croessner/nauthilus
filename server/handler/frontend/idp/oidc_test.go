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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/idp"
	"github.com/croessner/nauthilus/v3/server/idp/clientauth"
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
	dynamicRegistration   bool
	dynamicPolicy         config.OIDCDynamicClientRegistrationConfig
	cors                  config.CORS
	trustedProxies        []string
}

func (m *mockOIDCCfg) GetIDP() *config.IDPSection {
	dynamicPolicy := m.dynamicPolicy
	dynamicPolicy.Enabled = m.dynamicRegistration

	return &config.IDPSection{
		OIDC: config.OIDCConfig{
			Issuer:                    m.issuer,
			TokenEndpointAllowGET:     m.tokenEndpointAllowGET,
			DynamicClientRegistration: dynamicPolicy,
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
	gin.SetMode(gin.TestMode)

	for _, duplicateKey := range duplicateSensitiveAuthorizeParameters() {
		t.Run(duplicateKey, func(t *testing.T) {
			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)
			ctx.Request = httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+authorizeValuesWithDuplicate(duplicateKey).Encode(), nil)

			rejectDuplicateOIDCAuthorizeParameters(ctx)

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

func TestOIDCHandlerDiscoveryAdvertisesRegistrationEndpointOnlyWhenEnabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const issuer = "https://auth.example.com"

	for _, test := range []struct {
		name    string
		enabled bool
	}{
		{name: "disabled", enabled: false},
		{name: "enabled", enabled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := mustGetOIDCDiscoveryResponseWithDCR(t, issuer, test.enabled)
			endpoint, present := response["registration_endpoint"]

			if test.enabled {
				assert.True(t, present)
				assert.Equal(t, issuer+"/oidc/register", endpoint)

				return
			}

			assert.False(t, present)
		})
	}
}

// mustGetOIDCDiscoveryResponse executes discovery and returns the JSON payload.
func mustGetOIDCDiscoveryResponse(t *testing.T, issuer string) map[string]any {
	return mustGetOIDCDiscoveryResponseWithDCR(t, issuer, false)
}

// mustGetOIDCDiscoveryResponseWithDCR executes discovery with explicit registration state.
func mustGetOIDCDiscoveryResponseWithDCR(t *testing.T, issuer string, enabled bool) map[string]any {
	t.Helper()

	cfg := &mockOIDCCfg{issuer: issuer, signingKey: secret.New(generateTestKey()), dynamicRegistration: enabled}

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

	runtime, _, _ := seedCanonicalIDPFlow(t, nil)
	h.Register(r, runtime)

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

func TestOIDCHandlerRegisterMountsRegistrationEndpointOnlyWhenEnabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	for _, test := range []struct {
		name    string
		enabled bool
	}{
		{name: "disabled", enabled: false},
		{name: "enabled", enabled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := &mockOIDCCfg{
				issuer:              "https://auth.example.com",
				signingKey:          secret.New(generateTestKey()),
				dynamicRegistration: test.enabled,
			}
			router := newOIDCTestRouter(t, cfg, false)

			present := slices.ContainsFunc(router.Routes(), func(route gin.RouteInfo) bool {
				return route.Method == http.MethodPost && route.Path == "/oidc/register"
			})
			assert.Equal(t, test.enabled, present)
		})
	}
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
		runtime, _, _ := seedCanonicalIDPFlow(t, nil)
		h.Register(r, runtime)

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
	fixture.mock.ExpectGetDel("test:oidc:code:token-code-1").SetVal(fixture.authorizationCodeSessionJSON(t))

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
	fixture.mock.ExpectGetDel("test:oidc:code:audience-code").SetVal(fixture.authorizationCodeSessionJSON(t))

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

	f.mock.ExpectGetDel("test:oidc:code:" + code).SetVal(mustMarshalOIDCSession(t, session))
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
