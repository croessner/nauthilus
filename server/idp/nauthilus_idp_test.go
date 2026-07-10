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
	"encoding/pem"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/backend/accountcache"
	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/idp/oidckeys"
	"github.com/croessner/nauthilus/v3/server/idp/signing"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
	"github.com/croessner/nauthilus/v3/server/pluginruntime"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

const (
	idpLookupModuleName        = "idp_lookup"
	idpLookupBackendName       = "identity"
	idpLookupAccount           = "canonical@example.test"
	idpLookupUniqueID          = "idp-user-123"
	idpLookupDisplayName       = "IDP Lookup User"
	idpLookupUniqueIDField     = "entryUUID"
	idpLookupDisplayNameField  = "displayName"
	idpLookupTOTPSecretField   = "totpSecret"
	idpLookupTOTPRecoveryField = "totpRecovery"
)

func TestNauthilusIDPGetUserByUsernameUsesNativePluginNoAuthIdentity(t *testing.T) {
	const (
		username = "lookup@example.test"
		clientID = "lookup-client"
	)

	pluginBackend := &idpLookupPluginBackend{}
	subjectSource := &idpLookupSubjectSource{}

	installIDPLookupPluginRunner(t, pluginBackend, subjectSource)
	idp, ctx, mock := newIDPLookupTestIDP(t, username, clientID)

	user, err := idp.GetUserByUsername(ctx, username, clientID, "")
	if err != nil {
		t.Fatalf("GetUserByUsername() error = %v", err)
	}

	if !pluginBackend.called || !pluginBackend.sawNoAuth {
		t.Fatalf("native backend call = called:%t no_auth:%t, want true/true", pluginBackend.called, pluginBackend.sawNoAuth)
	}

	if !subjectSource.called || !subjectSource.sawIdentity {
		t.Fatalf("native subject readback = called:%t identity:%t, want true/true", subjectSource.called, subjectSource.sawIdentity)
	}

	assertIDPLookupUser(t, user)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// installIDPLookupPluginRunner installs a credential-free native lookup plugin for the test.
func installIDPLookupPluginRunner(t *testing.T, backend pluginapi.Backend, subjectSource pluginapi.SubjectSource) {
	t.Helper()

	runner := newIDPLookupPluginRunner(t, backend, subjectSource)
	previousRunner, _ := pluginruntime.DefaultRunner()

	pluginruntime.SetDefaultRunner(runner)
	t.Cleanup(func() {
		pluginruntime.SetDefaultRunner(previousRunner)

		if err := runner.Stop(context.Background()); err != nil {
			t.Errorf("plugin runner Stop() error = %v", err)
		}
	})

	if len(runner.ModuleCapabilities(idpLookupModuleName)) != 0 {
		t.Fatal("IdP lookup plugin unexpectedly received credential capability")
	}
}

// newIDPLookupTestIDP builds the IdP request context and Redis expectations for the lookup path.
func newIDPLookupTestIDP(t *testing.T, username string, clientID string) (*NauthilusIDP, *gin.Context, redismock.ClientMock) {
	t.Helper()

	backendSelector := &config.Backend{}

	if err := backendSelector.Set("plugin(" + idpLookupModuleName + "." + idpLookupBackendName + ")"); err != nil {
		t.Fatalf("backend selector error = %v", err)
	}

	cfg := &config.FileSettings{Server: &config.ServerSection{
		Redis:    config.Redis{Prefix: testRedisPrefix},
		Backends: []*config.Backend{backendSelector},
	}}
	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	userKey := rediscli.GetUserHashKey(testRedisPrefix, username)
	mappingField := accountcache.GetAccountMappingField(username, definitions.ProtoOIDC, clientID)

	mock.ExpectHGet(userKey, mappingField).RedisNil()
	mock.ExpectHSet(userKey, mappingField, idpLookupAccount).SetVal(1)
	mock.ExpectHGet(userKey, mappingField).SetVal(idpLookupAccount)

	idp := NewNauthilusIDP(&deps.Deps{
		Cfg:          cfg,
		Env:          config.NewTestEnvironmentConfig(),
		Redis:        redisClient,
		AccountCache: accountcache.NewManager(cfg),
	})
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())

	ctx.Request = httptest.NewRequest("GET", "/idp/user", nil)
	setupMockContext(ctx, "idp-plugin-lookup-guid", definitions.ServIDP)

	return idp, ctx, mock
}

// newIDPLookupPluginRunner registers and starts one native backend for the IdP lookup acceptance path.
func newIDPLookupPluginRunner(
	t *testing.T,
	backend pluginapi.Backend,
	subjectSource pluginapi.SubjectSource,
) *pluginruntime.Runner {
	t.Helper()

	module := config.PluginModule{Name: idpLookupModuleName, Type: config.PluginModuleTypeGo, Path: "/plugins/idp-lookup.so"}
	registry := pluginregistry.NewRegistry()
	registrar := registry.NewRegistrar(module)
	plugin := &idpLookupPlugin{backend: backend, subjectSource: subjectSource}

	if err := plugin.Register(registrar); err != nil {
		t.Fatalf("plugin Register() error = %v", err)
	}

	if err := registrar.Commit(); err != nil {
		t.Fatalf("registrar Commit() error = %v", err)
	}

	runner := pluginruntime.NewRunnerFromInstances(registry, []pluginloader.ModuleInstance{{
		Plugin:       plugin,
		Module:       module,
		ModuleName:   module.Name,
		Status:       pluginloader.ModuleStatusRegistered,
		Capabilities: registrar.Capabilities(),
		ArtifactPath: module.Path,
	}})
	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("plugin runner Start() error = %v", err)
	}

	return runner
}

// assertIDPLookupUser verifies every safe identity value survives the native backend lookup path.
func assertIDPLookupUser(t *testing.T, user *backend.User) {
	t.Helper()

	if user == nil {
		t.Fatal("GetUserByUsername() user = nil")
	}

	assert.Equal(t, idpLookupAccount, user.Name)
	assert.Equal(t, idpLookupUniqueID, user.ID)
	assert.Equal(t, idpLookupDisplayName, user.DisplayName)
	assert.Equal(t, []string{"group-a", "group-b"}, user.Groups)
	assert.Equal(t, []string{"cn=group-a,dc=example,dc=test", "cn=group-b,dc=example,dc=test"}, user.GroupDistinguishedNames)
	assert.Equal(t, idpLookupTOTPSecretField, user.TOTPSecretField)
	assert.Equal(t, idpLookupTOTPRecoveryField, user.TOTPRecoveryField)
	assert.Equal(t, []any{"lookup@example.test"}, user.Attributes["mail"])
}

type idpLookupPlugin struct {
	backend       pluginapi.Backend
	subjectSource pluginapi.SubjectSource
}

// Metadata describes the synthetic native IdP lookup plugin.
func (p *idpLookupPlugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{Name: idpLookupModuleName, Version: "test", APIVersion: pluginapi.APIVersion}
}

// Register exposes the synthetic lookup backend without credential capability.
func (p *idpLookupPlugin) Register(registrar pluginapi.Registrar) error {
	if err := registrar.RegisterBackend(p.backend); err != nil {
		return err
	}

	return registrar.RegisterSubjectSource(p.subjectSource)
}

type idpLookupSubjectSource struct {
	called      bool
	sawIdentity bool
}

// Descriptor schedules the IdP lookup subject readback check.
func (s *idpLookupSubjectSource) Descriptor() pluginapi.SourceDescriptor {
	return pluginapi.SourceDescriptor{Name: "identity_readback", AbortPolicy: pluginapi.AbortPolicyNone}
}

// Evaluate rejects lookup results that do not expose the complete safe identity value.
func (s *idpLookupSubjectSource) Evaluate(_ context.Context, request pluginapi.SubjectRequest) (pluginapi.SubjectResult, error) {
	s.called = true
	identity := request.BackendResult.Identity
	s.sawIdentity = identity.UniqueUserIDField == idpLookupUniqueIDField &&
		identity.DisplayNameField == idpLookupDisplayNameField &&
		identity.TOTPSecretField == idpLookupTOTPSecretField &&
		identity.TOTPRecoveryField == idpLookupTOTPRecoveryField &&
		len(identity.Groups) == 2 && len(identity.GroupDistinguishedNames) == 2

	return pluginapi.SubjectResult{Rejected: !s.sawIdentity}, nil
}

type idpLookupPluginBackend struct {
	called    bool
	sawNoAuth bool
}

// Name returns the plugin-local backend name.
func (b *idpLookupPluginBackend) Name() string {
	return idpLookupBackendName
}

// VerifyPassword returns identity metadata without accessing the credential provider.
func (b *idpLookupPluginBackend) VerifyPassword(_ context.Context, request pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error) {
	b.called = true
	b.sawNoAuth = request.Snapshot.Runtime.NoAuth

	return pluginapi.BackendResult{
		Attributes: map[string][]string{
			"uid":                     {idpLookupAccount},
			"mail":                    {request.Username},
			idpLookupUniqueIDField:    {idpLookupUniqueID},
			idpLookupDisplayNameField: {idpLookupDisplayName},
		},
		Identity: pluginapi.BackendIdentityResult{
			UniqueUserIDField:       idpLookupUniqueIDField,
			DisplayNameField:        idpLookupDisplayNameField,
			TOTPSecretField:         idpLookupTOTPSecretField,
			TOTPRecoveryField:       idpLookupTOTPRecoveryField,
			Groups:                  []string{"group-b", "group-a"},
			GroupDistinguishedNames: []string{"cn=group-b,dc=example,dc=test", "cn=group-a,dc=example,dc=test"},
		},
		Account:      idpLookupAccount,
		AccountField: "uid",
		UserFound:    true,
	}, nil
}

// ListAccounts is unused by the NoAuth identity lookup path.
func (b *idpLookupPluginBackend) ListAccounts(context.Context, pluginapi.AccountListRequest) (pluginapi.AccountListResult, error) {
	return pluginapi.AccountListResult{}, nil
}

const (
	testRedisPrefix = "test:"
	testIssuer      = "https://issuer.example.com"
	testClientID    = "client1"
	testUserID      = "user123"
	testScopeClaim  = "openid profile"

	claimIssuer   = "iss"
	claimSubject  = "sub"
	claimAudience = "aud"
	claimIssuedAt = "iat"
	claimExpires  = "exp"
	claimScope    = "scope"
)

func generateTestKey() string {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	return string(pemData)
}

type mockIdpConfig struct {
	*config.FileSettings
	oidc config.OIDCConfig
	saml config.SAML2Config
}

type mockTokenGenerator struct {
	token string
	err   error
}

func (m *mockTokenGenerator) GenerateToken(prefix string) (string, error) {
	if m.err != nil {
		return "", m.err
	}

	return prefix + m.token, nil
}

func (m *mockIdpConfig) GetIDP() *config.IDPSection {
	return &config.IDPSection{
		OIDC:  m.oidc,
		SAML2: m.saml,
	}
}

func (m *mockIdpConfig) GetServer() *config.ServerSection {
	return m.FileSettings.GetServer()
}

func testAccessTokenKey(token string) string {
	return testRedisPrefix + "oidc:access_token:" + token
}

func testDeniedAccessTokenKey(token string) string {
	return testRedisPrefix + "oidc:denied_access_token:" + token
}

func testRefreshTokenKey(token string) string {
	return testRedisPrefix + "oidc:refresh_token:" + token
}

func testUserAccessTokensKey(userID string) string {
	return testRedisPrefix + "oidc:user_access_tokens:" + userID
}

func testUserRefreshTokensKey(userID string) string {
	return testRedisPrefix + "oidc:user_refresh_tokens:" + userID
}

func testOIDCKeysHashKey() string {
	return testRedisPrefix + oidckeys.RedisKeyOIDCKeys
}

type idpTraceSpanCollector struct {
	mu    sync.Mutex
	spans []sdktrace.ReadOnlySpan
}

func (c *idpTraceSpanCollector) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.spans = append(c.spans, spans...)

	return nil
}

func (c *idpTraceSpanCollector) Shutdown(context.Context) error {
	return nil
}

func (c *idpTraceSpanCollector) findSpan(name string) (sdktrace.ReadOnlySpan, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, span := range c.spans {
		if span.Name() == name {
			return span, true
		}
	}

	return nil, false
}

func installIDPTraceTestProvider(tp *sdktrace.TracerProvider) func() {
	previousProvider := otel.GetTracerProvider()

	otel.SetTracerProvider(tp)

	return func() {
		otel.SetTracerProvider(previousProvider)

		_ = tp.Shutdown(context.Background())
	}
}

func assertIDPSpanRecorded(t *testing.T, collector *idpTraceSpanCollector, name string) sdktrace.ReadOnlySpan {
	t.Helper()

	span, found := collector.findSpan(name)
	if !found {
		t.Fatalf("span %q was not recorded", name)
	}

	return span
}

func newTestIDPWithMock(t *testing.T, oidcCfg config.OIDCConfig) (*NauthilusIDP, redismock.ClientMock, rediscli.Client) {
	t.Helper()

	cfg := &mockIdpConfig{
		FileSettings: &config.FileSettings{
			Server: &config.ServerSection{
				Redis: config.Redis{
					Prefix: testRedisPrefix,
				},
			},
		},
		oidc: oidcCfg,
	}
	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	return NewNauthilusIDP(&deps.Deps{Cfg: cfg, Redis: redisClient}), mock, redisClient
}

func signedTestAccessToken(t *testing.T, kid string, pemData string) string {
	t.Helper()

	return signedTestTokenWithClaims(t, kid, pemData, jwt.MapClaims{
		claimIssuer:                testIssuer,
		claimSubject:               testUserID,
		claimAudience:              testClientID,
		claimIssuedAt:              time.Now().Add(-time.Minute).Unix(),
		claimExpires:               time.Now().Add(time.Hour).Unix(),
		claimScope:                 testScopeClaim,
		definitions.ClaimTokenType: definitions.TokenTypeAccessToken,
	})
}

func signedTestTokenWithClaims(t *testing.T, kid string, pemData string, claims jwt.MapClaims) string {
	t.Helper()

	signer, err := signing.NewRS256SignerFromPEM(pemData, kid)
	assert.NoError(t, err)

	tokenString, err := signer.Sign(claims)
	assert.NoError(t, err)

	return tokenString
}

func redisKeyMetadataJSON(t *testing.T, kid string, pemData string) string {
	t.Helper()

	raw, err := json.Marshal(oidckeys.KeyMetadata{
		ID:        kid,
		PEM:       pemData,
		Algorithm: signing.AlgorithmRS256,
		CreatedAt: time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	assert.NoError(t, err)

	return string(raw)
}

func TestNauthilusIDP_Tokens(t *testing.T) {
	fixture := newIDPTokenTestFixture(t)

	t.Run("FindClient", func(t *testing.T) {
		assertIDPFindClient(t, fixture)
	})

	t.Run("IsDelayedResponse", func(t *testing.T) {
		assertIDPDelayedResponse(t, fixture)
	})

	t.Run("IssueAndValidateToken", func(t *testing.T) {
		assertIssueAndValidateToken(t, fixture)
	})

	t.Run("IssueWithoutOpenIDScope", func(t *testing.T) {
		assertIssueWithoutOpenIDScope(t, fixture)
	})

	t.Run("IssueWithOfflineAccess", func(t *testing.T) {
		assertIssueWithOfflineAccess(t, fixture)
	})

	t.Run("ExchangeRefreshToken_WithJWTAccessToken", func(t *testing.T) {
		assertExchangeRefreshTokenWithJWTAccessToken(t, fixture)
	})

	t.Run("ExchangeRefreshToken_WithOpaqueAccessToken", func(t *testing.T) {
		assertExchangeRefreshTokenWithOpaqueAccessToken(t, fixture)
	})

	t.Run("ExchangeRefreshToken_WithoutRotation_ReusesRefreshToken", func(t *testing.T) {
		assertExchangeRefreshTokenWithoutRotation(t, fixture)
	})

	t.Run("GetClaimsWithScopes", func(t *testing.T) {
		assertGetClaimsWithScopes(t, fixture)
	})

	t.Run("FilterScopes", func(t *testing.T) {
		assertFilterScopes(t, fixture)
	})

	t.Run("IssueWithImpliedOfflineAccess", func(t *testing.T) {
		assertIssueWithImpliedOfflineAccess(t, fixture)
	})

	t.Run("ValidateToken_Heuristic", func(t *testing.T) {
		assertValidateTokenHeuristic(t, fixture)
	})
}

type idpTokenTestFixture struct {
	cfg       *mockIdpConfig
	idp       *NauthilusIDP
	mock      redismock.ClientMock
	ctx       context.Context
	fixedTime time.Time
}

// newIDPTokenTestFixture builds the shared IDP token test fixture.
func newIDPTokenTestFixture(t *testing.T) idpTokenTestFixture {
	t.Helper()

	cfg := idpTokenTestConfig()
	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	idp := NewNauthilusIDP(&deps.Deps{Cfg: cfg, Redis: redisClient})
	idp.tokenGen = &mockTokenGenerator{token: "fixed-token"}

	return idpTokenTestFixture{
		cfg:       cfg,
		idp:       idp,
		mock:      mock,
		ctx:       t.Context(),
		fixedTime: time.Date(2026, 1, 26, 8, 0, 0, 0, time.UTC),
	}
}

// idpTokenTestConfig returns the OIDC configuration for token tests.
func idpTokenTestConfig() *mockIdpConfig {
	return &mockIdpConfig{
		FileSettings: &config.FileSettings{
			Server: &config.ServerSection{
				Redis: config.Redis{
					Prefix: testRedisPrefix,
				},
			},
		},
		oidc: idpTokenOIDCConfig(),
	}
}

// idpTokenOIDCConfig returns the OIDC client and scope fixture.
func idpTokenOIDCConfig() config.OIDCConfig {
	return config.OIDCConfig{
		Issuer:       testIssuer,
		SigningKeys:  []config.OIDCKey{{ID: "default", Key: secret.New(generateTestKey()), Active: true}},
		CustomScopes: idpTokenCustomScopes(),
		Clients: []config.OIDCClient{
			{
				ClientID:             testClientID,
				RedirectURIs:         []string{"http://localhost/cb"},
				DelayedResponse:      true,
				AccessTokenLifetime:  2 * time.Hour,
				RefreshTokenLifetime: 7 * 24 * time.Hour,
			},
		},
	}
}

// idpTokenCustomScopes returns custom scope metadata for token tests.
func idpTokenCustomScopes() []config.Oauth2CustomScope {
	return []config.Oauth2CustomScope{
		{
			Name:        "resource",
			Description: "Resource scope for access claims",
			Claims: []config.OIDCCustomClaim{
				{Name: "resource.role", Type: definitions.ClaimTypeStringArray},
			},
		},
		{
			Name:        "roles",
			Description: "Role scope for compatibility mappings",
			Claims: []config.OIDCCustomClaim{
				{Name: "roles", Type: definitions.ClaimTypeStringArray},
			},
		},
	}
}

// assertIDPFindClient verifies client lookup behavior.
func assertIDPFindClient(t *testing.T, fixture idpTokenTestFixture) {
	t.Helper()

	client, found := fixture.idp.FindClient(testClientID)
	assert.True(t, found)
	assert.Equal(t, testClientID, client.ClientID)

	_, found = fixture.idp.FindClient("nonexistent")
	assert.False(t, found)
}

// assertIDPDelayedResponse verifies delayed-response client lookup behavior.
func assertIDPDelayedResponse(t *testing.T, fixture idpTokenTestFixture) {
	t.Helper()

	assert.True(t, fixture.idp.IsDelayedResponse(testClientID, ""))
	assert.False(t, fixture.idp.IsDelayedResponse("nonexistent", ""))
}

// assertIssueAndValidateToken verifies ID token issuance and validation.
func assertIssueAndValidateToken(t *testing.T, fixture idpTokenTestFixture) {
	t.Helper()

	session := testOIDCSession([]string{"openid", "profile"}, fixture.fixedTime)
	session.Nonce = "test-nonce"

	idToken, accessToken, refreshToken, expiresIn, err := fixture.idp.IssueTokens(fixture.ctx, session)
	assert.NoError(t, err)
	assert.NotEmpty(t, idToken)
	assert.NotEmpty(t, accessToken)
	assert.Empty(t, refreshToken)
	assert.Equal(t, 2*time.Hour, expiresIn)

	claims, err := fixture.idp.ValidateToken(fixture.ctx, idToken)
	assert.NoError(t, err)
	assert.Equal(t, testUserID, claims[claimSubject])
	assert.Equal(t, testIssuer, claims[claimIssuer])
	assert.Equal(t, "test-nonce", claims["nonce"])
}

// assertIssueWithoutOpenIDScope verifies that non-OIDC OAuth scopes do not emit an ID token.
func assertIssueWithoutOpenIDScope(t *testing.T, fixture idpTokenTestFixture) {
	t.Helper()

	session := testOIDCSession([]string{"profile"}, fixture.fixedTime)
	session.Nonce = "test-nonce"

	idToken, accessToken, refreshToken, expiresIn, err := fixture.idp.IssueTokens(fixture.ctx, session)
	assert.NoError(t, err)
	assert.Empty(t, idToken, "id_token must be empty when openid scope is not requested")
	assert.NotEmpty(t, accessToken)
	assert.Empty(t, refreshToken)
	assert.Equal(t, 2*time.Hour, expiresIn)
}

// assertIssueWithOfflineAccess verifies refresh-token issuance for offline access.
func assertIssueWithOfflineAccess(t *testing.T, fixture idpTokenTestFixture) {
	t.Helper()

	session := testOIDCSession([]string{"openid", "offline_access"}, fixture.fixedTime)
	expectFixedRefreshTokenStore(fixture.mock)

	idToken, accessToken, refreshToken, _, err := fixture.idp.IssueTokens(fixture.ctx, session)
	assert.NoError(t, err)
	assert.NotEmpty(t, idToken)
	assert.NotEmpty(t, accessToken)
	assert.Equal(t, "na_rt_fixed-token", refreshToken)
	assert.Equal(t, accessToken, session.AccessToken, "session must track access token")
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

// assertExchangeRefreshTokenWithJWTAccessToken verifies refresh exchange with JWT access-token revocation.
func assertExchangeRefreshTokenWithJWTAccessToken(t *testing.T, fixture idpTokenTestFixture) {
	t.Helper()

	session := testRefreshOIDCSession("header.payload.signature", fixture.fixedTime)
	refreshToken := "old-rt"
	sessionData, _ := json.Marshal(session)
	expectJWTRefreshTokenExchange(fixture.mock, refreshToken, session.AccessToken, string(sessionData))

	assertRefreshTokenExchange(t, fixture, session, refreshToken, "na_rt_fixed-token")
}

// assertExchangeRefreshTokenWithOpaqueAccessToken verifies refresh exchange with opaque access-token revocation.
func assertExchangeRefreshTokenWithOpaqueAccessToken(t *testing.T, fixture idpTokenTestFixture) {
	t.Helper()

	session := testRefreshOIDCSession("na_at_old-opaque-token", fixture.fixedTime)
	refreshToken := "old-rt-opaque"
	sessionData, _ := json.Marshal(session)
	expectOpaqueRefreshTokenExchange(fixture.mock, refreshToken, session.AccessToken, string(sessionData))

	assertRefreshTokenExchange(t, fixture, session, refreshToken, "na_rt_fixed-token")
}

// assertExchangeRefreshTokenWithoutRotation verifies stable refresh-token reuse when rotation is disabled.
func assertExchangeRefreshTokenWithoutRotation(t *testing.T, fixture idpTokenTestFixture) {
	t.Helper()

	session := testRefreshOIDCSession("header.payload.signature", fixture.fixedTime)
	refreshToken := "stable-rt"

	restore := disableRefreshTokenRotation(&fixture.cfg.oidc.Clients[0])
	defer restore()

	sessionData, _ := json.Marshal(session)
	expectStableRefreshTokenExchange(fixture.mock, refreshToken, session.AccessToken, string(sessionData))

	_, idToken, accessToken, newRefreshToken, _, err := fixture.idp.ExchangeRefreshToken(fixture.ctx, refreshToken, testClientID)
	assert.NoError(t, err)
	assert.NotEmpty(t, idToken)
	assert.NotEmpty(t, accessToken)
	assert.Empty(t, newRefreshToken)

	updatedSession := *session
	updatedSession.AccessToken = accessToken
	updatedSessionData, _ := json.Marshal(&updatedSession)
	expectStableRefreshTokenExchange(fixture.mock, refreshToken, accessToken, string(updatedSessionData))

	_, _, secondAccessToken, secondRefreshToken, _, err := fixture.idp.ExchangeRefreshToken(fixture.ctx, refreshToken, testClientID)
	assert.NoError(t, err)
	assert.NotEmpty(t, secondAccessToken)
	assert.Empty(t, secondRefreshToken)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

// testOIDCSession builds a basic user session for token issuance tests.
func testOIDCSession(scopes []string, authTime time.Time) *OIDCSession {
	return &OIDCSession{
		ClientID: testClientID,
		UserID:   testUserID,
		Scopes:   scopes,
		AuthTime: authTime,
	}
}

// testRefreshOIDCSession builds a refresh-token session with an existing access token.
func testRefreshOIDCSession(accessToken string, authTime time.Time) *OIDCSession {
	session := testOIDCSession([]string{"openid", "offline_access"}, authTime)
	session.AccessToken = accessToken

	return session
}

// expectFixedRefreshTokenStore expects persistence of the deterministic mock refresh token.
func expectFixedRefreshTokenStore(mock redismock.ClientMock) {
	mock.Regexp().ExpectSet(testRefreshTokenKey("na_rt_fixed-token"), ".*", 7*24*time.Hour).SetVal("OK")
	mock.ExpectSAdd(testUserRefreshTokensKey(testUserID), "na_rt_fixed-token").SetVal(1)
	expectUserTokenIndexTTL(mock, testUserRefreshTokensKey(testUserID), 7*24*time.Hour)
}

// expectJWTRefreshTokenExchange expects JWT access-token denial and refresh-token rotation.
func expectJWTRefreshTokenExchange(mock redismock.ClientMock, refreshToken string, accessToken string, sessionData string) {
	mock.ExpectGet(testRefreshTokenKey(refreshToken)).SetVal(sessionData)
	mock.ExpectSet(testDeniedAccessTokenKey(accessToken), "1", 2*time.Hour).SetVal("OK")
	mock.ExpectGet(testRefreshTokenKey(refreshToken)).SetVal(sessionData)
	mock.ExpectSRem(testUserRefreshTokensKey(testUserID), refreshToken).SetVal(1)
	mock.ExpectDel(testRefreshTokenKey(refreshToken)).SetVal(1)
	expectFixedRefreshTokenStore(mock)
}

// expectOpaqueRefreshTokenExchange expects opaque access-token deletion and refresh-token rotation.
func expectOpaqueRefreshTokenExchange(mock redismock.ClientMock, refreshToken string, accessToken string, sessionData string) {
	mock.ExpectGet(testRefreshTokenKey(refreshToken)).SetVal(sessionData)
	mock.ExpectGet(testAccessTokenKey(accessToken)).SetVal(sessionData)
	mock.ExpectSRem(testUserAccessTokensKey(testUserID), accessToken).SetVal(1)
	mock.ExpectDel(testAccessTokenKey(accessToken)).SetVal(1)
	mock.ExpectGet(testRefreshTokenKey(refreshToken)).SetVal(sessionData)
	mock.ExpectSRem(testUserRefreshTokensKey(testUserID), refreshToken).SetVal(1)
	mock.ExpectDel(testRefreshTokenKey(refreshToken)).SetVal(1)
	expectFixedRefreshTokenStore(mock)
}

// expectStableRefreshTokenExchange expects refresh-token reuse without rotation.
func expectStableRefreshTokenExchange(mock redismock.ClientMock, refreshToken string, accessToken string, sessionData string) {
	mock.ExpectGet(testRefreshTokenKey(refreshToken)).SetVal(sessionData)
	mock.ExpectSet(testDeniedAccessTokenKey(accessToken), "1", 2*time.Hour).SetVal("OK")
	mock.Regexp().ExpectSet(testRefreshTokenKey(refreshToken), ".*", 7*24*time.Hour).SetVal("OK")
	mock.ExpectSAdd(testUserRefreshTokensKey(testUserID), refreshToken).SetVal(0)
	expectUserTokenIndexTTL(mock, testUserRefreshTokensKey(testUserID), 7*24*time.Hour)
}

// expectUserTokenIndexTTL expects monotonic TTL updates for user token indexes.
func expectUserTokenIndexTTL(mock redismock.ClientMock, userKey string, ttl time.Duration) {
	mock.ExpectExpireNX(userKey, ttl).SetVal(true)
	mock.ExpectExpireGT(userKey, ttl).SetVal(false)
}

// assertRefreshTokenExchange verifies the common rotated refresh-token exchange result.
func assertRefreshTokenExchange(t *testing.T, fixture idpTokenTestFixture, session *OIDCSession, refreshToken string, wantRefreshToken string) {
	t.Helper()

	exchangedSession, idToken, accessToken, newRefreshToken, _, err := fixture.idp.ExchangeRefreshToken(fixture.ctx, refreshToken, testClientID)
	assert.NoError(t, err)
	assert.Equal(t, session.UserID, exchangedSession.UserID)
	assert.NotEmpty(t, idToken)
	assert.NotEmpty(t, accessToken)
	assert.Equal(t, wantRefreshToken, newRefreshToken)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

// disableRefreshTokenRotation disables rotation for one client and returns a restore function.
func disableRefreshTokenRotation(client *config.OIDCClient) func() {
	originalClient := *client
	disabled := false
	client.RevokeRefreshToken = &disabled

	return func() {
		*client = originalClient
	}
}

// assertGetClaimsWithScopes verifies scope-gated ID and access token claims.
func assertGetClaimsWithScopes(t *testing.T, fixture idpTokenTestFixture) {
	t.Helper()

	user := testClaimsUser()
	client := testClaimsClient()
	ctx, _ := gin.CreateTestContext(nil)

	assertOpenIDClaimsOnly(t, fixture, ctx, user, client)
	assertEmailClaims(t, fixture, ctx, user, client)
	assertGroupResourceClaims(t, fixture, ctx, user, client)
	assertImpliedRoleClaims(t, fixture, ctx, user, client)
}

// testClaimsUser returns the user fixture for claim materialization tests.
func testClaimsUser() *backend.User {
	return &backend.User{
		ID:          testUserID,
		Name:        "jdoe",
		DisplayName: "John Doe",
		Attributes: bktype.AttributeMapping{
			"mail":     {"jdoe@example.com"},
			"memberOf": {"group1"},
		},
	}
}

// testClaimsClient returns the OIDC client fixture for claim materialization tests.
func testClaimsClient() *config.OIDCClient {
	return &config.OIDCClient{
		ClientID: testClientID,
		IDTokenClaims: config.IDTokenClaims{
			Mappings: []config.OIDCClaimMapping{
				{Claim: definitions.ClaimEmail, Attribute: "mail", Type: definitions.ClaimTypeString},
				{Claim: definitions.ClaimGroups, Attribute: "memberOf", Type: definitions.ClaimTypeStringArray},
				{Claim: "roles", Attribute: "memberOf", Type: definitions.ClaimTypeStringArray},
			},
		},
		AccessTokenClaims: config.AccessTokenClaims{
			Mappings: []config.OIDCClaimMapping{
				{Claim: "resource.role", Attribute: "memberOf", Type: definitions.ClaimTypeStringArray},
				{Claim: "roles", Attribute: "memberOf", Type: definitions.ClaimTypeStringArray},
			},
		},
	}
}

// assertOpenIDClaimsOnly verifies defaults without optional scope claims.
func assertOpenIDClaimsOnly(t *testing.T, fixture idpTokenTestFixture, ctx *gin.Context, user *backend.User, client *config.OIDCClient) {
	t.Helper()

	idClaims, accessClaims, err := fixture.idp.GetClaims(ctx, user, client, []string{"openid"})
	assert.NoError(t, err)
	assert.Equal(t, testUserID, idClaims[claimSubject])
	assert.Equal(t, "John Doe", idClaims["name"])
	assert.Nil(t, idClaims["email"])
	assert.Nil(t, idClaims["groups"])
	assert.Nil(t, idClaims["roles"])
	assert.Nil(t, accessClaims["roles"])
	assert.Nil(t, accessClaims["resource.role"])
}

// assertEmailClaims verifies email scope materialization.
func assertEmailClaims(t *testing.T, fixture idpTokenTestFixture, ctx *gin.Context, user *backend.User, client *config.OIDCClient) {
	t.Helper()

	idClaims, accessClaims, err := fixture.idp.GetClaims(ctx, user, client, []string{"openid", "email"})
	assert.NoError(t, err)
	assert.Equal(t, "jdoe@example.com", idClaims["email"])
	assert.Nil(t, idClaims["groups"])
	assert.Nil(t, accessClaims["resource.role"])
}

// assertGroupResourceClaims verifies group and custom resource claim materialization.
func assertGroupResourceClaims(t *testing.T, fixture idpTokenTestFixture, ctx *gin.Context, user *backend.User, client *config.OIDCClient) {
	t.Helper()

	idClaims, accessClaims, err := fixture.idp.GetClaims(ctx, user, client, []string{"openid", "groups", "resource"})
	assert.NoError(t, err)
	assert.Nil(t, idClaims["email"])
	assert.Equal(t, []string{"group1"}, idClaims["groups"])
	assert.Nil(t, idClaims["roles"])
	assert.Equal(t, []string{"group1"}, accessClaims["resource.role"])
	assert.Nil(t, accessClaims["roles"])
}

// assertImpliedRoleClaims verifies compatibility role claims from implied scopes.
func assertImpliedRoleClaims(t *testing.T, fixture idpTokenTestFixture, ctx *gin.Context, user *backend.User, client *config.OIDCClient) {
	t.Helper()

	clientWithImpliedRoles := &config.OIDCClient{
		ClientID:          testClientID,
		Scopes:            []string{"openid", "roles"},
		ImpliedScopes:     []string{"roles"},
		IDTokenClaims:     client.IDTokenClaims,
		AccessTokenClaims: client.AccessTokenClaims,
	}
	filteredScopes := fixture.idp.FilterScopes(clientWithImpliedRoles, []string{"openid"})
	assert.Equal(t, []string{"openid", "roles"}, filteredScopes)

	idClaims, accessClaims, err := fixture.idp.GetClaims(ctx, user, clientWithImpliedRoles, filteredScopes)
	assert.NoError(t, err)
	assert.Equal(t, []string{"group1"}, idClaims["roles"])
	assert.Equal(t, []string{"group1"}, accessClaims["roles"])
}

// assertFilterScopes verifies requested and implied scope filtering.
func assertFilterScopes(t *testing.T, fixture idpTokenTestFixture) {
	t.Helper()

	for _, tc := range filterScopeCases() {
		t.Run(tc.name, func(t *testing.T) {
			filtered := fixture.idp.FilterScopes(tc.client, tc.requested)
			assert.Equal(t, tc.want, filtered)
		})
	}
}

type filterScopeCase struct {
	name      string
	client    *config.OIDCClient
	requested []string
	want      []string
}

// filterScopeCases returns scope filtering scenarios.
func filterScopeCases() []filterScopeCase {
	return []filterScopeCase{
		{
			name:      "requested allowed scopes",
			client:    &config.OIDCClient{ClientID: testClientID, Scopes: []string{"openid", "profile"}},
			requested: []string{"openid", "profile"},
			want:      []string{"openid", "profile"},
		},
		{
			name:      "requested mixed scopes",
			client:    &config.OIDCClient{ClientID: testClientID, Scopes: []string{"openid", "profile"}},
			requested: []string{"openid", "profile", "email", "invalid"},
			want:      []string{"openid", "profile"},
		},
		{
			name:      "default scopes when none configured",
			client:    &config.OIDCClient{ClientID: "client2"},
			requested: []string{"openid", "profile", "email", "groups", "offline_access", "invalid"},
			want:      []string{"openid", "profile", "email", "groups", "offline_access"},
		},
		{
			name:      "adds implied scopes when allowed",
			client:    &config.OIDCClient{ClientID: "client3", Scopes: []string{"openid", "profile", "offline_access", "roles"}, ImpliedScopes: []string{"offline_access", "roles"}},
			requested: []string{"openid", "profile"},
			want:      []string{"openid", "profile", "offline_access", "roles"},
		},
		{
			name:      "keeps stable order and deduplicates implied scopes",
			client:    &config.OIDCClient{ClientID: "client4", Scopes: []string{"openid", "profile", "offline_access"}, ImpliedScopes: []string{"offline_access", "offline_access"}},
			requested: []string{"openid", "offline_access"},
			want:      []string{"openid", "offline_access"},
		},
		{
			name:      "ignores implied scopes that are not allowed",
			client:    &config.OIDCClient{ClientID: "client5", Scopes: []string{"openid", "profile"}, ImpliedScopes: []string{"offline_access"}},
			requested: []string{"openid"},
			want:      []string{"openid"},
		},
	}
}

// assertIssueWithImpliedOfflineAccess verifies implied offline_access refresh issuance.
func assertIssueWithImpliedOfflineAccess(t *testing.T, fixture idpTokenTestFixture) {
	t.Helper()

	client := &config.OIDCClient{
		ClientID:             testClientID,
		Scopes:               []string{"openid", "profile", "offline_access"},
		ImpliedScopes:        []string{"offline_access"},
		RefreshTokenLifetime: 7 * 24 * time.Hour,
	}
	filteredScopes := fixture.idp.FilterScopes(client, []string{"openid", "profile"})
	assert.Equal(t, []string{"openid", "profile", "offline_access"}, filteredScopes)

	session := testOIDCSession(filteredScopes, fixture.fixedTime)
	expectFixedRefreshTokenStore(fixture.mock)

	_, _, refreshToken, _, err := fixture.idp.IssueTokens(fixture.ctx, session)
	assert.NoError(t, err)
	assert.Equal(t, "na_rt_fixed-token", refreshToken)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

// assertValidateTokenHeuristic verifies JWT and opaque token Redis lookup routing.
func assertValidateTokenHeuristic(t *testing.T, fixture idpTokenTestFixture) {
	t.Helper()

	_, err := fixture.idp.ValidateToken(fixture.ctx, "header.payload.signature")
	assert.Error(t, err)
	assert.NoError(t, fixture.mock.ExpectationsWereMet(), "Redis should not have been hit for JWT-like token")

	opaqueToken := "na_at_someopaquevalue"
	fixture.mock.ExpectGet(testAccessTokenKey(opaqueToken)).RedisNil()
	_, err = fixture.idp.ValidateToken(fixture.ctx, opaqueToken)
	assert.Error(t, err)
	assert.NoError(t, fixture.mock.ExpectationsWereMet(), "Redis should have been hit for opaque token")
}

func TestValidateTokenOpaqueUsesSingleRedisLookup(t *testing.T) {
	idp, mock, _ := newTestIDPWithMock(t, config.OIDCConfig{
		Issuer: testIssuer,
	})

	tokenString := "na_at_single-read"
	session := &OIDCSession{
		ClientID:          testClientID,
		UserID:            testUserID,
		Scopes:            []string{"openid", "profile"},
		AccessTokenClaims: map[string]any{"role": "reader"},
	}

	sessionData, err := json.Marshal(session)
	assert.NoError(t, err)

	mock.ExpectGet(testAccessTokenKey(tokenString)).SetVal(string(sessionData))

	claims, err := idp.ValidateToken(t.Context(), tokenString)
	assert.NoError(t, err)
	assert.Equal(t, testUserID, claims[claimSubject])
	assert.Equal(t, testClientID, claims[claimAudience])
	assert.Equal(t, testScopeClaim, claims[claimScope])
	assert.Equal(t, "reader", claims["role"])
	assert.NoError(t, mock.ExpectationsWereMet(), "opaque token validation must use the session loaded by the first Redis lookup")
}

func TestValidateTokenJWTResolvesRedisKeyByKID(t *testing.T) {
	idp, mock, _ := newTestIDPWithMock(t, config.OIDCConfig{
		Issuer: testIssuer,
	})
	mock.MatchExpectationsInOrder(false)

	kid := "redis-key-1"
	pemData := generateTestKey()
	tokenString := signedTestAccessToken(t, kid, pemData)

	mock.ExpectHGet(testOIDCKeysHashKey(), kid).SetVal(redisKeyMetadataJSON(t, kid, pemData))
	mock.ExpectGet(testDeniedAccessTokenKey(tokenString)).RedisNil()

	claims, err := idp.ValidateToken(t.Context(), tokenString)
	assert.NoError(t, err)
	assert.Equal(t, testUserID, claims[claimSubject])
	assert.NoError(t, mock.ExpectationsWereMet(), "JWT validation should resolve the public key by kid and still check the denylist")
}

func TestValidateTokenJWTRejectsDeniedTokenAfterSignatureValidation(t *testing.T) {
	idp, mock, _ := newTestIDPWithMock(t, config.OIDCConfig{
		Issuer: testIssuer,
	})
	mock.MatchExpectationsInOrder(false)

	kid := "denied-key-1"
	pemData := generateTestKey()
	tokenString := signedTestAccessToken(t, kid, pemData)

	mock.ExpectHGet(testOIDCKeysHashKey(), kid).SetVal(redisKeyMetadataJSON(t, kid, pemData))
	mock.ExpectGet(testDeniedAccessTokenKey(tokenString)).SetVal("1")

	claims, err := idp.ValidateToken(t.Context(), tokenString)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "revoked")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIssueIDTokenReservedClaimsRemainCanonical(t *testing.T) {
	fixture := newIDPTokenTestFixture(t)
	session := testOIDCSession([]string{definitions.ScopeOpenID, definitions.ScopeProfile}, fixture.fixedTime)
	session.Nonce = "issuer-nonce"
	session.IDTokenClaims = map[string]any{
		"acr":                      "urn:evil:acr",
		"amr":                      []string{"pwd"},
		"aud":                      "evil-client",
		"custom_id":                "allowed",
		"exp":                      int64(1),
		"iat":                      int64(1),
		"iss":                      "https://evil.example.test",
		"nonce":                    "evil-nonce",
		"sub":                      "attacker",
		definitions.ClaimTokenType: definitions.TokenTypeAccessToken,
	}
	signer := &captureAccessTokenSigner{}

	_, err := fixture.idp.issueIDToken(session, signer, testIssuer, fixture.fixedTime, 2*time.Hour)
	assert.NoError(t, err)

	assert.Equal(t, testIssuer, signer.claims[claimIssuer])
	assert.Equal(t, testUserID, signer.claims[claimSubject])
	assert.Equal(t, testClientID, signer.claims[claimAudience])
	assert.Equal(t, fixture.fixedTime.Add(2*time.Hour).Unix(), signer.claims[claimExpires])
	assert.Equal(t, fixture.fixedTime.Unix(), signer.claims[claimIssuedAt])
	assert.Equal(t, "issuer-nonce", signer.claims["nonce"])
	assert.Nil(t, signer.claims["acr"])
	assert.Nil(t, signer.claims["amr"])
	assert.Nil(t, signer.claims[definitions.ClaimTokenType])
	assert.Equal(t, "allowed", signer.claims["custom_id"])
}

func TestValidateTokenForUserInfoRequiresOpenIDScope(t *testing.T) {
	idp, mock, _ := newTestIDPWithMock(t, config.OIDCConfig{
		Issuer: testIssuer,
	})
	mock.MatchExpectationsInOrder(false)

	kid := "userinfo-no-openid"
	pemData := generateTestKey()
	tokenString := signedTestTokenWithClaims(t, kid, pemData, jwt.MapClaims{
		claimIssuer:                testIssuer,
		claimSubject:               testUserID,
		claimAudience:              testClientID,
		claimIssuedAt:              time.Now().Add(-time.Minute).Unix(),
		claimExpires:               time.Now().Add(time.Hour).Unix(),
		claimScope:                 definitions.ScopeProfile,
		definitions.ClaimTokenType: definitions.TokenTypeAccessToken,
	})

	mock.ExpectHGet(testOIDCKeysHashKey(), kid).SetVal(redisKeyMetadataJSON(t, kid, pemData))
	mock.ExpectGet(testDeniedAccessTokenKey(tokenString)).RedisNil()

	claims, err := idp.ValidateTokenForUserInfo(t.Context(), tokenString)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestValidateTokenForUserInfoAcceptsOpenIDScope(t *testing.T) {
	idp, mock, _ := newTestIDPWithMock(t, config.OIDCConfig{
		Issuer: testIssuer,
	})
	mock.MatchExpectationsInOrder(false)

	kid := "userinfo-openid"
	pemData := generateTestKey()
	tokenString := signedTestAccessToken(t, kid, pemData)

	mock.ExpectHGet(testOIDCKeysHashKey(), kid).SetVal(redisKeyMetadataJSON(t, kid, pemData))
	mock.ExpectGet(testDeniedAccessTokenKey(tokenString)).RedisNil()

	claims, err := idp.ValidateTokenForUserInfo(t.Context(), tokenString)
	assert.NoError(t, err)
	assert.Equal(t, testUserID, claims[claimSubject])
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestValidateTokenEmitsDiagnosticChildSpans(t *testing.T) {
	collector := &idpTraceSpanCollector{}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(collector)),
	)

	restore := installIDPTraceTestProvider(tp)
	defer restore()

	idp, mock, _ := newTestIDPWithMock(t, config.OIDCConfig{
		Issuer: testIssuer,
	})
	mock.MatchExpectationsInOrder(false)

	kid := "trace-key-1"
	pemData := generateTestKey()
	tokenString := signedTestAccessToken(t, kid, pemData)

	mock.ExpectHGet(testOIDCKeysHashKey(), kid).SetVal(redisKeyMetadataJSON(t, kid, pemData))
	mock.ExpectGet(testDeniedAccessTokenKey(tokenString)).RedisNil()

	_, err := idp.ValidateToken(t.Context(), tokenString)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())

	assertIDPSpanRecorded(t, collector, "idp.validate_token")
	assertIDPSpanRecorded(t, collector, "idp.validate_token.jwt.verify")
	assertIDPSpanRecorded(t, collector, "idp.validate_token.jwt.key_resolve")
	assertIDPSpanRecorded(t, collector, "idp.validate_token.jwt.denylist")
}

func TestNauthilusIDP_FindSAMLServiceProvider_ReturnsSliceElement(t *testing.T) {
	cfg := &mockIdpConfig{
		FileSettings: &config.FileSettings{
			Server: &config.ServerSection{
				Redis: config.Redis{
					Prefix: testRedisPrefix,
				},
			},
		},
		saml: config.SAML2Config{
			ServiceProviders: []config.SAML2ServiceProvider{
				{
					Name:     "test-client",
					EntityID: "https://localhost:9095/saml/metadata",
					ACSURL:   "https://localhost:9095/saml/acs",
					SLOURL:   "https://localhost:9095/saml/slo",
				},
			},
		},
	}

	idp := NewNauthilusIDP(&deps.Deps{Cfg: cfg})

	sp, found := idp.FindSAMLServiceProvider("https://localhost:9095/saml/metadata")
	assert.True(t, found)

	if !assert.NotNil(t, sp) {
		return
	}

	sp.Name = "updated-client"

	assert.Equal(t, "updated-client", cfg.saml.ServiceProviders[0].Name)
}

func TestNauthilusIDP_ClientCredentials(t *testing.T) {
	idpInst := newClientCredentialsTestIDP()

	t.Run("IssueClientCredentialsToken_Success", func(t *testing.T) {
		assertIssueClientCredentialsToken(t, idpInst)
	})

	t.Run("IssueClientCredentialsToken_UnsupportedGrant", func(t *testing.T) {
		assertClientCredentialsTokenError(t, idpInst, "authcode-only", []string{"openid"}, "does not support client_credentials")
	})

	t.Run("IssueClientCredentialsToken_OpenIDScopeRejected", func(t *testing.T) {
		assertClientCredentialsTokenError(t, idpInst, "cc-client", []string{definitions.ScopeOpenID}, "openid scope is not allowed")
	})

	t.Run("IssueClientCredentialsToken_UnknownClient", func(t *testing.T) {
		assertClientCredentialsTokenError(t, idpInst, "nonexistent", nil, "client not found")
	})

	t.Run("SupportsGrantType", func(t *testing.T) {
		assertClientCredentialsGrantTypes(t, idpInst)
	})
}

// newClientCredentialsTestIDP builds the IDP fixture for client-credentials tests.
func newClientCredentialsTestIDP() *NauthilusIDP {
	cfg := &mockIdpConfig{
		FileSettings: &config.FileSettings{
			Server: &config.ServerSection{
				Redis: config.Redis{
					Prefix: testRedisPrefix,
				},
			},
		},
		oidc: clientCredentialsOIDCConfig(),
	}
	db, _ := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	return NewNauthilusIDP(&deps.Deps{Cfg: cfg, Redis: redisClient})
}

// clientCredentialsOIDCConfig returns clients for client-credentials grant tests.
func clientCredentialsOIDCConfig() config.OIDCConfig {
	return config.OIDCConfig{
		Issuer:      testIssuer,
		SigningKeys: []config.OIDCKey{{ID: "default", Key: secret.New(generateTestKey()), Active: true}},
		Clients: []config.OIDCClient{
			{
				ClientID:            "cc-client",
				ClientSecret:        secret.New("cc-secret"),
				GrantTypes:          []string{"client_credentials"},
				Scopes:              []string{definitions.ScopeOpenID, "api.read", "api.write"},
				AccessTokenLifetime: time.Hour,
			},
			{
				ClientID:     "authcode-only",
				ClientSecret: secret.New("secret"),
				RedirectURIs: []string{"http://localhost/cb"},
			},
		},
	}
}

// assertIssueClientCredentialsToken verifies successful client-credentials token issuance.
func assertIssueClientCredentialsToken(t *testing.T, idpInst *NauthilusIDP) {
	t.Helper()

	ctx := t.Context()
	accessToken, expiresIn, err := idpInst.IssueClientCredentialsToken(ctx, "cc-client", []string{"api.read"})
	assert.NoError(t, err)
	assert.NotEmpty(t, accessToken)
	assert.Equal(t, time.Hour, expiresIn)
	assert.Contains(t, accessToken, ".")

	claims, err := idpInst.ValidateToken(ctx, accessToken)
	assert.NoError(t, err)
	assert.Equal(t, "cc-client", claims[claimSubject])
	assert.Equal(t, definitions.AudienceBackchannelAPI, claims[claimAudience])
	assert.Equal(t, testIssuer, claims[claimIssuer])
	assert.Equal(t, definitions.TokenTypeAccessToken, claims[definitions.ClaimTokenType])
}

// assertClientCredentialsTokenError verifies a failing client-credentials token request.
func assertClientCredentialsTokenError(t *testing.T, idpInst *NauthilusIDP, clientID string, scopes []string, contains string) {
	t.Helper()

	_, _, err := idpInst.IssueClientCredentialsToken(t.Context(), clientID, scopes)
	if !assert.Error(t, err) {
		return
	}

	assert.Contains(t, err.Error(), contains)
}

// assertClientCredentialsGrantTypes verifies grant-type capability checks.
func assertClientCredentialsGrantTypes(t *testing.T, idpInst *NauthilusIDP) {
	t.Helper()

	ccClient, ok := idpInst.FindClient("cc-client")
	assert.True(t, ok)
	assert.True(t, ccClient.SupportsGrantType("client_credentials"))
	assert.False(t, ccClient.SupportsGrantType("authorization_code"))

	acClient, ok := idpInst.FindClient("authcode-only")
	assert.True(t, ok)
	assert.True(t, acClient.SupportsGrantType("authorization_code"))
	assert.False(t, acClient.SupportsGrantType("client_credentials"))
}
