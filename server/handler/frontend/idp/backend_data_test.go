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
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/backend/accountcache"
	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/v3/server/backend/remote"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	_ "github.com/croessner/nauthilus/v3/server/core/auth"
	"github.com/croessner/nauthilus/v3/server/definitions"
	authv1 "github.com/croessner/nauthilus/v3/server/grpcapi/auth/v1"
	commonv1 "github.com/croessner/nauthilus/v3/server/grpcapi/common/v1"
	identityv1 "github.com/croessner/nauthilus/v3/server/grpcapi/identity/v1"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/model/mfa"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/croessner/nauthilus/v3/server/security"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/go-webauthn/webauthn/webauthn"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
)

type webAuthnBackendTestConfig struct {
	config.File
	prefix string
	ttl    time.Duration
}

func (c *webAuthnBackendTestConfig) GetServer() *config.ServerSection {
	return &config.ServerSection{
		Redis: config.Redis{
			Prefix:      c.prefix,
			PosCacheTTL: c.ttl,
		},
	}
}

type mockWebAuthnProvider struct {
	credentials []mfa.PersistentCredential
	err         error
}

func (m *mockWebAuthnProvider) GetWebAuthnCredentials() ([]mfa.PersistentCredential, error) {
	return m.credentials, m.err
}

const (
	backendDataPoolName                = "baseline_idp_backend_data"
	backendDataUsername                = "baseline@example.test"
	backendDataDisplayName             = "Baseline User"
	backendDataUniqueUserID            = "baseline-uid-1"
	backendDataTOTPSecret              = "JBSWY3DPEHPK3PXP"
	backendDataCredentialName          = "Baseline Security Key"
	backendDataDN                      = "uid=baseline,ou=users,dc=example,dc=test"
	backendDataAttrUID                 = "uid"
	backendDataAttrDisplayName         = "displayName"
	backendDataAttrUniqueUserID        = "entryUUID"
	backendDataAttrTOTPSecret          = "nauthilusTotpSecret"
	backendDataAttrRecoveryCode        = "nauthilusRecoveryCode"
	backendDataAttrWebAuthnCredential  = "nauthilusFido2Credential"
	backendDataAttrWebAuthnObjectClass = "nauthilusFido2Account"
	remoteBackendDataAuthority         = "edge-authority"
	remoteBackendDataAuthorityBackend  = "authority-ldap"
	remoteBackendDataAttributeMail     = "mail"
	remoteBackendDataBackendRef        = "remote-backend-ref"
	backendDataPluginResponseHeader    = "X-Nauthilus-Lookup-Response"
)

func TestGetUserBackendDataCapturesIdentityAndMFAState(t *testing.T) {
	gin.SetMode(gin.TestMode)

	fixture := newBackendDataLDAPFixture(t)
	credential := newBackendDataTestCredential()

	fixture.expectBackendDataRequestFlow(t, credential)
	ldapDone := fixture.replyToBackendDataSearches(t, credential)

	handler := newBackendDataFrontendHandler(fixture.backendDataBaseFixture)
	data, statusCode := runGetUserBackendDataRequest(t, handler)

	assert.Equal(t, http.StatusOK, statusCode)
	assertBaselineBackendData(t, data, credential)

	assert.NoError(t, fixture.mock.ExpectationsWereMet())
	assert.NoError(t, fixture.waitLDAPDone(ldapDone))
}

func TestGetUserBackendDataUsesRemoteAuthorityMFAStateWithoutLocalBackends(t *testing.T) {
	gin.SetMode(gin.TestMode)

	fixture := newBackendDataRemoteFixture(t)
	credential := newBackendDataTestCredential()
	client := newRemoteBackendDataAuthorityClient(credential)

	cleanup := remote.SetAuthorityClientForTest(remoteBackendDataAuthority, client)
	defer cleanup()

	fixture.expectAccountMapping(backendDataUsername, definitions.ProtoIDP, backendDataUsername)
	fixture.expectAccountMapping(backendDataUsername, definitions.ProtoIDP, backendDataUsername)
	fixture.expectSavedWebAuthnCache(t, &backend.User{
		ID:          backendDataUniqueUserID,
		Name:        backendDataUsername,
		DisplayName: backendDataDisplayName,
		Credentials: []mfa.PersistentCredential{credential},
	})

	handler := newBackendDataFrontendHandler(fixture.backendDataBaseFixture)
	data, statusCode := runGetUserBackendDataRequest(t, handler)

	assert.Equal(t, http.StatusOK, statusCode)
	assertBaselineBackendData(t, data, credential)
	assert.Equal(t, remoteBackendDataBackendRef, data.AuthState.Runtime.RemoteBackendRef.OpaqueToken)
	assert.Len(t, client.resolveUserRequests, 1)
	assert.Len(t, client.mfaStateRequests, 1)
	assert.Equal(t, backendDataUsername, client.resolveUserRequests[0].GetUsername())
	assert.Equal(t, backendDataUsername, client.mfaStateRequests[0].GetUsername())
	assert.True(t, client.mfaStateRequests[0].GetIncludeWebauthnCredentials())
	assert.Empty(t, client.lookupIdentityRequests)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

func TestGetUserBackendDataPurgesStaleWebAuthnCacheWhenAuthorityHasNoCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)

	fixture := newBackendDataRemoteFixture(t)
	client := newRemoteBackendDataAuthorityClient()
	client.mfaStateResponse.Mfa.HasWebauthn = false
	client.mfaStateResponse.Mfa.WebauthnCredentials = nil

	cleanup := remote.SetAuthorityClientForTest(remoteBackendDataAuthority, client)
	defer cleanup()

	redisKey := fixture.cfg.GetServer().GetRedis().GetPrefix() + "webauthn:user:" + backendDataUniqueUserID
	fixture.expectAccountMapping(backendDataUsername, definitions.ProtoIDP, backendDataUsername)
	fixture.expectAccountMapping(backendDataUsername, definitions.ProtoIDP, backendDataUsername)
	fixture.mock.ExpectDel(redisKey).SetVal(1)

	handler := newBackendDataFrontendHandler(fixture.backendDataBaseFixture)
	data, statusCode := runGetUserBackendDataRequest(t, handler)

	assert.Equal(t, http.StatusOK, statusCode)

	if assert.NotNil(t, data) {
		assert.False(t, data.HaveWebAuthn)
		assert.Nil(t, data.WebAuthnUser)
		assert.True(t, data.HaveTOTP)
		assert.Equal(t, 3, data.NumRecoveryCodes)
	}

	assert.Len(t, client.mfaStateRequests, 1)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

func TestPurgeCachedAuthenticationForUserIgnoresConsumedStructuredBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	fixture := newBackendDataRemoteFixture(t)
	handler := newBackendDataFrontendHandler(fixture.backendDataBaseFixture)

	router := gin.New()
	router.POST("/login/webauthn/finish", func(ctx *gin.Context) {
		ctx.Set(definitions.CtxGUIDKey, "baseline-backend-data-guid")
		ctx.Set(definitions.CtxServiceKey, definitions.ServIDP)
		ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())

		handler.purgeCachedAuthenticationForUser(ctx, backendDataUsername)

		ctx.Status(http.StatusNoContent)
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login/webauthn/finish", strings.NewReader(""))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "127.0.0.1:12345"
	router.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusNoContent, recorder.Code)
	assert.Empty(t, recorder.Body.String())
}

func TestHasWebAuthnIgnoresConsumedStructuredBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	fixture := newBackendDataRemoteFixture(t)
	handler := newBackendDataFrontendHandler(fixture.backendDataBaseFixture)

	router := gin.New()
	router.POST("/login/webauthn/finish", func(ctx *gin.Context) {
		ctx.Set(definitions.CtxGUIDKey, "baseline-backend-data-guid")
		ctx.Set(definitions.CtxServiceKey, definitions.ServIDP)
		ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())

		ok := handler.hasWebAuthn(ctx, &backend.User{
			ID:   backendDataUniqueUserID,
			Name: backendDataUsername,
		}, definitions.ProtoIDP)

		assert.False(t, ok)
		ctx.Status(http.StatusNoContent)
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login/webauthn/finish", strings.NewReader(""))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "127.0.0.1:12345"
	router.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusNoContent, recorder.Code)
	assert.Empty(t, recorder.Body.String())
}

func TestBackendDataLookupContextDoesNotExposePluginResponseBoundary(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(
		http.MethodPost,
		"/login/webauthn/finish",
		strings.NewReader(`{"id":"credential"}`),
	)
	ctx.Request.Header.Set("Content-Type", "application/json")

	lookupCtx := backendDataLookupContext(ctx)
	assert.NotSame(t, ctx, lookupCtx)

	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	authState := core.NewAuthStateFromContextWithDeps(lookupCtx, core.AuthDeps{Cfg: cfg}).(*core.AuthState)
	authState.Request.Service = definitions.ServIDP

	assert.NotPanics(t, func() {
		authState.ApplyPluginResponseMutation(lookupCtx, pluginapi.ResponseMutation{
			Headers: pluginapi.ResponseHeaderMutation{
				Set: map[string][]string{backendDataPluginResponseHeader: {"must-not-escape"}},
			},
		})
	})
	assert.Empty(t, recorder.Header().Get(backendDataPluginResponseHeader))
}

func newBackendDataTestCredential() mfa.PersistentCredential {
	return mfa.PersistentCredential{
		Credential: webauthn.Credential{
			ID: []byte("baseline-credential-id"),
			Authenticator: webauthn.Authenticator{
				SignCount: 7,
			},
		},
		Name: backendDataCredentialName,
	}
}

func newBackendDataFrontendHandler(fixture *backendDataBaseFixture) *FrontendHandler {
	return &FrontendHandler{
		deps: &deps.Deps{
			Cfg:          fixture.cfg,
			Env:          config.NewTestEnvironmentConfig(),
			Logger:       slog.Default(),
			Redis:        fixture.redis,
			AccountCache: accountcache.NewManager(fixture.cfg),
		},
	}
}

func runGetUserBackendDataRequest(t *testing.T, handler *FrontendHandler) (*UserBackendData, int) {
	t.Helper()

	var data *UserBackendData

	router := gin.New()
	router.GET("/test", func(ctx *gin.Context) {
		ctx.Set(definitions.CtxGUIDKey, "baseline-backend-data-guid")
		ctx.Set(definitions.CtxServiceKey, definitions.ServIDP)
		ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())
		ctx.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: map[string]any{
			definitions.SessionKeyAccount: backendDataUsername,
		}})

		result, err := handler.GetUserBackendData(ctx)
		if err != nil {
			t.Fatalf("GetUserBackendData returned error: %v", err)
		}

		data = result

		ctx.Status(http.StatusOK)
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/test", nil)
	request.RemoteAddr = "127.0.0.1:12345"
	router.ServeHTTP(recorder, request)

	return data, recorder.Code
}

func assertBaselineBackendData(t *testing.T, data *UserBackendData, credential mfa.PersistentCredential) {
	t.Helper()

	if !assert.NotNil(t, data) {
		return
	}

	assert.Equal(t, backendDataUsername, data.Username)
	assert.Equal(t, backendDataDisplayName, data.DisplayName)
	assert.Equal(t, backendDataUniqueUserID, data.UniqueUserID)
	assert.True(t, data.HaveTOTP)
	assert.Equal(t, 3, data.NumRecoveryCodes)
	assert.True(t, data.HaveWebAuthn)
	assertBaselineWebAuthnUser(t, data.WebAuthnUser, credential)
}

func assertBaselineWebAuthnUser(t *testing.T, user *backend.User, credential mfa.PersistentCredential) {
	t.Helper()

	if !assert.NotNil(t, user) {
		return
	}

	assert.Equal(t, backendDataUsername, user.Name)
	assert.Equal(t, backendDataDisplayName, user.DisplayName)
	assert.Len(t, user.Credentials, 1)
	assert.Equal(t, credential.Authenticator.SignCount, user.Credentials[0].Authenticator.SignCount)
	assert.Equal(t, credential.Name, user.Credentials[0].Name)
}

func TestResolveWebAuthnUserFallbacksToBackend(t *testing.T) {
	gin.SetMode(gin.TestMode)

	fixture := newWebAuthnFallbackFixture(t)
	fixture.expectBackendFallbackCacheRefresh(t)

	data, statusCode := fixture.runResolveWebAuthnUser(t)

	assert.Equal(t, http.StatusOK, statusCode)

	if assert.NotNil(t, data) {
		assert.Equal(t, fixture.uniqueUserID, data.UniqueUserID)
		assert.True(t, data.HaveWebAuthn)
		assert.NotNil(t, data.WebAuthnUser)
		assert.Len(t, data.WebAuthnUser.Credentials, 1)
	}

	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

func TestHasWebAuthnWithProviderFallbacksToBackend(t *testing.T) {
	gin.SetMode(gin.TestMode)

	fixture := newWebAuthnFallbackFixture(t)
	fixture.expectBackendFallbackCacheRefresh(t)

	statusCode := fixture.runHasWebAuthnWithProvider(t)

	assert.Equal(t, http.StatusOK, statusCode)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

type webAuthnFallbackFixture struct {
	cfg          *webAuthnBackendTestConfig
	redis        rediscli.Client
	mock         redismock.ClientMock
	handler      *FrontendHandler
	provider     *mockWebAuthnProvider
	uniqueUserID string
	redisKey     string
}

// newWebAuthnFallbackFixture creates shared Redis and provider state for fallback tests.
func newWebAuthnFallbackFixture(t *testing.T) *webAuthnFallbackFixture {
	t.Helper()

	cfg := &webAuthnBackendTestConfig{
		prefix: "test:",
		ttl:    time.Minute,
	}

	db, mockRedis := redismock.NewClientMock()
	if db == nil || mockRedis == nil {
		t.Fatalf("failed to create Redis mock client")
	}

	redisClient := rediscli.NewTestClient(db)
	uniqueUserID := "uid-123"

	fixture := &webAuthnFallbackFixture{
		cfg:          cfg,
		redis:        redisClient,
		mock:         mockRedis,
		uniqueUserID: uniqueUserID,
		redisKey:     cfg.GetServer().GetRedis().GetPrefix() + "webauthn:user:" + uniqueUserID,
		provider:     newWebAuthnFallbackProvider(),
	}
	fixture.handler = newWebAuthnFallbackHandler(cfg, redisClient)

	return fixture
}

// newWebAuthnFallbackProvider returns a provider with one backend credential.
func newWebAuthnFallbackProvider() *mockWebAuthnProvider {
	return &mockWebAuthnProvider{
		credentials: []mfa.PersistentCredential{
			{
				Credential: webauthn.Credential{ID: []byte("cred-1")},
				Name:       "Test Key",
			},
		},
	}
}

// newWebAuthnFallbackHandler creates the frontend handler used by fallback tests.
func newWebAuthnFallbackHandler(cfg *webAuthnBackendTestConfig, redisClient rediscli.Client) *FrontendHandler {
	return &FrontendHandler{
		deps: &deps.Deps{
			Cfg:    cfg,
			Logger: slog.Default(),
			Redis:  redisClient,
		},
	}
}

// expectBackendFallbackCacheRefresh registers Redis expectations for backend fallback caching.
func (f *webAuthnFallbackFixture) expectBackendFallbackCacheRefresh(t *testing.T) {
	t.Helper()

	f.mock.ExpectHGetAll(f.redisKey).SetVal(map[string]string{})
	f.mock.ExpectHSet(f.redisKey, f.expectedCachedWebAuthnUser(t)).SetVal(4)
	f.mock.ExpectExpire(f.redisKey, f.cfg.GetServer().GetRedis().GetPosCacheTTL()).SetVal(true)
}

// expectedCachedWebAuthnUser returns the Redis hash expected after fallback resolution.
func (f *webAuthnFallbackFixture) expectedCachedWebAuthnUser(t *testing.T) map[string]any {
	t.Helper()

	return map[string]any{
		"id":           f.uniqueUserID,
		"name":         "test1",
		"display_name": "Test User",
		"credentials":  f.encryptedCredentialsValue(t),
	}
}

// encryptedCredentialsValue returns the serialized credential payload expected in Redis.
func (f *webAuthnFallbackFixture) encryptedCredentialsValue(t *testing.T) string {
	t.Helper()

	credentialsJSON, err := jsoniter.ConfigFastest.Marshal(f.provider.credentials)
	if err != nil {
		t.Fatalf("failed to marshal credentials: %v", err)
	}

	credentialsValue := string(credentialsJSON)
	if encrypted, err := f.redis.GetSecurityManager().Encrypt(credentialsValue); err == nil {
		return encrypted
	}

	return credentialsValue
}

// runResolveWebAuthnUser executes resolveWebAuthnUser through a Gin route.
func (f *webAuthnFallbackFixture) runResolveWebAuthnUser(t *testing.T) (*UserBackendData, int) {
	t.Helper()

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyUniqueUserID: f.uniqueUserID,
	}}
	data := &UserBackendData{
		Username:    "test1",
		DisplayName: "Test User",
	}

	statusCode := runWebAuthnFallbackRoute(func(c *gin.Context) {
		f.handler.resolveWebAuthnUser(c, mgr, data, f.provider)
	})

	return data, statusCode
}

// runHasWebAuthnWithProvider executes hasWebAuthnWithProvider through a Gin route.
func (f *webAuthnFallbackFixture) runHasWebAuthnWithProvider(t *testing.T) int {
	t.Helper()

	user := &backend.User{ID: f.uniqueUserID, Name: "test1", DisplayName: "Test User"}

	return runWebAuthnFallbackRoute(func(c *gin.Context) {
		assert.True(t, f.handler.hasWebAuthnWithProvider(c, user, "", f.provider))
	})
}

// runWebAuthnFallbackRoute executes a single fallback assertion route.
func runWebAuthnFallbackRoute(run func(*gin.Context)) int {
	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		run(c)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	return w.Code
}

type backendDataBaseFixture struct {
	cfg   *config.FileSettings
	redis rediscli.Client
	mock  redismock.ClientMock
}

type backendDataLDAPFixture struct {
	*backendDataBaseFixture
	securityManager *security.Manager
	poolName        string
}

type backendDataRemoteFixture struct {
	*backendDataBaseFixture
}

func newBackendDataLDAPFixture(t *testing.T) *backendDataLDAPFixture {
	t.Helper()

	encryptionSecret := secret.New("testsecret12345678")
	cfg := newBackendDataLDAPConfig(t, encryptionSecret)
	env := config.NewTestEnvironmentConfig()
	configureBackendDataGlobals(cfg, env)

	db, mock := redismock.NewClientMock()

	priorityqueue.LDAPQueue.AddPoolName(backendDataPoolName)

	return &backendDataLDAPFixture{
		backendDataBaseFixture: &backendDataBaseFixture{
			cfg:   cfg,
			redis: rediscli.NewTestClient(db),
			mock:  mock,
		},
		securityManager: security.NewManager(encryptionSecret),
		poolName:        backendDataPoolName,
	}
}

func newBackendDataRemoteFixture(t *testing.T) *backendDataRemoteFixture {
	t.Helper()

	cfg := newBackendDataRemoteConfig(t)
	env := config.NewTestEnvironmentConfig()
	configureBackendDataGlobals(cfg, env)

	db, mock := redismock.NewClientMock()

	return &backendDataRemoteFixture{
		backendDataBaseFixture: &backendDataBaseFixture{
			cfg:   cfg,
			redis: rediscli.NewTestClient(db),
			mock:  mock,
		},
	}
}

func newBackendDataLDAPConfig(t *testing.T, encryptionSecret secret.Value) *config.FileSettings {
	t.Helper()

	backendCfg := newBackendDataBackend(t)

	return &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				Prefix:      "baseline:",
				PosCacheTTL: time.Minute,
			},
			Timeouts: config.Timeouts{
				LDAPSearch: time.Second,
				LDAPModify: time.Second,
				RedisRead:  time.Second,
				RedisWrite: time.Second,
			},
			Backends: []*config.Backend{backendCfg},
		},
		LDAP: &config.LDAPSection{
			Config: &config.LDAPConf{
				EncryptionSecret: encryptionSecret,
			},
			Search: []config.LDAPSearchProtocol{
				newBackendDataLDAPSearch(),
			},
		},
	}
}

func newBackendDataRemoteConfig(t *testing.T) *config.FileSettings {
	t.Helper()

	backendCfg := &config.Backend{}
	if err := backendCfg.Set(definitions.BackendRemoteName); err != nil {
		t.Fatalf("backend.Set failed: %v", err)
	}

	return &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				Prefix:      "remote:",
				PosCacheTTL: time.Minute,
			},
			Timeouts: config.Timeouts{
				RedisRead:  time.Second,
				RedisWrite: time.Second,
			},
			Backends: []*config.Backend{backendCfg},
		},
		Runtime: &config.RuntimeSection{
			Clients: config.RuntimeClientsSection{
				GRPC: config.RuntimeGRPCClientsSection{
					NauthilusAuthorities: map[string]*config.NauthilusAuthorityClientSection{
						remoteBackendDataAuthority: {
							Address: "bufconn",
							Timeout: time.Second,
						},
					},
				},
			},
		},
		Auth: &config.AuthSection{
			Backends: config.AuthBackendsSection{
				Remote: map[string]*config.RemoteBackendSection{
					config.RemoteBackendDefaultName: {
						Authority: remoteBackendDataAuthority,
						Mode:      config.RemoteBackendModeNauthilus,
						AllowedOperations: []string{
							config.RemoteBackendOperationLookupIdentity,
							config.RemoteBackendOperationAttributeRead,
							config.RemoteBackendOperationMFARead,
							config.RemoteBackendOperationWebAuthnRead,
						},
						Timeout: time.Second,
					},
				},
			},
		},
	}
}

func newBackendDataBackend(t *testing.T) *config.Backend {
	t.Helper()

	backendCfg := &config.Backend{}

	if err := backendCfg.Set("ldap(" + backendDataPoolName + ")"); err != nil {
		t.Fatalf("backend.Set failed: %v", err)
	}

	return backendCfg
}

func newBackendDataLDAPSearch() config.LDAPSearchProtocol {
	return config.LDAPSearchProtocol{
		Protocols: []string{definitions.ProtoIDP},
		CacheName: "idp",
		PoolName:  backendDataPoolName,
		BaseDN:    "ou=users,dc=example,dc=test",
		LDAPFilter: config.LDAPFilter{
			User: "(uid={{.Username}})",
		},
		LDAPAttributeMapping: config.LDAPAttributeMapping{
			AccountField:            backendDataAttrUID,
			DisplayNameField:        backendDataAttrDisplayName,
			UniqueUserIDField:       backendDataAttrUniqueUserID,
			TOTPSecretField:         backendDataAttrTOTPSecret,
			TOTPRecoveryField:       backendDataAttrRecoveryCode,
			WebAuthnCredentialField: backendDataAttrWebAuthnCredential,
			WebAuthnObjectClass:     backendDataAttrWebAuthnObjectClass,
		},
		Attributes: []string{
			backendDataAttrUID,
			backendDataAttrDisplayName,
			backendDataAttrUniqueUserID,
			backendDataAttrTOTPSecret,
			backendDataAttrRecoveryCode,
		},
	}
}

func configureBackendDataGlobals(cfg *config.FileSettings, env config.Environment) {
	config.SetTestEnvironmentConfig(env)
	config.SetTestFile(cfg)
	core.InitPassDBResultPool()
	core.SetDefaultConfigFile(cfg)
	core.SetDefaultLogger(slog.Default())
	util.SetDefaultConfigFile(cfg)
	util.SetDefaultLogger(slog.Default())
	util.SetDefaultEnvironment(env)
}

func (f *backendDataLDAPFixture) encrypt(t *testing.T, value string) string {
	t.Helper()

	encrypted, err := f.securityManager.Encrypt(value)
	if err != nil {
		t.Fatalf("failed to encrypt %q: %v", value, err)
	}

	return encrypted
}

func (f *backendDataBaseFixture) expectAccountMapping(username, protocol, account string) {
	key := rediscli.GetUserHashKey(f.cfg.GetServer().GetRedis().GetPrefix(), username)
	field := accountcache.GetAccountMappingField(username, protocol, "")

	f.mock.ExpectHGet(key, field).RedisNil()
	f.mock.ExpectHSet(key, field, account).SetVal(1)
}

func (f *backendDataLDAPFixture) expectAccountMapping(username, protocol, account string) {
	f.backendDataBaseFixture.expectAccountMapping(username, protocol, account)
}

func (f *backendDataLDAPFixture) expectEmptyWebAuthnCache(uniqueUserID string) {
	key := f.cfg.GetServer().GetRedis().GetPrefix() + "webauthn:user:" + uniqueUserID

	f.mock.ExpectHGetAll(key).SetVal(map[string]string{})
}

func (f *backendDataBaseFixture) expectSavedWebAuthnCache(t *testing.T, user *backend.User) {
	t.Helper()

	credentialsJSON, err := jsoniter.ConfigFastest.Marshal(user.Credentials)
	if err != nil {
		t.Fatalf("failed to marshal credentials: %v", err)
	}

	credentialsValue := string(credentialsJSON)
	if encrypted, err := f.redis.GetSecurityManager().Encrypt(credentialsValue); err == nil {
		credentialsValue = encrypted
	}

	key := f.cfg.GetServer().GetRedis().GetPrefix() + "webauthn:user:" + user.ID
	f.mock.ExpectHSet(key, map[string]any{
		"id":           user.ID,
		"name":         user.Name,
		"display_name": user.DisplayName,
		"credentials":  credentialsValue,
	}).SetVal(4)
	f.mock.ExpectExpire(key, f.cfg.GetServer().GetRedis().GetPosCacheTTL()).SetVal(true)
}

func (f *backendDataLDAPFixture) expectSavedWebAuthnCache(t *testing.T, user *backend.User) {
	f.backendDataBaseFixture.expectSavedWebAuthnCache(t, user)
}

func (f *backendDataLDAPFixture) expectBackendDataRequestFlow(t *testing.T, credential mfa.PersistentCredential) {
	t.Helper()

	f.expectAccountMapping(backendDataUsername, definitions.ProtoIDP, backendDataUsername)
	f.expectAccountMapping(backendDataUsername, definitions.ProtoIDP, backendDataUsername)
	f.expectEmptyWebAuthnCache(backendDataUniqueUserID)
	f.expectSavedWebAuthnCache(t, &backend.User{
		ID:          backendDataUniqueUserID,
		Name:        backendDataUsername,
		DisplayName: backendDataDisplayName,
		Credentials: []mfa.PersistentCredential{credential},
	})
}

func (f *backendDataLDAPFixture) replyToBackendDataSearches(
	t *testing.T,
	credential mfa.PersistentCredential,
) <-chan error {
	t.Helper()

	credentialJSON, err := jsoniter.ConfigFastest.Marshal(credential)
	if err != nil {
		t.Fatalf("failed to marshal WebAuthn credential: %v", err)
	}

	return f.replyToLDAPSearches(
		f.backendIdentityReply(t),
		bktype.AttributeMapping{
			backendDataAttrWebAuthnCredential: {string(credentialJSON)},
		},
	)
}

func (f *backendDataLDAPFixture) backendIdentityReply(t *testing.T) bktype.AttributeMapping {
	t.Helper()

	return bktype.AttributeMapping{
		definitions.DistinguishedName: {backendDataDN},
		backendDataAttrUID:            {backendDataUsername},
		backendDataAttrDisplayName:    {backendDataDisplayName},
		backendDataAttrUniqueUserID:   {backendDataUniqueUserID},
		backendDataAttrTOTPSecret:     {f.encrypt(t, backendDataTOTPSecret)},
		backendDataAttrRecoveryCode: {
			f.encrypt(t, "recovery-1"),
			f.encrypt(t, "recovery-2"),
			f.encrypt(t, "recovery-3"),
		},
	}
}

func (f *backendDataLDAPFixture) replyToLDAPSearches(replies ...bktype.AttributeMapping) <-chan error {
	done := make(chan error, 1)

	go func() {
		for _, reply := range replies {
			request := priorityqueue.LDAPQueue.Pop(f.poolName)
			if request == nil {
				done <- nil

				return
			}

			request.LDAPReplyChan <- &bktype.LDAPReply{Result: reply}
		}

		done <- nil
	}()

	return done
}

func (f *backendDataLDAPFixture) waitLDAPDone(done <-chan error) error {
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		return assert.AnError
	}
}

type remoteBackendDataAuthorityClient struct {
	resolveUserResponse     *identityv1.UserSnapshotResponse
	mfaStateResponse        *identityv1.MFAStateResponse
	resolveUserRequests     []*identityv1.ResolveUserRequest
	mfaStateRequests        []*identityv1.GetMFAStateRequest
	lookupIdentityRequests  []*authv1.LookupIdentityRequest
	authenticateRequests    []*authv1.AuthRequest
	listAccountsRequests    []*authv1.ListAccountsRequest
	webAuthnCredentialReads []*identityv1.GetWebAuthnCredentialsRequest
}

func newRemoteBackendDataAuthorityClient(credentials ...mfa.PersistentCredential) *remoteBackendDataAuthorityClient {
	protoCredentials := make([]*identityv1.WebAuthnCredential, 0, len(credentials))
	for index := range credentials {
		protoCredentials = append(protoCredentials, identityv1.PersistentCredentialToProto(&credentials[index]))
	}

	return &remoteBackendDataAuthorityClient{
		resolveUserResponse: &identityv1.UserSnapshotResponse{
			Status: &commonv1.OperationStatus{Result: commonv1.OperationResult_OPERATION_RESULT_OK},
			User: &identityv1.UserSnapshot{
				Username:     backendDataUsername,
				Account:      backendDataUsername,
				UniqueUserId: backendDataUniqueUserID,
				DisplayName:  backendDataDisplayName,
				Attributes: map[string]*commonv1.AttributeValues{
					remoteBackendDataAttributeMail: {Values: []string{backendDataUsername}},
				},
				Groups:   []string{"idp-users"},
				GroupDns: []string{"cn=idp-users,ou=groups,dc=example,dc=test"},
				Backend: &commonv1.BackendRef{
					Type:        definitions.BackendLDAPName,
					Name:        remoteBackendDataAuthorityBackend,
					Protocol:    definitions.ProtoIDP,
					Authority:   remoteBackendDataAuthority,
					OpaqueToken: remoteBackendDataBackendRef,
				},
			},
		},
		mfaStateResponse: &identityv1.MFAStateResponse{
			Status: &commonv1.OperationStatus{Result: commonv1.OperationResult_OPERATION_RESULT_OK},
			Mfa: &identityv1.MFAState{
				HasTotp:             true,
				RecoveryCodeCount:   3,
				HasWebauthn:         len(protoCredentials) > 0,
				WebauthnCredentials: protoCredentials,
			},
			Backend: &commonv1.BackendRef{
				Type:        definitions.BackendLDAPName,
				Name:        remoteBackendDataAuthorityBackend,
				Protocol:    definitions.ProtoIDP,
				Authority:   remoteBackendDataAuthority,
				OpaqueToken: remoteBackendDataBackendRef,
			},
		},
	}
}

func (c *remoteBackendDataAuthorityClient) Authenticate(
	_ context.Context,
	request *authv1.AuthRequest,
) (*authv1.AuthResponse, error) {
	c.authenticateRequests = append(c.authenticateRequests, request)

	return nil, errors.New("unexpected Authenticate call")
}

func (c *remoteBackendDataAuthorityClient) LookupIdentity(
	_ context.Context,
	request *authv1.LookupIdentityRequest,
) (*authv1.AuthResponse, error) {
	c.lookupIdentityRequests = append(c.lookupIdentityRequests, request)

	return nil, errors.New("unexpected LookupIdentity call")
}

func (c *remoteBackendDataAuthorityClient) ListAccounts(
	_ context.Context,
	request *authv1.ListAccountsRequest,
) (*authv1.ListAccountsResponse, error) {
	c.listAccountsRequests = append(c.listAccountsRequests, request)

	return nil, errors.New("unexpected ListAccounts call")
}

func (c *remoteBackendDataAuthorityClient) ResolveUser(
	_ context.Context,
	request *identityv1.ResolveUserRequest,
) (*identityv1.UserSnapshotResponse, error) {
	c.resolveUserRequests = append(c.resolveUserRequests, request)

	return c.resolveUserResponse, nil
}

func (c *remoteBackendDataAuthorityClient) GetMFAState(
	_ context.Context,
	request *identityv1.GetMFAStateRequest,
) (*identityv1.MFAStateResponse, error) {
	c.mfaStateRequests = append(c.mfaStateRequests, request)

	return c.mfaStateResponse, nil
}

func (c *remoteBackendDataAuthorityClient) BeginTOTPRegistration(
	_ context.Context,
	_ *identityv1.BeginTOTPRegistrationRequest,
) (*identityv1.BeginTOTPRegistrationResponse, error) {
	return nil, errors.New("unexpected BeginTOTPRegistration call")
}

func (c *remoteBackendDataAuthorityClient) FinishTOTPRegistration(
	_ context.Context,
	_ *identityv1.FinishTOTPRegistrationRequest,
) (*identityv1.MFAWriteResponse, error) {
	return nil, errors.New("unexpected FinishTOTPRegistration call")
}

func (c *remoteBackendDataAuthorityClient) VerifyTOTP(
	_ context.Context,
	_ *identityv1.VerifyTOTPRequest,
) (*identityv1.VerifyTOTPResponse, error) {
	return nil, errors.New("unexpected VerifyTOTP call")
}

func (c *remoteBackendDataAuthorityClient) DeleteTOTP(
	_ context.Context,
	_ *identityv1.DeleteTOTPRequest,
) (*identityv1.MFAWriteResponse, error) {
	return nil, errors.New("unexpected DeleteTOTP call")
}

func (c *remoteBackendDataAuthorityClient) GenerateRecoveryCodes(
	_ context.Context,
	_ *identityv1.GenerateRecoveryCodesRequest,
) (*identityv1.GenerateRecoveryCodesResponse, error) {
	return nil, errors.New("unexpected GenerateRecoveryCodes call")
}

func (c *remoteBackendDataAuthorityClient) UseRecoveryCode(
	_ context.Context,
	_ *identityv1.UseRecoveryCodeRequest,
) (*identityv1.UseRecoveryCodeResponse, error) {
	return nil, errors.New("unexpected UseRecoveryCode call")
}

func (c *remoteBackendDataAuthorityClient) DeleteRecoveryCodes(
	_ context.Context,
	_ *identityv1.DeleteRecoveryCodesRequest,
) (*identityv1.MFAWriteResponse, error) {
	return nil, errors.New("unexpected DeleteRecoveryCodes call")
}

func (c *remoteBackendDataAuthorityClient) GetWebAuthnCredentials(
	_ context.Context,
	request *identityv1.GetWebAuthnCredentialsRequest,
) (*identityv1.WebAuthnCredentialsResponse, error) {
	c.webAuthnCredentialReads = append(c.webAuthnCredentialReads, request)

	return &identityv1.WebAuthnCredentialsResponse{
		Status:      c.mfaStateResponse.GetStatus(),
		Credentials: c.mfaStateResponse.GetMfa().GetWebauthnCredentials(),
		Backend:     c.mfaStateResponse.GetBackend(),
	}, nil
}

func (c *remoteBackendDataAuthorityClient) SaveWebAuthnCredential(
	_ context.Context,
	_ *identityv1.SaveWebAuthnCredentialRequest,
) (*identityv1.MFAWriteResponse, error) {
	return nil, errors.New("unexpected SaveWebAuthnCredential call")
}

func (c *remoteBackendDataAuthorityClient) UpdateWebAuthnCredential(
	_ context.Context,
	_ *identityv1.UpdateWebAuthnCredentialRequest,
) (*identityv1.MFAWriteResponse, error) {
	return nil, errors.New("unexpected UpdateWebAuthnCredential call")
}

func (c *remoteBackendDataAuthorityClient) DeleteWebAuthnCredential(
	_ context.Context,
	_ *identityv1.DeleteWebAuthnCredentialRequest,
) (*identityv1.MFAWriteResponse, error) {
	return nil, errors.New("unexpected DeleteWebAuthnCredential call")
}
