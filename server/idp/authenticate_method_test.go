package idp

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	coreauth "github.com/croessner/nauthilus/v3/server/core/auth"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/backend/accountcache"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
)

type capturePasswordVerifier struct {
	method          string
	protocolContext *core.IDPRequestContext
}

type delayedFailurePasswordVerifier struct {
	passwordCalls int
	lookupCalls   int
}

func delayedPasswordIdentityLoader(
	t *testing.T,
	verifier *delayedFailurePasswordVerifier,
) passwordIdentityLoader {
	t.Helper()

	return func(
		_ *gin.Context,
		username string,
		oidcCID string,
		samlEntityID string,
		protocolContext core.IDPRequestContext,
	) (PasswordAuthentication, error) {
		verifier.lookupCalls++

		if username != "alice" || oidcCID != "client1" || samlEntityID != "" ||
			protocolContext.GrantType != "authorization_code" {
			t.Fatalf(
				"delayed lookup binding = %q/%q/%q/%#v",
				username, oidcCID, samlEntityID, protocolContext,
			)
		}

		return PasswordAuthentication{
			User: backend.NewUser("alice", "Alice Example", "identity-42"),
			BackendRef: core.RemoteBackendRef{
				Type: "remote", Name: "authority", Protocol: definitions.ProtoOIDC,
				Authority: "authority-a", OpaqueToken: "delayed-lookup-capability",
			},
		}, nil
	}
}

func assertEligibleDelayedPasswordFailure(
	t *testing.T,
	result PasswordAuthentication,
	err error,
	verifier *delayedFailurePasswordVerifier,
) {
	t.Helper()

	var failure *AuthFailureError
	if !errors.As(err, &failure) || !failure.Status.DelayedResponseEligible {
		t.Fatalf("password failure = %#v, want delayed-response eligible", err)
	}

	if result.User == nil || result.User.ID != "identity-42" || result.User.Name != "alice" ||
		result.BackendRef.OpaqueToken != "delayed-lookup-capability" {
		t.Fatalf(
			"hydrated delayed failure = %#v; calls = %d/%d",
			result, verifier.passwordCalls, verifier.lookupCalls,
		)
	}

	if verifier.passwordCalls != 1 || verifier.lookupCalls != 1 {
		t.Fatalf("verifier calls = password:%d lookup:%d, want 1/1", verifier.passwordCalls, verifier.lookupCalls)
	}
}

func masterUserPasswordIdentityLoader(t *testing.T, lookupCalls *int) passwordIdentityLoader {
	t.Helper()

	return func(
		_ *gin.Context,
		username string,
		_ string,
		_ string,
		_ core.IDPRequestContext,
	) (PasswordAuthentication, error) {
		*lookupCalls++

		if username != "admin@example.test" {
			t.Fatalf("MFA identity lookup username = %q, want master account", username)
		}

		return PasswordAuthentication{
			User: backend.NewUser("admin@example.test", "Admin", "master-identity"),
			BackendRef: core.RemoteBackendRef{
				Type: "remote", Name: "authority", Protocol: definitions.ProtoOIDC,
				Authority: "authority-a", OpaqueToken: "master-capability",
			},
		}, nil
	}
}

func (v *delayedFailurePasswordVerifier) Verify(
	_ *gin.Context,
	auth *core.AuthState,
	_ []*core.PassDBMap,
) (*core.PassDBResult, error) {
	result := core.GetPassDBResultFromPool()
	result.Backend = definitions.BackendRemote
	result.BackendName = "remote"
	result.UserFound = true
	result.Account = "alice"
	result.AccountField = definitions.MetaUserAccount
	result.DisplayNameField = "Partial Alice"
	result.UniqueUserIDField = "partial-identity"

	if !auth.Request.NoAuth {
		v.passwordCalls++

		return result, nil
	}

	return result, nil
}

func (v *capturePasswordVerifier) Verify(_ *gin.Context, auth *core.AuthState, _ []*core.PassDBMap) (*core.PassDBResult, error) {
	v.method = auth.Request.Method
	if auth.Runtime.IDPContext != nil {
		protocolContext := *auth.Runtime.IDPContext
		protocolContext.RequestedScopes = append([]string(nil), auth.Runtime.IDPContext.RequestedScopes...)
		v.protocolContext = &protocolContext
	}

	result := core.GetPassDBResultFromPool()
	result.Authenticated = true
	result.UserFound = false
	result.Account = "user1"
	result.AccountField = definitions.MetaUserAccount
	result.DisplayNameField = "User One"
	result.UniqueUserIDField = "uid-1"
	result.Backend = definitions.BackendLDAP

	return result, nil
}

func TestNauthilusIDPAuthenticateWithBackendUsesTypedContextOverLegacyManager(t *testing.T) {
	gin.SetMode(gin.TestMode)

	verifier := &capturePasswordVerifier{}

	core.RegisterPasswordVerifier(verifier)
	defer core.RegisterPasswordVerifier(coreauth.DefaultPasswordVerifier{})

	db, _ := redismock.NewClientMock()
	cfg := &config.FileSettings{Server: &config.ServerSection{Redis: config.Redis{Prefix: "test:"}}}
	idp := NewNauthilusIDP(&deps.Deps{
		Cfg: cfg, Redis: rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg), Logger: slog.Default(),
	})

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("POST", "/login", nil)
	ctx.Request.RemoteAddr = "192.0.2.1:12345"
	setupMockContext(ctx, "typed-idp-context-guid", definitions.ServIDP)

	legacy := cookie.NewSecureManager([]byte("test-secret-32bytes-1234567890!!"), "legacy", cfg, config.NewTestEnvironmentConfig())
	legacy.Set(definitions.SessionKeyOIDCGrantType, "legacy-grant")
	legacy.Set(definitions.SessionKeyIDPRedirectURI, "https://legacy.example.test/callback")
	legacy.Set(definitions.SessionKeyIDPScope, "legacy")
	legacy.Set(definitions.SessionKeyMFACompleted, true)
	legacy.Set(definitions.SessionKeyMFAMethod, "legacy-method")
	ctx.Set(definitions.CtxSecureDataKey, legacy)

	typed := core.IDPRequestContext{
		GrantType: "authorization_code", RedirectURI: "https://client.example.test/callback",
		RequestedScopes: []string{"openid", "profile"},
	}
	_, _ = idp.AuthenticateWithBackend(ctx, "user1", "pass1", "client1", "", typed)

	if verifier.protocolContext == nil || verifier.protocolContext.GrantType != typed.GrantType ||
		verifier.protocolContext.RedirectURI != typed.RedirectURI ||
		len(verifier.protocolContext.RequestedScopes) != 2 ||
		verifier.protocolContext.RequestedScopes[0] != "openid" ||
		verifier.protocolContext.MFACompleted || verifier.protocolContext.MFAMethod != "" {
		t.Fatalf("password verifier protocol context = %#v, want %#v", verifier.protocolContext, typed)
	}

	if got := legacy.GetString(definitions.SessionKeyOIDCGrantType, ""); got != "legacy-grant" {
		t.Fatalf("legacy manager was mutated: grant type = %q", got)
	}
}

func TestNauthilusIDPAuthenticateWithBackendHydratesEligibleDelayedFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	verifier := &delayedFailurePasswordVerifier{}

	core.RegisterPasswordVerifier(verifier)
	defer core.RegisterPasswordVerifier(coreauth.DefaultPasswordVerifier{})

	db, mock := redismock.NewClientMock()
	mock.ExpectHGet("test:user:{47}", "alice|oidc|client1").RedisNil()

	cfg := &config.FileSettings{
		Server: &config.ServerSection{Redis: config.Redis{Prefix: "test:"}},
		IDP: &config.IDPSection{OIDC: config.OIDCConfig{Clients: []config.OIDCClient{{
			ClientID: "client1", Scopes: []string{"openid", "profile"}, DelayedResponse: true,
		}}}},
	}
	idp := NewNauthilusIDP(&deps.Deps{
		Cfg: cfg, Redis: rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg), Logger: slog.Default(),
	})
	idp.passwordIdentityLoader = delayedPasswordIdentityLoader(t, verifier)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("POST", "/login", nil)
	ctx.Request.RemoteAddr = "192.0.2.1:12345"
	setupMockContext(ctx, "delayed-failure-guid", definitions.ServIDP)

	result, err := idp.AuthenticateWithBackend(
		ctx,
		"alice",
		"wrong-password",
		"client1",
		"",
		core.IDPRequestContext{GrantType: "authorization_code", RequestedScopes: []string{"openid", "profile"}},
	)

	assertEligibleDelayedPasswordFailure(t, result, err, verifier)
}

func TestNauthilusIDPBindsMasterUserMFAIdentitySeparatelyFromTarget(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{Prefix: "test:"},
			MasterUser: config.MasterUser{
				Enabled: true, UserFormat: config.DefaultMasterUserFormat,
			},
		},
	}
	idp := &NauthilusIDP{deps: &deps.Deps{Cfg: cfg, Logger: slog.Default()}}
	lookupCalls := 0
	idp.passwordIdentityLoader = masterUserPasswordIdentityLoader(t, &lookupCalls)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodPost, "/login", nil)

	result, err := idp.bindPasswordMFAIdentity(
		ctx,
		"alice@example.test*admin@example.test",
		"client1",
		"",
		core.IDPRequestContext{GrantType: "authorization_code"},
		PasswordAuthentication{
			User: backend.NewUser("alice@example.test", "Alice", "target-identity"),
			BackendRef: core.RemoteBackendRef{
				Type: "remote", Name: "authority", Protocol: definitions.ProtoOIDC,
				Authority: "authority-a", OpaqueToken: "target-capability",
			},
		},
	)
	if err != nil {
		t.Fatalf("bind master-user MFA identity: %v", err)
	}

	if result.User == nil || result.User.Name != "alice@example.test" ||
		result.BackendRef.OpaqueToken != "target-capability" || result.MFAUser == nil ||
		result.MFAUser.Name != "admin@example.test" || result.MFAUser.ID != "master-identity" ||
		result.MFABackendRef.OpaqueToken != "master-capability" || lookupCalls != 1 {
		t.Fatalf("master-user password binding = %#v, lookup calls = %d", result, lookupCalls)
	}
}

func TestOrdinaryLocalizedPasswordFailureRemainsDelayedResponseEligible(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	auth := &core.AuthState{Runtime: core.AuthRuntime{
		StatusMessage:        definitions.PasswordFail,
		StatusMessageI18NKey: "auth.invalid_credentials",
		ResponseLanguage:     "en",
	}}

	err := (&NauthilusIDP{}).authFailureError(
		ctx, auth, errors.New("ordinary password failure"), true,
	)

	var failure *AuthFailureError
	if !errors.As(err, &failure) {
		t.Fatalf("password failure type = %T, want *AuthFailureError", err)
	}

	if !failure.Status.PolicyTerminal || !failure.Status.DelayedResponseEligible {
		t.Fatalf("localized password failure status = %#v, want terminal rendering and delayed eligibility", failure.Status)
	}
}

func TestNauthilusIDPAuthenticateSetsPasswordMethodForIDPLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	verifier := &capturePasswordVerifier{}

	core.RegisterPasswordVerifier(verifier)
	defer core.RegisterPasswordVerifier(coreauth.DefaultPasswordVerifier{})

	db, _ := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				Prefix: "test:",
			},
		},
	}

	d := &deps.Deps{
		Cfg:          cfg,
		Redis:        redisClient,
		AccountCache: accountcache.NewManager(cfg),
	}

	idp := NewNauthilusIDP(d)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("POST", "/login", nil)
	ctx.Request.RemoteAddr = "192.168.1.100:12345"

	setupMockContext(ctx, "test-idp-method-guid", definitions.ServIDP)

	_, _ = idp.AuthenticateWithBackend(
		ctx,
		"user1",
		"pass1",
		"client1",
		"",
		core.IDPRequestContext{},
	)

	if verifier.method != "password" {
		t.Fatalf("expected method to be %q, got %q", "password", verifier.method)
	}
}
