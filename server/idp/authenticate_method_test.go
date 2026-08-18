package idp

import (
	"net/http/httptest"
	"testing"

	coreauth "github.com/croessner/nauthilus/v3/server/core/auth"

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
		Cfg: cfg, Redis: rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
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
