package idp

import (
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/handler/deps"

	"github.com/gin-gonic/gin"
)

func TestNauthilusIDPAuthenticateWithBackendUsesTypedContextOverLegacyManager(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.FileSettings{Server: &config.ServerSection{}}
	application := &recordingIDPAuthApplication{authenticateResults: []applicationBoundaryResult{{
		outcome: &core.AuthOutcome{Decision: core.AuthDecisionFail},
	}}}
	d := &deps.Deps{Cfg: cfg, Env: config.NewTestEnvironmentConfig(), AuthApplication: application}
	idp := NewNauthilusIDP(d)

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

	if len(application.authenticateInputs) != 1 {
		t.Fatalf("application calls = %d, want 1", len(application.authenticateInputs))
	}

	input := application.authenticateInputs[0]
	if input.IDP.Request.GrantType != typed.GrantType ||
		input.IDP.Request.RedirectURI != typed.RedirectURI ||
		len(input.IDP.Request.RequestedScopes) != 2 ||
		input.IDP.Request.RequestedScopes[0] != "openid" {
		t.Fatalf("application protocol context = %#v, want %#v", input.IDP.Request, typed)
	}

	if got := legacy.GetString(definitions.SessionKeyOIDCGrantType, ""); got != "legacy-grant" {
		t.Fatalf("legacy manager was mutated: grant type = %q", got)
	}

	if input.Context.Protocol != definitions.ProtoOIDC {
		t.Fatalf("application protocol = %q, want %q", input.Context.Protocol, definitions.ProtoOIDC)
	}
}

func TestNauthilusIDPAuthenticateSetsPasswordMethodForIDPLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	application := &recordingIDPAuthApplication{authenticateResults: []applicationBoundaryResult{{
		outcome: &core.AuthOutcome{Decision: core.AuthDecisionFail},
	}}}
	d := &deps.Deps{
		Cfg: &config.FileSettings{Server: &config.ServerSection{}},
		Env: config.NewTestEnvironmentConfig(), AuthApplication: application,
	}
	idp := NewNauthilusIDP(d)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("POST", "/login", nil)
	ctx.Request.RemoteAddr = "192.168.1.100:12345"
	setupMockContext(ctx, "test-idp-method-guid", definitions.ServIDP)

	_, _ = idp.AuthenticateWithBackend(
		ctx,
		"user1",
		"pass1",
		"client1",
		"",
		core.IDPRequestContext{GrantType: definitions.OIDCFlowAuthorizationCode},
	)

	if len(application.authenticateInputs) != 1 {
		t.Fatalf("application calls = %d, want 1", len(application.authenticateInputs))
	}

	if method := application.authenticateInputs[0].Context.Method; method != definitions.AuthMethodPassword {
		t.Fatalf("expected method to be %q, got %q", definitions.AuthMethodPassword, method)
	}
}
