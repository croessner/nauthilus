package idp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	flowdomain "github.com/croessner/nauthilus/server/idp/flow"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
)

func TestResumeFlowSequences(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("OIDC authorization resume", func(t *testing.T) {
		mgr := &mockCookieManager{data: map[string]any{
			definitions.SessionKeyIdPFlowID:       "flow-oidc",
			definitions.SessionKeyIdPFlowType:     definitions.ProtoOIDC,
			definitions.SessionKeyOIDCGrantType:   definitions.OIDCFlowAuthorizationCode,
			definitions.SessionKeyIdPClientID:     "client-1",
			definitions.SessionKeyIdPRedirectURI:  "https://rp.example/cb",
			definitions.SessionKeyIdPScope:        "openid profile",
			definitions.SessionKeyIdPState:        "state-1",
			definitions.SessionKeyIdPNonce:        "nonce-1",
			definitions.SessionKeyIdPResponseType: "code",
		}}

		decision, err := resumeFlow(context.Background(), mgr, nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if decision.RedirectURI == "" {
			t.Fatal("expected redirect URI")
		}

		if decision.RedirectURI != "/oidc/authorize?client_id=client-1&nonce=nonce-1&redirect_uri=https%3A%2F%2Frp.example%2Fcb&response_type=code&scope=openid+profile&state=state-1" {
			t.Fatalf("unexpected redirect URI: %s", decision.RedirectURI)
		}
	})

	t.Run("SAML resume", func(t *testing.T) {
		mgr := &mockCookieManager{data: map[string]any{
			definitions.SessionKeyIdPFlowID:       "flow-saml",
			definitions.SessionKeyIdPFlowType:     definitions.ProtoSAML,
			definitions.SessionKeyIdPSAMLEntityID: "sp-1",
			definitions.SessionKeyIdPOriginalURL:  "/saml/sso?SAMLRequest=abc",
		}}

		decision, err := resumeFlow(context.Background(), mgr, nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if decision.RedirectURI != "/saml/sso?SAMLRequest=abc" {
			t.Fatalf("unexpected redirect URI: %s", decision.RedirectURI)
		}
	})

	t.Run("Device code completion marker", func(t *testing.T) {
		mgr := &mockCookieManager{data: map[string]any{
			definitions.SessionKeyIdPFlowID:     "flow-device",
			definitions.SessionKeyIdPFlowType:   definitions.ProtoOIDC,
			definitions.SessionKeyOIDCGrantType: definitions.OIDCFlowDeviceCode,
			definitions.SessionKeyDeviceCode:    "device-1",
		}}

		decision, err := resumeFlow(context.Background(), mgr, nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if decision.RedirectURI != flowdomain.FlowMetadataResumeTargetDeviceCodeComplete {
			t.Fatalf("unexpected redirect marker: %s", decision.RedirectURI)
		}
	})
}

func TestResumeFlowStaleIDRecovery(t *testing.T) {
	db, mock := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)

	const (
		redisPrefix = "test:"
		flowID      = "flow-stale"
	)

	mock.ExpectGet("test:idp:flow:" + flowID).RedisNil()

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyIdPFlowID:     flowID,
		definitions.SessionKeyIdPFlowType:   definitions.ProtoOIDC,
		definitions.SessionKeyOIDCGrantType: definitions.OIDCFlowAuthorizationCode,
		definitions.SessionKeyIdPClientID:   "client-1",
	}}

	decision, err := resumeFlow(context.Background(), mgr, rClient, redisPrefix)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.RedirectURI != "/login" {
		t.Fatalf("expected stale flow recovery redirect to /login, got: %s", decision.RedirectURI)
	}

	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet redis expectations: %v", err)
	}
}

func TestContinueRequiredMFARegistrationFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("redirects to next required registration when pending exists", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/mfa/register/continue", nil)
		ctx.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: map[string]any{
			definitions.SessionKeyRequireMFAPending: definitions.MFAMethodTOTP,
		}})

		h := &FrontendHandler{}
		h.ContinueRequiredMFARegistration(ctx)

		if recorder.Code != http.StatusFound {
			t.Fatalf("expected redirect, got status %d", recorder.Code)
		}

		if recorder.Header().Get("Location") != definitions.MFARoot+"/totp/register" {
			t.Fatalf("unexpected location: %s", recorder.Header().Get("Location"))
		}
	})

	t.Run("resumes parent flow when pending is empty", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/mfa/register/continue", nil)
		ctx.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: map[string]any{
			definitions.SessionKeyIdPFlowID:       "flow-parent",
			definitions.SessionKeyIdPFlowType:     definitions.ProtoOIDC,
			definitions.SessionKeyOIDCGrantType:   definitions.OIDCFlowAuthorizationCode,
			definitions.SessionKeyIdPClientID:     "client-1",
			definitions.SessionKeyIdPRedirectURI:  "https://rp.example/cb",
			definitions.SessionKeyIdPScope:        "openid",
			definitions.SessionKeyIdPResponseType: "code",
		}})

		h := &FrontendHandler{
			deps: &deps.Deps{
				Cfg: &mockFrontendCfg{
					FileSettings: config.FileSettings{
						Server: &config.ServerSection{
							Redis: config.Redis{Prefix: "test:"},
						},
					},
				},
			},
		}

		h.ContinueRequiredMFARegistration(ctx)

		if recorder.Code != http.StatusFound {
			t.Fatalf("expected redirect, got status %d", recorder.Code)
		}

		location := recorder.Header().Get("Location")
		if location == "" {
			t.Fatal("expected resume redirect location")
		}

		if !strings.HasPrefix(location, "/oidc/authorize?") {
			t.Fatalf("unexpected resume location: %s", location)
		}
	})

	t.Run("restores parent flow id after require_mfa sub-flow cleanup", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/mfa/register/continue", nil)
		ctx.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: map[string]any{
			definitions.SessionKeyIdPFlowID:              "require-mfa-flow",
			definitions.SessionKeyRequireMFAParentFlowID: "flow-parent",
			definitions.SessionKeyRequireMFAFlow:         true,
			definitions.SessionKeyIdPFlowType:            definitions.ProtoOIDC,
			definitions.SessionKeyOIDCGrantType:          definitions.OIDCFlowAuthorizationCode,
			definitions.SessionKeyIdPClientID:            "client-1",
			definitions.SessionKeyIdPRedirectURI:         "https://rp.example/cb",
			definitions.SessionKeyIdPScope:               "openid",
			definitions.SessionKeyIdPResponseType:        "code",
			definitions.SessionKeyRequireMFAPending:      "",
		}})

		h := &FrontendHandler{
			deps: &deps.Deps{
				Cfg: &mockFrontendCfg{
					FileSettings: config.FileSettings{
						Server: &config.ServerSection{
							Redis: config.Redis{Prefix: "test:"},
						},
					},
				},
			},
		}

		h.ContinueRequiredMFARegistration(ctx)

		if recorder.Code != http.StatusFound {
			t.Fatalf("expected redirect, got status %d", recorder.Code)
		}

		location := recorder.Header().Get("Location")
		if !strings.HasPrefix(location, "/oidc/authorize?") {
			t.Fatalf("unexpected resume location: %s", location)
		}
	})
}
