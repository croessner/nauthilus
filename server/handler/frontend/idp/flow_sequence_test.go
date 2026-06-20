package idp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
)

func TestResumeFlowSequences(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name        string
		cookieData  map[string]any
		redirectURI string
	}{
		{
			name: "OIDC authorization resume",
			cookieData: map[string]any{
				definitions.SessionKeyIDPFlowID:       "flow-oidc",
				definitions.SessionKeyIDPFlowType:     definitions.ProtoOIDC,
				definitions.SessionKeyOIDCGrantType:   definitions.OIDCFlowAuthorizationCode,
				definitions.SessionKeyIDPClientID:     "client-1",
				definitions.SessionKeyIDPRedirectURI:  "https://rp.example/cb",
				definitions.SessionKeyIDPScope:        "openid profile",
				definitions.SessionKeyIDPState:        "state-1",
				definitions.SessionKeyIDPNonce:        "nonce-1",
				definitions.SessionKeyIDPResponseType: "code",
			},
			redirectURI: "/oidc/authorize?client_id=client-1&nonce=nonce-1&redirect_uri=https%3A%2F%2Frp.example%2Fcb&response_type=code&scope=openid+profile&state=state-1",
		},
		{
			name: "SAML resume",
			cookieData: map[string]any{
				definitions.SessionKeyIDPFlowID:       "flow-saml",
				definitions.SessionKeyIDPFlowType:     definitions.ProtoSAML,
				definitions.SessionKeyIDPSAMLEntityID: "sp-1",
				definitions.SessionKeyIDPOriginalURL:  "/saml/sso?SAMLRequest=abc",
			},
			redirectURI: "/saml/sso?SAMLRequest=abc",
		},
		{
			name: "Device code completion marker",
			cookieData: map[string]any{
				definitions.SessionKeyIDPFlowID:     "flow-device",
				definitions.SessionKeyIDPFlowType:   definitions.ProtoOIDC,
				definitions.SessionKeyOIDCGrantType: definitions.OIDCFlowDeviceCode,
				definitions.SessionKeyDeviceCode:    "device-1",
			},
			redirectURI: flowdomain.FlowMetadataResumeTargetDeviceCodeComplete,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assertResumeFlowRedirect(t, tt.cookieData, tt.redirectURI)
		})
	}
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
		definitions.SessionKeyIDPFlowID:     flowID,
		definitions.SessionKeyIDPFlowType:   definitions.ProtoOIDC,
		definitions.SessionKeyOIDCGrantType: definitions.OIDCFlowAuthorizationCode,
		definitions.SessionKeyIDPClientID:   "client-1",
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

	cases := []struct {
		name           string
		handler        *FrontendHandler
		cookieData     map[string]any
		location       string
		locationPrefix string
	}{
		{
			name:    "redirects to next required registration when pending exists",
			handler: &FrontendHandler{},
			cookieData: map[string]any{
				definitions.SessionKeyRequireMFAPending: definitions.MFAMethodTOTP,
			},
			location: definitions.MFARoot + "/totp/register",
		},
		{
			name:    "resumes parent flow when pending is empty",
			handler: newContinueMFAFrontendHandler(),
			cookieData: map[string]any{
				definitions.SessionKeyIDPFlowID:       "flow-parent",
				definitions.SessionKeyIDPFlowType:     definitions.ProtoOIDC,
				definitions.SessionKeyOIDCGrantType:   definitions.OIDCFlowAuthorizationCode,
				definitions.SessionKeyIDPClientID:     "client-1",
				definitions.SessionKeyIDPRedirectURI:  "https://rp.example/cb",
				definitions.SessionKeyIDPScope:        "openid",
				definitions.SessionKeyIDPResponseType: "code",
			},
			locationPrefix: "/oidc/authorize?",
		},
		{
			name:    "restores parent flow id after require_mfa sub-flow cleanup",
			handler: newContinueMFAFrontendHandler(),
			cookieData: map[string]any{
				definitions.SessionKeyIDPFlowID:              "require-mfa-flow",
				definitions.SessionKeyRequireMFAParentFlowID: "flow-parent",
				definitions.SessionKeyRequireMFAFlow:         true,
				definitions.SessionKeyIDPFlowType:            definitions.ProtoOIDC,
				definitions.SessionKeyOIDCGrantType:          definitions.OIDCFlowAuthorizationCode,
				definitions.SessionKeyIDPClientID:            "client-1",
				definitions.SessionKeyIDPRedirectURI:         "https://rp.example/cb",
				definitions.SessionKeyIDPScope:               "openid",
				definitions.SessionKeyIDPResponseType:        "code",
				definitions.SessionKeyRequireMFAPending:      "",
			},
			locationPrefix: "/oidc/authorize?",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			recorder := runContinueRequiredMFARegistration(t, tt.handler, tt.cookieData)

			assertContinueMFARedirect(t, recorder, tt.location, tt.locationPrefix)
		})
	}
}

// assertResumeFlowRedirect verifies the redirect target produced by resumeFlow.
func assertResumeFlowRedirect(t *testing.T, cookieData map[string]any, redirectURI string) {
	t.Helper()

	mgr := &mockCookieManager{data: cookieData}

	decision, err := resumeFlow(context.Background(), mgr, nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.RedirectURI == "" {
		t.Fatal("expected redirect URI")
	}

	if decision.RedirectURI != redirectURI {
		t.Fatalf("unexpected redirect URI: %s", decision.RedirectURI)
	}
}

// newContinueMFAFrontendHandler creates a handler with the config needed to resume parent flows.
func newContinueMFAFrontendHandler() *FrontendHandler {
	return &FrontendHandler{
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
}

// runContinueRequiredMFARegistration executes the continue endpoint for one cookie state.
func runContinueRequiredMFARegistration(
	t *testing.T,
	handler *FrontendHandler,
	cookieData map[string]any,
) *httptest.ResponseRecorder {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/mfa/register/continue", nil)
	ctx.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: cookieData})

	handler.ContinueRequiredMFARegistration(ctx)

	return recorder
}

// assertContinueMFARedirect verifies exact or prefix-based redirect expectations.
func assertContinueMFARedirect(t *testing.T, recorder *httptest.ResponseRecorder, location string, locationPrefix string) {
	t.Helper()

	if recorder.Code != http.StatusFound {
		t.Fatalf("expected redirect, got status %d", recorder.Code)
	}

	actual := recorder.Header().Get("Location")
	if location != "" && actual != location {
		t.Fatalf("unexpected location: %s", actual)
	}

	if locationPrefix != "" && !strings.HasPrefix(actual, locationPrefix) {
		t.Fatalf("unexpected resume location: %s", actual)
	}
}
