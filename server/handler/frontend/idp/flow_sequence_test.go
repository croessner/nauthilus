package idp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend"
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

func TestResumeFlowUsesAuthorizeContextWhenFlowReferenceWasCleared(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/login/totp/de", nil)

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyIDPFlowID:              "flow-oidc",
		definitions.SessionKeyIDPFlowType:            definitions.ProtoOIDC,
		definitions.SessionKeyOIDCGrantType:          definitions.OIDCFlowAuthorizationCode,
		definitions.SessionKeyIDPClientID:            "roundcube-client",
		definitions.SessionKeyIDPRedirectURI:         "https://webmail.example.test/index.php/login/oauth",
		definitions.SessionKeyIDPScope:               "openid profile email",
		definitions.SessionKeyIDPState:               "state-1",
		definitions.SessionKeyIDPNonce:               "nonce-1",
		definitions.SessionKeyIDPResponseType:        "code",
		definitions.SessionKeyIDPPrompt:              "login",
		definitions.SessionKeyIDPCodeChallenge:       "challenge-1",
		definitions.SessionKeyIDPCodeChallengeMethod: oidcPKCEChallengeMethodS256,
	}}

	storeIDPFlowResumeFallback(mgr, time.Now())
	mgr.Delete(definitions.SessionKeyIDPFlowID)

	redirectURI, ok := (&FrontendHandler{}).resumeIDPFlowRedirectURI(ctx, mgr)
	if !ok {
		t.Fatal("expected OIDC authorize context fallback")
	}

	if redirectURI == "/" {
		t.Fatal("TOTP completion must not fall back to Nauthilus root when OIDC authorize context is present")
	}

	if !strings.HasPrefix(redirectURI, "/oidc/authorize?") {
		t.Fatalf("resume redirect = %q, want OIDC authorize URL", redirectURI)
	}

	if !strings.Contains(redirectURI, "client_id=roundcube-client") {
		t.Fatalf("resume redirect lost client_id: %q", redirectURI)
	}

	if !strings.Contains(redirectURI, "code_challenge=challenge-1") {
		t.Fatalf("resume redirect lost PKCE challenge: %q", redirectURI)
	}

	for _, fragment := range []string{
		"redirect_uri=https%3A%2F%2Fwebmail.example.test%2Findex.php%2Flogin%2Foauth",
		"scope=openid+profile+email",
		"state=state-1",
		"nonce=nonce-1",
		"response_type=code",
		"prompt=login",
		"code_challenge_method=S256",
	} {
		if !strings.Contains(redirectURI, fragment) {
			t.Fatalf("resume redirect %q missing %q", redirectURI, fragment)
		}
	}
}

func TestResumeFlowUsesFallbackWhenActiveFlowRedirectsToRoot(t *testing.T) {
	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyIDPFlowID: "flow-oidc",
	}}

	mgr.Set(definitions.SessionKeyIDPResumeFallbackURL, "/oidc/authorize?client_id=admin-level3")
	mgr.Set(definitions.SessionKeyIDPResumeFallbackAt, time.Now().Unix())

	if !shouldUseFallbackIDPFlowRedirectURI("/") {
		t.Fatal("expected fresh fallback to override root redirect for an active step-up flow")
	}
}

func TestStoreIDPFlowResumeFallbackUsesCurrentAuthorizeRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/oidc/authorize?client_id=admin-level3&state=state-1", nil)

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyIDPFlowID:   "flow-oidc",
		definitions.SessionKeyIDPFlowType: definitions.ProtoOIDC,
	}}

	storeIDPFlowResumeFallback(mgr, time.Now())
	storeIDPFlowResumeFallbackFromRequest(ctx, mgr, time.Now())

	redirectURI := fallbackIDPFlowRedirectURI(mgr)
	if redirectURI != "/oidc/authorize?client_id=admin-level3&state=state-1" {
		t.Fatalf("fallback redirect = %q, want current authorize request", redirectURI)
	}
}

func TestResumeFlowDoesNotUseStaleAuthorizeContextWithoutFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/login/totp/de", nil)

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyIDPFlowType:     definitions.ProtoOIDC,
		definitions.SessionKeyOIDCGrantType:   definitions.OIDCFlowAuthorizationCode,
		definitions.SessionKeyIDPClientID:     "roundcube-client",
		definitions.SessionKeyIDPRedirectURI:  "https://webmail.example.test/index.php/login/oauth",
		definitions.SessionKeyIDPState:        "state-1",
		definitions.SessionKeyIDPResponseType: "code",
	}}

	redirectURI, ok := (&FrontendHandler{}).resumeIDPFlowRedirectURI(ctx, mgr)
	if !ok {
		t.Fatal("expected default redirect decision")
	}

	if redirectURI != "/" {
		t.Fatalf("stale OIDC metadata redirect = %q, want /", redirectURI)
	}
}

func TestResumeFlowFallbackRejectsUnsafeOrExpiredTargets(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name       string
		target     string
		createdAt  time.Time
		wantTarget string
	}{
		{
			name:       "safe local SAML target",
			target:     "/saml/sso?SAMLRequest=abc",
			createdAt:  now,
			wantTarget: "/saml/sso?SAMLRequest=abc",
		},
		{
			name:      "absolute target rejected",
			target:    "https://evil.example/saml/sso",
			createdAt: now,
		},
		{
			name:      "protocol-relative target rejected",
			target:    "//evil.example/saml/sso",
			createdAt: now,
		},
		{
			name:      "expired target rejected",
			target:    "/saml/sso?SAMLRequest=abc",
			createdAt: now.Add(-idpResumeFallbackTTL - time.Second),
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			mgr := &mockCookieManager{data: map[string]any{
				definitions.SessionKeyIDPResumeFallbackURL: tt.target,
				definitions.SessionKeyIDPResumeFallbackAt:  tt.createdAt.Unix(),
			}}

			got := fallbackIDPFlowRedirectURI(mgr)
			if got != tt.wantTarget {
				t.Fatalf("fallback target = %q, want %q", got, tt.wantTarget)
			}
		})
	}
}

func TestStoreIDPFlowResumeFallbackSupportsDeviceCodeMarker(t *testing.T) {
	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyIDPFlowID:     "flow-device",
		definitions.SessionKeyIDPFlowType:   definitions.ProtoOIDC,
		definitions.SessionKeyOIDCGrantType: definitions.OIDCFlowDeviceCode,
		definitions.SessionKeyDeviceCode:    "device-1",
	}}

	storeIDPFlowResumeFallback(mgr, time.Now())
	mgr.Delete(definitions.SessionKeyIDPFlowID)

	got := fallbackIDPFlowRedirectURI(mgr)
	if got != flowdomain.FlowMetadataResumeTargetDeviceCodeComplete {
		t.Fatalf("device fallback target = %q, want device completion marker", got)
	}
}

func TestResumeFlowDoesNotFallbackOnRedisErrorWithActiveFlowReference(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, mock := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)

	const (
		redisPrefix = "test:"
		flowID      = "flow-active"
	)

	mock.ExpectGet("test:idp:flow:" + flowID).SetErr(errors.New("redis unavailable"))

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyIDPFlowID:              flowID,
		definitions.SessionKeyIDPFlowType:            definitions.ProtoOIDC,
		definitions.SessionKeyOIDCGrantType:          definitions.OIDCFlowAuthorizationCode,
		definitions.SessionKeyIDPClientID:            "roundcube-client",
		definitions.SessionKeyIDPRedirectURI:         "https://webmail.example.test/index.php/login/oauth",
		definitions.SessionKeyIDPState:               "state-1",
		definitions.SessionKeyIDPResponseType:        "code",
		definitions.SessionKeyIDPCodeChallenge:       "challenge-1",
		definitions.SessionKeyIDPCodeChallengeMethod: oidcPKCEChallengeMethodS256,
	}}

	decision, err := resumeFlow(context.Background(), mgr, rClient, redisPrefix)
	if err == nil {
		t.Fatalf("expected Redis-backed resume error to fail closed, got decision %#v", decision)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
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
			recorder, _ := runContinueRequiredMFARegistration(t, tt.handler, tt.cookieData)

			assertContinueMFARedirect(t, recorder, tt.location, tt.locationPrefix)
		})
	}
}

func TestContinueRequiredMFARegistrationRecordsAssurance(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name     string
		flowType string
	}{
		{name: "normal OIDC flow marker", flowType: definitions.ProtoOIDC},
		{name: "missing flow marker with client identifier", flowType: ""},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			parentFlowID := "flow-parent"
			cookieData := map[string]any{
				definitions.SessionKeyIDPFlowID:              flowdomain.NewRequireMFAFlowID(parentFlowID),
				definitions.SessionKeyRequireMFAParentFlowID: parentFlowID,
				definitions.SessionKeyRequireMFAFlow:         true,
				definitions.SessionKeyIDPFlowType:            tt.flowType,
				definitions.SessionKeyOIDCGrantType:          definitions.OIDCFlowAuthorizationCode,
				definitions.SessionKeyIDPClientID:            "client-1",
				definitions.SessionKeyIDPRedirectURI:         "https://rp.example/cb",
				definitions.SessionKeyIDPScope:               "openid",
				definitions.SessionKeyIDPResponseType:        "code",
				definitions.SessionKeyRequireMFAPending:      "",
			}

			recorder, mgr := runContinueRequiredMFARegistration(t, newContinueMFAFrontendHandler(), cookieData)
			if tt.flowType != "" {
				assertContinueMFARedirect(t, recorder, "", "/oidc/authorize?")
			}

			assertRequiredMFARegistrationAssurance(t, mgr)
		})
	}
}

func TestContinueRequiredMFARegistrationUsesEffectiveOIDCPolicyLevel(t *testing.T) {
	gin.SetMode(gin.TestMode)

	idpConfig := &config.IDPSection{
		OIDC: config.OIDCConfig{
			Clients: []config.OIDCClient{
				{
					ClientID:         "client-1",
					SupportedMFA:     []string{definitions.MFAMethodTOTP, definitions.MFAMethodWebAuthn},
					RequireMFA:       []string{definitions.MFAMethodWebAuthn},
					RequiredMFALevel: 3,
					MFAPolicy: config.MFAPolicy{
						Levels: map[string]int{
							definitions.MFAMethodTOTP:     3,
							definitions.MFAMethodWebAuthn: 2,
						},
					},
				},
			},
		},
	}
	setContinueMFATestIDPConfig(t, idpConfig)

	cookieData := map[string]any{
		definitions.SessionKeyIDPFlowID:              flowdomain.NewRequireMFAFlowID("flow-parent"),
		definitions.SessionKeyRequireMFAParentFlowID: "flow-parent",
		definitions.SessionKeyRequireMFAFlow:         true,
		definitions.SessionKeyIDPFlowType:            definitions.ProtoOIDC,
		definitions.SessionKeyOIDCGrantType:          definitions.OIDCFlowAuthorizationCode,
		definitions.SessionKeyIDPClientID:            "client-1",
		definitions.SessionKeyIDPRedirectURI:         "https://rp.example/cb",
		definitions.SessionKeyIDPScope:               "openid",
		definitions.SessionKeyIDPResponseType:        "code",
		definitions.SessionKeyRequireMFAPending:      "",
	}

	recorder, mgr := runContinueRequiredMFARegistration(t, newContinueMFAFrontendHandlerWithIDP(idpConfig), cookieData)

	assertContinueMFARedirect(t, recorder, "", "/oidc/authorize?")
	if got := mgr.GetInt(definitions.SessionKeyMFAAssuranceLevel, 0); got != 2 {
		t.Fatalf("MFA assurance level = %d, want 2", got)
	}

	if sessionSatisfiesIDPSSOMFAAssurancePolicy(
		mgr,
		[]string{definitions.MFAMethodWebAuthn},
		oidcMFAAssuranceScope("client-1"),
		3,
		time.Now(),
	) {
		t.Fatal("forced WebAuthn registration must not satisfy higher OIDC required_mfa_level")
	}
}

func TestContinueRequiredMFARegistrationUsesEffectiveSAMLPolicyLevel(t *testing.T) {
	gin.SetMode(gin.TestMode)

	idpConfig := &config.IDPSection{
		SAML2: config.SAML2Config{
			ServiceProviders: []config.SAML2ServiceProvider{
				{
					EntityID:         "sp-1",
					ACSURL:           "https://sp.example/acs",
					SupportedMFA:     []string{definitions.MFAMethodTOTP, definitions.MFAMethodWebAuthn},
					RequireMFA:       []string{definitions.MFAMethodWebAuthn},
					RequiredMFALevel: 3,
					MFAPolicy: config.MFAPolicy{
						Levels: map[string]int{
							definitions.MFAMethodTOTP:     3,
							definitions.MFAMethodWebAuthn: 2,
						},
					},
				},
			},
		},
	}
	setContinueMFATestIDPConfig(t, idpConfig)

	cookieData := map[string]any{
		definitions.SessionKeyIDPFlowID:              flowdomain.NewRequireMFAFlowID("flow-parent"),
		definitions.SessionKeyRequireMFAParentFlowID: "flow-parent",
		definitions.SessionKeyRequireMFAFlow:         true,
		definitions.SessionKeyIDPFlowType:            definitions.ProtoSAML,
		definitions.SessionKeyIDPSAMLEntityID:        "sp-1",
		definitions.SessionKeyIDPOriginalURL:         "/saml/sso?SAMLRequest=abc",
		definitions.SessionKeyRequireMFAPending:      "",
	}

	recorder, mgr := runContinueRequiredMFARegistration(t, newContinueMFAFrontendHandlerWithIDP(idpConfig), cookieData)

	assertContinueMFARedirect(t, recorder, "/saml/sso?SAMLRequest=abc", "")
	if got := mgr.GetInt(definitions.SessionKeyMFAAssuranceLevel, 0); got != 2 {
		t.Fatalf("MFA assurance level = %d, want 2", got)
	}

	if sessionSatisfiesIDPSSOMFAAssurancePolicy(
		mgr,
		[]string{definitions.MFAMethodWebAuthn},
		samlMFAAssuranceScope("sp-1"),
		3,
		time.Now(),
	) {
		t.Fatal("forced WebAuthn registration must not satisfy higher SAML required_mfa_level")
	}
}

// assertRequiredMFARegistrationAssurance checks the proof stored after forced MFA registration.
func assertRequiredMFARegistrationAssurance(t *testing.T, mgr *mockCookieManager) {
	t.Helper()

	if !mgr.GetBool(definitions.SessionKeyMFACompleted, false) {
		t.Fatal("expected required MFA registration to record completed MFA assurance")
	}

	if got := mgr.GetString(definitions.SessionKeyMFAMethod, ""); got != definitions.MFAMethodTOTP {
		t.Fatalf("MFA assurance method = %q, want %s", got, definitions.MFAMethodTOTP)
	}

	if got := mgr.GetString(definitions.SessionKeyMFAAssuranceMethod, ""); got != definitions.MFAMethodTOTP {
		t.Fatalf("durable MFA assurance method = %q, want %s", got, definitions.MFAMethodTOTP)
	}

	if got := mgr.GetInt64(definitions.SessionKeyMFAAssuranceAt, 0); got == 0 {
		t.Fatal("expected required MFA registration to record assurance time")
	}

	if got := mgr.GetString(definitions.SessionKeyMFAAssuranceScope, ""); got != oidcMFAAssuranceScope("client-1") {
		t.Fatalf("MFA assurance scope = %q, want %s", got, oidcMFAAssuranceScope("client-1"))
	}
}

func TestStartRequiredMFARegistrationFallsBackToIDPFlowProtocol(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/login", nil)

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyIDPFlowID:         "flow-parent",
		definitions.SessionKeyIDPFlowType:       definitions.ProtoOIDC,
		definitions.SessionKeyIDPClientID:       "client-1",
		definitions.SessionKeyRequireMFAPending: definitions.MFAMethodRecoveryCodes,
		definitions.SessionKeyAccount:           "user@example.test",
		definitions.SessionKeyUniqueUserID:      "uid-user",
	}}
	user := &backend.User{
		ID:   "uid-user",
		Name: "user@example.test",
	}

	redirectURI, redirected := newContinueMFAFrontendHandler().startRequireMFARegistrationFlow(
		ctx,
		mgr,
		user,
		idpProtocolFromSession(mgr),
		[]string{definitions.MFAMethodRecoveryCodes},
	)

	if !redirected {
		t.Fatal("expected required MFA registration redirect")
	}

	if redirectURI == "" {
		t.Fatal("expected required MFA registration redirect URI")
	}

	if got := mgr.GetString(definitions.SessionKeyIDPFlowType, ""); got != definitions.ProtoOIDC {
		t.Fatalf("IDP flow type = %q, want %s", got, definitions.ProtoOIDC)
	}

	if got := mgr.GetString(definitions.SessionKeyRequireMFAParentFlowID, ""); got != "flow-parent" {
		t.Fatalf("parent flow id = %q, want flow-parent", got)
	}
}

func TestWebAuthnCompletionResumesAuthorizationFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/login/webauthn/finish", nil)

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyIDPFlowID:       "flow-oidc",
		definitions.SessionKeyIDPFlowType:     definitions.ProtoOIDC,
		definitions.SessionKeyOIDCGrantType:   definitions.OIDCFlowAuthorizationCode,
		definitions.SessionKeyIDPClientID:     "roundcube-client",
		definitions.SessionKeyIDPRedirectURI:  "https://webmail.example.test/index.php/login/oauth",
		definitions.SessionKeyIDPScope:        "openid profile email",
		definitions.SessionKeyIDPState:        "state-1",
		definitions.SessionKeyIDPNonce:        "nonce-1",
		definitions.SessionKeyIDPResponseType: "code",
		definitions.SessionKeyAccount:         "user@example.test",
		definitions.SessionKeyMFACompleted:    true,
	}}

	redirectURI, ok := (&FrontendHandler{}).loginWebAuthnCompletionRedirect(ctx, mgr)
	if !ok {
		t.Fatal("expected WebAuthn completion redirect")
	}

	if strings.HasPrefix(redirectURI, "/login") {
		t.Fatalf("WebAuthn completion must not resume through /login, got %q", redirectURI)
	}

	if !strings.HasPrefix(redirectURI, "/oidc/authorize?") {
		t.Fatalf("WebAuthn completion redirect = %q, want OIDC authorize resume", redirectURI)
	}

	if !strings.Contains(redirectURI, "client_id=roundcube-client") {
		t.Fatalf("WebAuthn completion redirect lost client_id: %q", redirectURI)
	}
}

func TestWebAuthnCompletionRequiredMFAUsesEnrollmentSnapshot(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/login/webauthn/finish", strings.NewReader("{}"))
	ctx.Request.Header.Set("Content-Type", "application/json")

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyHaveTOTP:          true,
		definitions.SessionKeyHaveWebAuthn:      true,
		definitions.SessionKeyHaveRecoveryCodes: true,
		definitions.SessionKeyAccount:           "user@example.test",
		definitions.SessionKeyUniqueUserID:      "uid-user",
	}}
	ctx.Set(definitions.CtxSecureDataKey, mgr)

	missing := (&FrontendHandler{}).missingRequireMFAMethods(
		ctx,
		mgr,
		&backend.User{Name: "user@example.test", ID: "uid-user"},
		definitions.ProtoOIDC,
		[]string{
			definitions.MFAMethodTOTP,
			definitions.MFAMethodWebAuthn,
			definitions.MFAMethodRecoveryCodes,
		},
	)
	if len(missing) != 0 {
		t.Fatalf("missing required MFA methods after WebAuthn completion = %#v, want none", missing)
	}
}

func TestRequireMFAMethodsFromMetadata(t *testing.T) {
	methods := requireMFAMethodsFromMetadata(map[string]string{
		"require_mfa": "totp,recovery,webauthn,, ",
	})

	want := []string{
		definitions.MFAMethodTOTP,
		definitions.MFAMethodRecoveryCodes,
		definitions.MFAMethodWebAuthn,
	}
	if !slices.Equal(methods, want) {
		t.Fatalf("methods = %#v, want %#v", methods, want)
	}

	if got := requireMFAMethodsFromMetadata(nil); got != nil {
		t.Fatalf("nil metadata methods = %#v, want nil", got)
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
	return newContinueMFAFrontendHandlerWithIDP(&config.IDPSection{
		OIDC: config.OIDCConfig{
			Clients: []config.OIDCClient{
				{
					ClientID:   "client-1",
					RequireMFA: []string{definitions.MFAMethodTOTP},
				},
			},
		},
	})
}

// newContinueMFAFrontendHandlerWithIDP creates a handler with custom IDP config.
func newContinueMFAFrontendHandlerWithIDP(idpConfig *config.IDPSection) *FrontendHandler {
	return &FrontendHandler{
		deps: &deps.Deps{
			Cfg: &mockFrontendCfg{
				FileSettings: config.FileSettings{
					Server: &config.ServerSection{
						Redis: config.Redis{Prefix: "test:"},
					},
					IDP: idpConfig,
				},
			},
		},
	}
}

// setContinueMFATestIDPConfig installs IDP config for effective-policy tests.
func setContinueMFATestIDPConfig(t *testing.T, idpConfig *config.IDPSection) {
	t.Helper()

	previousConfigLoaded := config.IsFileLoaded()

	var previousConfig config.File
	if previousConfigLoaded {
		previousConfig = config.GetFile()
	}

	config.SetTestFile(&config.FileSettings{IDP: idpConfig})

	t.Cleanup(func() {
		if previousConfigLoaded {
			config.SetTestFile(previousConfig)

			return
		}

		config.SetTestFile(nil)
	})
}

// runContinueRequiredMFARegistration executes the continue endpoint for one cookie state.
func runContinueRequiredMFARegistration(
	t *testing.T,
	handler *FrontendHandler,
	cookieData map[string]any,
) (*httptest.ResponseRecorder, *mockCookieManager) {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/mfa/register/continue", nil)
	mgr := &mockCookieManager{data: cookieData}
	ctx.Set(definitions.CtxSecureDataKey, mgr)

	handler.ContinueRequiredMFARegistration(ctx)

	return recorder, mgr
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
