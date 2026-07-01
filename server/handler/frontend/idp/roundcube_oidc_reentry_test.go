package idp

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/idp"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
)

func TestExistingSessionAuthorizeCreatesCurrentFlowBeforeMFA(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx, mgr := newRoundcubeAuthorizeTestContext()
	handler := newRoundcubeOIDCHandler()

	request, ok := readOIDCAuthorizeRequest(ctx)
	if !ok {
		t.Fatal("expected valid authorize request")
	}

	flowContext := newOIDCAuthorizeFlowContext(mgr)
	if !handler.ensureOIDCAuthorizeFlowState(ctx, mgr, flowContext, request, flowContext.Account()) {
		t.Fatal("expected OIDC authorize flow state")
	}

	assertRoundcubeOIDCFlowSession(t, mgr)

	frontendHandler := newRoundcubeFrontendHandler()
	if !frontendHandler.redirectExistingSessionMFAAssurance(ctx, mgr) {
		t.Fatal("expected existing session to redirect to MFA assurance")
	}

	if got := ctx.Writer.Header().Get("Location"); got != frontendMFASelectPath {
		t.Fatalf("MFA redirect = %q, want %q", got, frontendMFASelectPath)
	}

	redirectURI, resumeOK := frontendHandler.resumeIDPFlowRedirectURI(ctx, mgr)
	if !resumeOK {
		t.Fatal("expected resumable OIDC authorize flow")
	}

	if !strings.HasPrefix(redirectURI, "/oidc/authorize?") {
		t.Fatalf("resume redirect = %q, want OIDC authorize URL", redirectURI)
	}

	if !strings.Contains(redirectURI, "client_id=roundcube-client") {
		t.Fatalf("resume redirect lost client_id: %q", redirectURI)
	}
}

func TestRoundcubeRequireMFARestrictsUnsetSupportedMethods(t *testing.T) {
	handler := newRoundcubeFrontendHandler()
	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyIDPFlowType: definitions.ProtoOIDC,
		definitions.SessionKeyIDPClientID: "roundcube-client",
	}}

	if !handler.isMFAMethodSupported(mgr, definitions.MFAMethodTOTP) {
		t.Fatal("TOTP must stay supported by require_mfa")
	}

	if !handler.isMFAMethodSupported(mgr, definitions.MFAMethodRecoveryCodes) {
		t.Fatal("recovery codes must stay supported by require_mfa")
	}

	if handler.isMFAMethodSupported(mgr, definitions.MFAMethodWebAuthn) {
		t.Fatal("WebAuthn must not be offered when require_mfa excludes it and supported_mfa is unset")
	}

	mgr.Set(definitions.SessionKeyMFAAssuranceMethod, definitions.MFAMethodWebAuthn)
	mgr.Set(definitions.SessionKeyMFAAssuranceAt, time.Now().Unix())
	mgr.Set(definitions.SessionKeyMFAAssuranceScope, oidcMFAAssuranceScope("roundcube-client"))

	if sessionHasFreshMFAAssurance(
		mgr,
		[]string{definitions.MFAMethodTOTP, definitions.MFAMethodRecoveryCodes},
		oidcMFAAssuranceScope("roundcube-client"),
		time.Now(),
	) {
		t.Fatal("WebAuthn assurance must not satisfy a TOTP/recovery client policy")
	}
}

func TestAuthorizeExistingSessionPublicPathPersistsFlowBeforeUserLookup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupRoundcubeAuthorizePublicPathBoundaryTest()

	recorder, ctx, mgr := newRoundcubeAuthorizeRecorderContext()
	handler := newRoundcubeOIDCHandler()

	handler.Authorize(ctx)

	if recorder.Code == http.StatusBadRequest {
		t.Fatalf("public Authorize path returned No-Flow-style 400; body=%q", recorder.Body.String())
	}

	if got := recorder.Header().Get("Location"); strings.HasPrefix(got, frontendLoginPath) {
		t.Fatalf("public Authorize path redirected to login without a resumable flow: %q", got)
	}

	assertRoundcubeOIDCFlowSession(t, mgr)
	assertRoundcubeOIDCFlowRequestState(t, mgr)

	redirectURI, ok := newRoundcubeFrontendHandler().resumeIDPFlowRedirectURI(ctx, mgr)
	if !ok {
		t.Fatal("expected public Authorize path to leave a resumable flow")
	}

	assertRoundcubeAuthorizeResumeTarget(t, redirectURI)
}

func TestPromptNoneConsentRequiredCleansFreshAuthorizeFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder, ctx, mgr := newPromptNoneConsentAuthorizeContext()
	handler := newRoundcubeOIDCHandler()

	request, ok := readOIDCAuthorizeRequest(ctx)
	if !ok {
		t.Fatal("expected valid authorize request")
	}

	flowContext := newOIDCAuthorizeFlowContext(mgr)
	if !handler.ensureOIDCAuthorizeFlowState(ctx, mgr, flowContext, request, flowContext.Account()) {
		t.Fatal("expected fresh OIDC authorize flow state")
	}

	if mgr.GetString(definitions.SessionKeyIDPFlowID, "") == "" {
		t.Fatal("expected test precondition to create a flow")
	}

	assertPromptNoneConsentRequiredRedirect(t, handler, ctx, mgr, flowContext, request, recorder)
	assertNoOIDCAuthorizeFlowState(t, mgr)
	assertFollowUpAuthorizeCreatesFreshFlow(t, handler, mgr)
}

func newPromptNoneConsentAuthorizeContext() (*httptest.ResponseRecorder, *gin.Context, *mockCookieManager) {
	recorder, ctx, mgr := newRoundcubeAuthorizeRecorderContext()
	ctx.Request = httptest.NewRequest(http.MethodGet, "/oidc/authorize?client_id=consent-client&redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&response_type=code&scope=openid+profile&state=state-2&nonce=nonce-2&prompt=none&code_challenge=challenge-2&code_challenge_method=S256", nil)

	return recorder, ctx, mgr
}

func assertPromptNoneConsentRequiredRedirect(
	t *testing.T,
	handler *OIDCHandler,
	ctx *gin.Context,
	mgr *mockCookieManager,
	flowContext *oidcAuthorizeFlowContext,
	request oidcAuthorizeRequest,
	recorder *httptest.ResponseRecorder,
) {
	t.Helper()

	client := &config.OIDCClient{ClientID: "consent-client"}
	session := &idp.OIDCSession{ClientID: "consent-client", Scopes: []string{"openid", "profile"}}

	if !handler.redirectOIDCAuthorizeConsent(ctx, mgr, client, flowContext, request, session, session.Scopes, true) {
		t.Fatal("expected prompt=none consent_required redirect")
	}

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusFound)
	}

	if got := recorder.Header().Get("Location"); got != "https://app.example.test/callback?error=consent_required&state=state-2" {
		t.Fatalf("redirect = %q, want consent_required callback", got)
	}
}

func assertFollowUpAuthorizeCreatesFreshFlow(t *testing.T, handler *OIDCHandler, mgr *mockCookieManager) {
	t.Helper()

	nextRecorder := httptest.NewRecorder()
	nextCtx, _ := gin.CreateTestContext(nextRecorder)
	nextCtx.Request = httptest.NewRequest(http.MethodGet, "/oidc/authorize?client_id=roundcube-client&redirect_uri=https%3A%2F%2Fwebmail.example.test%2Findex.php%2Flogin%2Foauth&response_type=code&scope=openid+profile+email&state=state-fresh&nonce=nonce-fresh&code_challenge=challenge-fresh&code_challenge_method=S256", nil)
	nextCtx.Set(definitions.CtxSecureDataKey, mgr)
	nextCtx.Set(definitions.CtxServiceKey, definitions.ServIDP)
	nextCtx.Set(definitions.CtxGUIDKey, "roundcube-reentry-test-guid")
	nextCtx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())

	nextRequest, ok := readOIDCAuthorizeRequest(nextCtx)
	if !ok {
		t.Fatal("expected valid follow-up authorize request")
	}

	nextFlowContext := newOIDCAuthorizeFlowContext(mgr)
	if !handler.ensureOIDCAuthorizeFlowState(nextCtx, mgr, nextFlowContext, nextRequest, nextFlowContext.Account()) {
		t.Fatal("expected follow-up authorize request to create fresh flow state")
	}

	assertRoundcubeOIDCFlowSession(t, mgr)

	if got := mgr.GetString(definitions.SessionKeyIDPState, ""); got != "state-fresh" {
		t.Fatalf("follow-up state = %q, want fresh request state", got)
	}

	if got := mgr.GetString(definitions.SessionKeyIDPNonce, ""); got != "nonce-fresh" {
		t.Fatalf("follow-up nonce = %q, want fresh request nonce", got)
	}

	if got := mgr.GetString(definitions.SessionKeyIDPCodeChallenge, ""); got != "challenge-fresh" {
		t.Fatalf("follow-up code challenge = %q, want fresh request PKCE", got)
	}
}

func TestLoginWithoutIDPFlowStaysRejected(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/login", nil)
	ctx.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: map[string]any{
		definitions.SessionKeyAccount: "user@example.test",
	}})

	(&FrontendHandler{}).Login(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func newRoundcubeAuthorizeTestContext() (*gin.Context, *mockCookieManager) {
	_, ctx, mgr := newRoundcubeAuthorizeRecorderContext()

	return ctx, mgr
}

func newRoundcubeAuthorizeRecorderContext() (*httptest.ResponseRecorder, *gin.Context, *mockCookieManager) {
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/oidc/authorize?client_id=roundcube-client&redirect_uri=https%3A%2F%2Fwebmail.example.test%2Findex.php%2Flogin%2Foauth&response_type=code&scope=openid+profile+email&state=state-1&nonce=nonce-1&code_challenge=challenge-1&code_challenge_method=S256", nil)
	ctx.Set(definitions.CtxServiceKey, definitions.ServIDP)
	ctx.Set(definitions.CtxGUIDKey, "roundcube-reentry-test-guid")
	ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyAccount:      "user@example.test",
		definitions.SessionKeyUniqueUserID: "uid-user",
		definitions.SessionKeyDisplayName:  "User Example",
		definitions.SessionKeySubject:      "uid-user",
	}}
	ctx.Set(definitions.CtxSecureDataKey, mgr)

	return recorder, ctx, mgr
}

func setupRoundcubeAuthorizePublicPathBoundaryTest() {
	core.SetDefaultLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
	util.SetDefaultLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
	core.InitPassDBResultPool()
}

func newRoundcubeOIDCHandler() *OIDCHandler {
	dependencies := newRoundcubeDeps()

	return NewOIDCHandler(dependencies, idp.NewNauthilusIDP(dependencies), nil)
}

func newRoundcubeFrontendHandler() *FrontendHandler {
	return &FrontendHandler{
		deps: newRoundcubeDeps(),
	}
}

func newRoundcubeDeps() *deps.Deps {
	return &deps.Deps{
		Cfg:         newRoundcubeConfig(),
		Env:         config.NewTestEnvironmentConfig(),
		LangManager: &mockLangManager{},
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func newRoundcubeConfig() *mockFrontendCfg {
	testBackend := &config.Backend{}
	_ = testBackend.Set(definitions.BackendTestName)

	return &mockFrontendCfg{
		FileSettings: config.FileSettings{
			Server: &config.ServerSection{
				Redis:    config.Redis{Prefix: "test:"},
				Backends: []*config.Backend{testBackend},
			},
			IDP: &config.IDPSection{
				OIDC: config.OIDCConfig{
					Clients: []config.OIDCClient{
						{
							ClientID:        "roundcube-client",
							Name:            "Roundcube",
							RedirectURIs:    []string{"https://webmail.example.test/index.php/login/oauth"},
							Scopes:          []string{"openid", "profile", "email"},
							RequireMFA:      []string{definitions.MFAMethodTOTP, definitions.MFAMethodRecoveryCodes},
							SkipConsent:     true,
							DelayedResponse: true,
						},
					},
				},
			},
		},
	}
}

func assertRoundcubeOIDCFlowSession(t *testing.T, mgr *mockCookieManager) {
	t.Helper()

	if got := mgr.GetString(definitions.SessionKeyIDPFlowID, ""); got == "" {
		t.Fatal("expected OIDC flow id")
	}

	if got := mgr.GetString(definitions.SessionKeyIDPFlowType, ""); got != definitions.ProtoOIDC {
		t.Fatalf("flow type = %q, want %q", got, definitions.ProtoOIDC)
	}

	if got := mgr.GetString(definitions.SessionKeyOIDCGrantType, ""); got != definitions.OIDCFlowAuthorizationCode {
		t.Fatalf("grant type = %q, want %q", got, definitions.OIDCFlowAuthorizationCode)
	}

	if got := mgr.GetString(definitions.SessionKeyIDPClientID, ""); got != "roundcube-client" {
		t.Fatalf("client id = %q, want roundcube-client", got)
	}
}

func assertRoundcubeOIDCFlowRequestState(t *testing.T, mgr *mockCookieManager) {
	t.Helper()

	if got := mgr.GetString(definitions.SessionKeyIDPRedirectURI, ""); got != "https://webmail.example.test/index.php/login/oauth" {
		t.Fatalf("redirect_uri = %q, want Roundcube callback", got)
	}

	if got := mgr.GetString(definitions.SessionKeyIDPScope, ""); got != "openid profile email" {
		t.Fatalf("scope = %q, want openid profile email", got)
	}

	if got := mgr.GetString(definitions.SessionKeyIDPState, ""); got != "state-1" {
		t.Fatalf("state = %q, want state-1", got)
	}

	if got := mgr.GetString(definitions.SessionKeyIDPNonce, ""); got != "nonce-1" {
		t.Fatalf("nonce = %q, want nonce-1", got)
	}

	if got := mgr.GetString(definitions.SessionKeyIDPCodeChallenge, ""); got != "challenge-1" {
		t.Fatalf("code challenge = %q, want challenge-1", got)
	}

	if got := mgr.GetString(definitions.SessionKeyIDPCodeChallengeMethod, ""); got != oidcPKCEChallengeMethodS256 {
		t.Fatalf("code challenge method = %q, want %s", got, oidcPKCEChallengeMethodS256)
	}
}

func assertRoundcubeAuthorizeResumeTarget(t *testing.T, redirectURI string) {
	t.Helper()

	for _, fragment := range []string{
		"/oidc/authorize?",
		"client_id=roundcube-client",
		"redirect_uri=https%3A%2F%2Fwebmail.example.test%2Findex.php%2Flogin%2Foauth",
		"scope=openid+profile+email",
		"state=state-1",
		"nonce=nonce-1",
		"code_challenge=challenge-1",
		"code_challenge_method=S256",
	} {
		if !strings.Contains(redirectURI, fragment) {
			t.Fatalf("resume redirect %q missing %q", redirectURI, fragment)
		}
	}
}

func assertNoOIDCAuthorizeFlowState(t *testing.T, mgr *mockCookieManager) {
	t.Helper()

	for _, key := range []string{
		definitions.SessionKeyIDPFlowID,
		definitions.SessionKeyIDPClientID,
		definitions.SessionKeyIDPRedirectURI,
		definitions.SessionKeyIDPState,
		definitions.SessionKeyIDPNonce,
		definitions.SessionKeyIDPCodeChallenge,
		definitions.SessionKeyIDPCodeChallengeMethod,
	} {
		if got := mgr.GetString(key, ""); got != "" {
			t.Fatalf("session key %s = %q, want cleanup", key, got)
		}
	}
}
