package idp

import (
	"encoding/json"
	"errors"
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
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
)

const roundcubeTestCodeChallenge = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

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

func TestExistingSAMLFlowIsReplacedBeforeOIDCAuthorize(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx, mgr := newRoundcubeAuthorizeTestContext()
	mgr.Set(definitions.SessionKeyIDPFlowID, "completed-saml-flow")
	mgr.Set(definitions.SessionKeyIDPFlowType, definitions.ProtoSAML)
	mgr.Set(definitions.SessionKeyIDPSAMLEntityID, "https://saml.example.test/metadata")
	mgr.Set(definitions.SessionKeyIDPOriginalURL, "/saml/sso?SAMLRequest=stale")

	request, ok := readOIDCAuthorizeRequest(ctx)
	if !ok {
		t.Fatal("expected valid authorize request")
	}

	handler := newRoundcubeOIDCHandler()
	flowContext := newOIDCAuthorizeFlowContext(mgr)
	if !handler.ensureOIDCAuthorizeFlowState(ctx, mgr, flowContext, request, flowContext.Account()) {
		t.Fatal("expected OIDC authorize flow state")
	}

	if got := mgr.GetString(definitions.SessionKeyIDPFlowID, ""); got == "completed-saml-flow" {
		t.Fatal("stale SAML flow id was reused for OIDC")
	}

	assertRoundcubeOIDCFlowSession(t, mgr)

	if got := mgr.GetString(definitions.SessionKeyIDPSAMLEntityID, ""); got != "" {
		t.Fatalf("SAML entity id = %q, want cleanup", got)
	}

	if got := mgr.GetString(definitions.SessionKeyIDPOriginalURL, ""); got != "" {
		t.Fatalf("SAML original URL = %q, want cleanup", got)
	}
}

func TestOIDCAuthorizeRequestMatchesSessionBindsAllRequestFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	request := oidcAuthorizeRequest{
		clientID:            "roundcube-client",
		redirectURI:         "https://webmail.example.test/index.php/login/oauth",
		scope:               "openid profile email",
		state:               "state-1",
		nonce:               "nonce-1",
		responseType:        "code",
		prompt:              "login",
		codeChallenge:       roundcubeTestCodeChallenge,
		codeChallengeMethod: oidcPKCEChallengeMethodS256,
	}
	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyIDPFlowType:            definitions.ProtoOIDC,
		definitions.SessionKeyOIDCGrantType:          definitions.OIDCFlowAuthorizationCode,
		definitions.SessionKeyIDPClientID:            request.clientID,
		definitions.SessionKeyIDPRedirectURI:         request.redirectURI,
		definitions.SessionKeyIDPScope:               request.scope,
		definitions.SessionKeyIDPState:               request.state,
		definitions.SessionKeyIDPNonce:               request.nonce,
		definitions.SessionKeyIDPResponseType:        request.responseType,
		definitions.SessionKeyIDPPrompt:              request.prompt,
		definitions.SessionKeyIDPCodeChallenge:       request.codeChallenge,
		definitions.SessionKeyIDPCodeChallengeMethod: request.codeChallengeMethod,
	}}

	if !oidcAuthorizeRequestMatchesSession(mgr, request) {
		t.Fatal("expected identical OIDC request to match the active flow")
	}

	request.state = "different-state"
	if oidcAuthorizeRequestMatchesSession(mgr, request) {
		t.Fatal("OIDC request with a different state reused the active flow")
	}
}

func TestCurrentOIDCAuthorizeFlowStateFailsClosedWithoutRedis(t *testing.T) {
	ctx, mgr := newRoundcubeAuthorizeTestContext()
	request, ok := readOIDCAuthorizeRequest(ctx)
	if !ok {
		t.Fatal("expected valid authorize request")
	}

	mgr.Set(definitions.SessionKeyIDPFlowID, "flow-oidc")
	mgr.Set(definitions.SessionKeyIDPFlowType, definitions.ProtoOIDC)
	mgr.Set(definitions.SessionKeyOIDCGrantType, definitions.OIDCFlowAuthorizationCode)
	mgr.Set(definitions.SessionKeyIDPClientID, request.clientID)
	mgr.Set(definitions.SessionKeyIDPRedirectURI, request.redirectURI)
	mgr.Set(definitions.SessionKeyIDPScope, request.scope)
	mgr.Set(definitions.SessionKeyIDPState, request.state)
	mgr.Set(definitions.SessionKeyIDPNonce, request.nonce)
	mgr.Set(definitions.SessionKeyIDPResponseType, request.responseType)
	mgr.Set(definitions.SessionKeyIDPPrompt, request.prompt)
	mgr.Set(definitions.SessionKeyIDPCodeChallenge, request.codeChallenge)
	mgr.Set(definitions.SessionKeyIDPCodeChallengeMethod, request.codeChallengeMethod)

	if newRoundcubeOIDCHandler().currentOIDCAuthorizeFlowState(ctx, mgr, request) {
		t.Fatal("OIDC flow without Redis state was accepted")
	}
}

func TestOIDCAuthorizeResumesPendingRequiredMFARegistration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder, ctx, mgr := newRoundcubeAuthorizeRecorderContext()
	parentFlowID := "flow-parent"
	flowID := flowdomain.NewRequireMFAFlowID(parentFlowID)
	mgr.Set(definitions.SessionKeyIDPFlowID, flowID)
	mgr.Set(definitions.SessionKeyIDPFlowType, definitions.ProtoOIDC)
	mgr.Set(definitions.SessionKeyOIDCGrantType, definitions.OIDCFlowAuthorizationCode)
	mgr.Set(definitions.SessionKeyIDPClientID, "roundcube-client")
	mgr.Set(definitions.SessionKeyRequireMFAParentFlowID, parentFlowID)
	mgr.Set(definitions.SessionKeyRequireMFAFlow, true)
	mgr.Set(definitions.SessionKeyRequireMFAPending, definitions.MFAMethodRecoveryCodes)

	request, ok := readOIDCAuthorizeRequest(ctx)
	if !ok {
		t.Fatal("expected valid authorize request")
	}

	handler, mock := newRoundcubeOIDCHandlerWithRedis()
	expectRequiredMFAFlowState(t, mock, flowID, definitions.MFAMethodRecoveryCodes)

	if handler.deps.Redis == nil || handler.deps.Redis.GetWriteHandle() == nil {
		t.Fatal("test Redis dependency is unavailable")
	}

	flowContext := newOIDCAuthorizeFlowContext(mgr)
	if handler.ensureOIDCAuthorizeFlowState(ctx, mgr, flowContext, request, flowContext.Account()) {
		t.Fatal("second authorize request must not replace an incomplete required-MFA registration")
	}

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusFound, recorder.Body.String())
	}

	if got := recorder.Header().Get("Location"); got != definitions.MFARoot+"/recovery/register" {
		t.Fatalf("resume target = %q, want recovery-code registration", got)
	}

	if got := mgr.GetString(definitions.SessionKeyIDPFlowID, ""); got != flowdomain.NewRequireMFAFlowID(parentFlowID) {
		t.Fatalf("flow id = %q, want pending required-MFA flow", got)
	}

	if got := mgr.GetString(definitions.SessionKeyRequireMFAPending, ""); got != definitions.MFAMethodRecoveryCodes {
		t.Fatalf("pending method = %q, want preserved recovery-code registration", got)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet Redis expectations: %v", err)
	}
}

func TestOIDCAuthorizePromptNoneRejectsPendingRequiredMFAInteraction(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler, mock := newRoundcubeOIDCHandlerWithRedis()
	recorder, ctx, mgr := newRoundcubeAuthorizeRecorderContext()
	ctx.Request = httptest.NewRequest(http.MethodGet, "/oidc/authorize?client_id=roundcube-client&redirect_uri=https%3A%2F%2Fwebmail.example.test%2Findex.php%2Flogin%2Foauth&response_type=code&scope=openid+profile+email&state=state-1&nonce=nonce-1&prompt=none&code_challenge=challenge-1&code_challenge_method=S256", nil)
	parentFlowID := "flow-parent"
	flowID := flowdomain.NewRequireMFAFlowID(parentFlowID)
	mgr.Set(definitions.SessionKeyIDPFlowID, flowID)
	mgr.Set(definitions.SessionKeyIDPFlowType, definitions.ProtoOIDC)
	mgr.Set(definitions.SessionKeyOIDCGrantType, definitions.OIDCFlowAuthorizationCode)
	mgr.Set(definitions.SessionKeyIDPClientID, "roundcube-client")
	mgr.Set(definitions.SessionKeyRequireMFAParentFlowID, parentFlowID)
	mgr.Set(definitions.SessionKeyRequireMFAFlow, true)
	mgr.Set(definitions.SessionKeyRequireMFAPending, definitions.MFAMethodRecoveryCodes)
	expectRequiredMFAFlowState(t, mock, flowID, definitions.MFAMethodRecoveryCodes)

	request, ok := readOIDCAuthorizeRequest(ctx)
	if !ok {
		t.Fatal("expected valid authorize request")
	}

	flowContext := newOIDCAuthorizeFlowContext(mgr)
	if handler.ensureOIDCAuthorizeFlowState(ctx, mgr, flowContext, request, flowContext.Account()) {
		t.Fatal("prompt=none must not continue a pending interactive registration")
	}

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusFound, recorder.Body.String())
	}

	if got := recorder.Header().Get("Location"); got != "https://webmail.example.test/index.php/login/oauth?error=interaction_required&state=state-1" {
		t.Fatalf("redirect = %q, want interaction_required callback", got)
	}

	if got := mgr.GetString(definitions.SessionKeyIDPFlowID, ""); got != flowID {
		t.Fatalf("flow id = %q, want pending flow preserved", got)
	}

	if got := mgr.GetString(definitions.SessionKeyRequireMFAPending, ""); got != definitions.MFAMethodRecoveryCodes {
		t.Fatalf("pending method = %q, want preserved registration", got)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet Redis expectations: %v", err)
	}
}

func TestOIDCAuthorizeResumesPendingRequiredMFAWithoutOptionalUniqueUserID(t *testing.T) {
	for _, tc := range []struct {
		name       string
		promptNone bool
		wantTarget string
	}{
		{
			name:       "interactive resume",
			wantTarget: definitions.MFARoot + "/recovery/register",
		},
		{
			name:       "prompt none callback",
			promptNone: true,
			wantTarget: "https://webmail.example.test/index.php/login/oauth?error=interaction_required&state=state-1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertPendingRequiredMFAResumesWithoutUniqueUserID(t, tc.promptNone, tc.wantTarget)
		})
	}
}

func TestOIDCAuthorizeRestoresMissingSessionUniqueUserIDFromBoundRequiredMFAFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler, mock := newRoundcubeOIDCHandlerWithRedis()
	recorder, ctx, mgr := newRoundcubeAuthorizeRecorderContext()
	delete(mgr.data, definitions.SessionKeyUniqueUserID)
	prepareBoundRequiredMFAResume(
		t,
		mock,
		mgr,
		"flow-parent-missing-session-uid",
		definitions.MFAMethodTOTP,
		definitions.MFAMethodTOTP+","+definitions.MFAMethodRecoveryCodes,
		"uid-user",
	)
	mgr.mutations = nil

	resumePendingRequiredMFAAuthorize(t, handler, ctx, mgr)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusFound, recorder.Body.String())
	}

	if got := recorder.Header().Get("Location"); got != definitions.MFARoot+"/totp/register" {
		t.Fatalf("resume target = %q, want TOTP registration", got)
	}

	if got := mgr.GetString(definitions.SessionKeyUniqueUserID, ""); got != "uid-user" {
		t.Fatalf("restored unique user ID = %q, want metadata binding", got)
	}

	assertUniqueUserIDRestoreSaved(t, mgr)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet Redis expectations: %v", err)
	}
}

func TestOIDCAuthorizeRejectsMismatchedRequiredMFAUniqueUserID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler, mock := newRoundcubeOIDCHandlerWithRedis()
	recorder, ctx, mgr := newRoundcubeAuthorizeRecorderContext()
	mgr.Set(definitions.SessionKeyUniqueUserID, "uid-other")
	prepareBoundRequiredMFAResume(
		t,
		mock,
		mgr,
		"flow-parent-mismatched-session-uid",
		definitions.MFAMethodTOTP,
		definitions.MFAMethodTOTP+","+definitions.MFAMethodRecoveryCodes,
		"uid-user",
	)
	mgr.mutations = nil

	resumePendingRequiredMFAAuthorize(t, handler, ctx, mgr)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusConflict, recorder.Body.String())
	}

	if got := recorder.Header().Get("Location"); got != "" {
		t.Fatalf("mismatched identity redirected to %q", got)
	}

	if got := mgr.GetString(definitions.SessionKeyUniqueUserID, ""); got != "uid-other" {
		t.Fatalf("session unique user ID = %q, want mismatch preserved for rejection", got)
	}

	if mgr.saves != 0 || len(mgr.mutations) != 0 {
		t.Fatalf("mismatched identity mutated session: saves=%d mutations=%v", mgr.saves, mgr.mutations)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet Redis expectations: %v", err)
	}
}

func TestOIDCAuthorizeFailsClosedWhenRestoredRequiredMFAUniqueUserIDCannotBeSaved(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler, mock := newRoundcubeOIDCHandlerWithRedis()
	recorder, ctx, mgr := newRoundcubeAuthorizeRecorderContext()
	delete(mgr.data, definitions.SessionKeyUniqueUserID)
	prepareBoundRequiredMFAResume(
		t,
		mock,
		mgr,
		"flow-parent-uid-save-error",
		definitions.MFAMethodTOTP,
		definitions.MFAMethodTOTP+","+definitions.MFAMethodRecoveryCodes,
		"uid-user",
	)
	mgr.mutations = nil
	mgr.saveErr = errors.New("injected cookie save failure")

	resumePendingRequiredMFAAuthorize(t, handler, ctx, mgr)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusInternalServerError, recorder.Body.String())
	}

	if got := recorder.Header().Get("Location"); got != "" {
		t.Fatalf("failed session save redirected to %q", got)
	}

	assertUniqueUserIDRestoreSaved(t, mgr)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet Redis expectations: %v", err)
	}
}

func prepareBoundRequiredMFAResume(
	t *testing.T,
	mock redismock.ClientMock,
	mgr *mockCookieManager,
	parentFlowID string,
	pending string,
	required string,
	uniqueUserID string,
) {
	t.Helper()

	flowID := flowdomain.NewRequireMFAFlowID(parentFlowID)
	mgr.Set(definitions.SessionKeyIDPFlowID, flowID)
	mgr.Set(definitions.SessionKeyIDPFlowType, definitions.ProtoOIDC)
	mgr.Set(definitions.SessionKeyOIDCGrantType, definitions.OIDCFlowAuthorizationCode)
	mgr.Set(definitions.SessionKeyIDPClientID, "roundcube-client")
	mgr.Set(definitions.SessionKeyRequireMFAParentFlowID, parentFlowID)
	mgr.Set(definitions.SessionKeyRequireMFAFlow, true)
	mgr.Set(definitions.SessionKeyRequireMFAPending, pending)
	expectRequiredMFAFlowStateWithUniqueUserID(t, mock, flowID, required, uniqueUserID)
}

func resumePendingRequiredMFAAuthorize(t *testing.T, handler *OIDCHandler, ctx *gin.Context, mgr *mockCookieManager) {
	t.Helper()

	request, ok := readOIDCAuthorizeRequest(ctx)
	if !ok {
		t.Fatal("expected valid authorize request")
	}

	flowContext := newOIDCAuthorizeFlowContext(mgr)
	if handler.ensureOIDCAuthorizeFlowState(ctx, mgr, flowContext, request, flowContext.Account()) {
		t.Fatal("pending required-MFA flow must be handled without starting a replacement")
	}
}

func assertUniqueUserIDRestoreSaved(t *testing.T, mgr *mockCookieManager) {
	t.Helper()

	wantSet := "set:" + definitions.SessionKeyUniqueUserID
	if mgr.saves != 1 || len(mgr.mutations) != 2 || mgr.mutations[0] != wantSet || mgr.mutations[1] != "save" {
		t.Fatalf("unique user ID restore order = %v, saves=%d; want [%s save]", mgr.mutations, mgr.saves, wantSet)
	}
}

func assertPendingRequiredMFAResumesWithoutUniqueUserID(t *testing.T, promptNone bool, wantTarget string) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	handler, mock := newRoundcubeOIDCHandlerWithRedis()
	recorder, ctx, mgr := newRoundcubeAuthorizeRecorderContext()
	delete(mgr.data, definitions.SessionKeyUniqueUserID)

	if promptNone {
		ctx.Request = httptest.NewRequest(http.MethodGet, "/oidc/authorize?client_id=roundcube-client&redirect_uri=https%3A%2F%2Fwebmail.example.test%2Findex.php%2Flogin%2Foauth&response_type=code&scope=openid+profile+email&state=state-1&nonce=nonce-1&prompt=none&code_challenge=challenge-1&code_challenge_method=S256", nil)
	}

	parentFlowID := "flow-parent-without-optional-uid"
	flowID := flowdomain.NewRequireMFAFlowID(parentFlowID)
	mgr.Set(definitions.SessionKeyIDPFlowID, flowID)
	mgr.Set(definitions.SessionKeyIDPFlowType, definitions.ProtoOIDC)
	mgr.Set(definitions.SessionKeyOIDCGrantType, definitions.OIDCFlowAuthorizationCode)
	mgr.Set(definitions.SessionKeyIDPClientID, "roundcube-client")
	mgr.Set(definitions.SessionKeyRequireMFAParentFlowID, parentFlowID)
	mgr.Set(definitions.SessionKeyRequireMFAFlow, true)
	mgr.Set(definitions.SessionKeyRequireMFAPending, definitions.MFAMethodRecoveryCodes)
	expectRequiredMFAFlowStateWithUniqueUserID(t, mock, flowID, definitions.MFAMethodRecoveryCodes, "")

	request, ok := readOIDCAuthorizeRequest(ctx)
	if !ok {
		t.Fatal("expected valid authorize request")
	}

	flowContext := newOIDCAuthorizeFlowContext(mgr)
	if handler.ensureOIDCAuthorizeFlowState(ctx, mgr, flowContext, request, flowContext.Account()) {
		t.Fatal("pending enrollment without optional unique user ID must be resumed")
	}

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusFound, recorder.Body.String())
	}

	if got := recorder.Header().Get("Location"); got != wantTarget {
		t.Fatalf("target = %q, want %q", got, wantTarget)
	}

	if got := mgr.GetString(definitions.SessionKeyIDPFlowID, ""); got != flowID {
		t.Fatalf("flow id = %q, want live pending flow %q", got, flowID)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet Redis expectations: %v", err)
	}
}

func TestOIDCAuthorizeDoesNotTrustForgedRequiredMFAMarkers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	_, ctx, mgr := newRoundcubeAuthorizeRecorderContext()
	mgr.Set(definitions.SessionKeyIDPFlowID, "attacker-controlled-flow")
	mgr.Set(definitions.SessionKeyRequireMFAParentFlowID, "flow-parent")
	mgr.Set(definitions.SessionKeyRequireMFAFlow, true)
	mgr.Set(definitions.SessionKeyRequireMFAPending, definitions.MFAMethodRecoveryCodes)

	request, ok := readOIDCAuthorizeRequest(ctx)
	if !ok {
		t.Fatal("expected valid authorize request")
	}

	handler := newRoundcubeOIDCHandler()

	flowContext := newOIDCAuthorizeFlowContext(mgr)
	if !handler.ensureOIDCAuthorizeFlowState(ctx, mgr, flowContext, request, flowContext.Account()) {
		t.Fatal("forged required-MFA markers must not lock the browser flow")
	}

	if got := mgr.GetString(definitions.SessionKeyIDPFlowID, ""); flowdomain.IsRequireMFAFlowID(got) || got == "attacker-controlled-flow" {
		t.Fatalf("flow id = %q, want a fresh authorization flow", got)
	}

	if mgr.GetBool(definitions.SessionKeyRequireMFAFlow, false) {
		t.Fatal("forged pending-MFA marker was not cleared")
	}
}

func TestOIDCAuthorizeExpiredRequiredMFAFlowStartsFreshParent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler, mock := newRoundcubeOIDCHandlerWithRedis()
	_, ctx, mgr := newRoundcubeAuthorizeRecorderContext()
	oldParentFlowID := "flow-parent-expired"
	expiredFlowID := flowdomain.NewRequireMFAFlowID(oldParentFlowID)
	mgr.Set(definitions.SessionKeyIDPFlowID, expiredFlowID)
	mgr.Set(definitions.SessionKeyIDPFlowType, definitions.ProtoOIDC)
	mgr.Set(definitions.SessionKeyOIDCGrantType, definitions.OIDCFlowAuthorizationCode)
	mgr.Set(definitions.SessionKeyIDPClientID, "roundcube-client")
	mgr.Set(definitions.SessionKeyRequireMFAParentFlowID, oldParentFlowID)
	mgr.Set(definitions.SessionKeyRequireMFAFlow, true)
	mgr.Set(definitions.SessionKeyRequireMFAPending, definitions.MFAMethodTOTP)
	mock.ExpectGet("nt:idp:flow:" + expiredFlowID).RedisNil()
	mock.Regexp().ExpectSet("nt:idp:flow:.*", ".*", 10*time.Minute).SetVal("OK")

	request, ok := readOIDCAuthorizeRequest(ctx)
	if !ok {
		t.Fatal("expected valid authorize request")
	}

	flowContext := newOIDCAuthorizeFlowContext(mgr)
	if !handler.ensureOIDCAuthorizeFlowState(ctx, mgr, flowContext, request, flowContext.Account()) {
		t.Fatal("expired required-MFA state must allow a fresh authorize parent flow")
	}

	newFlowID := mgr.GetString(definitions.SessionKeyIDPFlowID, "")
	if newFlowID == "" || newFlowID == expiredFlowID || newFlowID == oldParentFlowID || flowdomain.IsRequireMFAFlowID(newFlowID) {
		t.Fatalf("flow id = %q, want fresh OIDC parent", newFlowID)
	}

	if got := mgr.GetString(definitions.SessionKeyRequireMFAParentFlowID, ""); got != "" {
		t.Fatalf("stale required-MFA parent = %q, want cleared", got)
	}

	if got := mgr.GetString(definitions.SessionKeyRequireMFAPending, ""); got != "" {
		t.Fatalf("stale pending methods = %q, want cleared", got)
	}

	if mgr.GetBool(definitions.SessionKeyRequireMFAFlow, false) {
		t.Fatal("stale required-MFA marker was not cleared")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet Redis expectations: %v", err)
	}
}

func TestOIDCAuthorizePromptNoneAfterExpiredRequiredMFAFlowAbortsFreshParent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler, mock := newRoundcubeOIDCHandlerWithRedis()
	recorder, ctx, mgr := newRoundcubeAuthorizeRecorderContext()
	ctx.Request = httptest.NewRequest(http.MethodGet, "/oidc/authorize?client_id=roundcube-client&redirect_uri=https%3A%2F%2Fwebmail.example.test%2Findex.php%2Flogin%2Foauth&response_type=code&scope=openid+profile+email&state=state-1&nonce=nonce-1&prompt=none&code_challenge=challenge-1&code_challenge_method=S256", nil)
	oldParentFlowID := "flow-parent-expired-prompt-none"
	expiredFlowID := flowdomain.NewRequireMFAFlowID(oldParentFlowID)
	mgr.Set(definitions.SessionKeyIDPFlowID, expiredFlowID)
	mgr.Set(definitions.SessionKeyIDPFlowType, definitions.ProtoOIDC)
	mgr.Set(definitions.SessionKeyOIDCGrantType, definitions.OIDCFlowAuthorizationCode)
	mgr.Set(definitions.SessionKeyIDPClientID, "roundcube-client")
	mgr.Set(definitions.SessionKeyRequireMFAParentFlowID, oldParentFlowID)
	mgr.Set(definitions.SessionKeyRequireMFAFlow, true)
	mgr.Set(definitions.SessionKeyRequireMFAPending, definitions.MFAMethodTOTP)
	mock.ExpectGet("nt:idp:flow:" + expiredFlowID).RedisNil()
	mock.Regexp().ExpectSet("nt:idp:flow:.*", ".*", 10*time.Minute).SetVal("OK")

	request, ok := readOIDCAuthorizeRequest(ctx)
	if !ok {
		t.Fatal("expected valid authorize request")
	}

	flowContext := newOIDCAuthorizeFlowContext(mgr)
	if !handler.ensureOIDCAuthorizeFlowState(ctx, mgr, flowContext, request, flowContext.Account()) {
		t.Fatal("expired required-MFA state must allow a fresh authorize parent flow")
	}

	newFlowID := mgr.GetString(definitions.SessionKeyIDPFlowID, "")
	if newFlowID == "" || newFlowID == expiredFlowID || flowdomain.IsRequireMFAFlowID(newFlowID) {
		t.Fatalf("flow id = %q, want fresh OIDC parent", newFlowID)
	}

	mgr.Set(definitions.SessionKeyMFACompleted, true)
	mgr.Set(definitions.SessionKeyMFAAssuranceMethod, definitions.MFAMethodTOTP)
	mgr.Set(definitions.SessionKeyMFAAssuranceAt, time.Now().Unix())
	mgr.Set(definitions.SessionKeyMFAAssuranceScope, oidcMFAAssuranceScope("roundcube-client"))
	mgr.Set(definitions.SessionKeyMFAAssuranceLevel, 2)
	mock.ExpectDel("nt:idp:flow:" + newFlowID).SetVal(1)

	client := config.OIDCClient{
		ClientID:   "roundcube-client",
		RequireMFA: []string{definitions.MFAMethodTOTP, definitions.MFAMethodRecoveryCodes},
	}

	handler.issueOIDCAuthorizeCode(
		ctx,
		mgr,
		flowContext,
		&client,
		request,
		&idp.OIDCSession{ClientID: client.ClientID},
		[]string{definitions.ScopeOpenID},
	)

	assertPromptNoneExpiredFlowAbort(t, recorder, mgr)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet Redis expectations: %v", err)
	}
}

func assertPromptNoneExpiredFlowAbort(t *testing.T, recorder *httptest.ResponseRecorder, mgr *mockCookieManager) {
	t.Helper()

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusFound, recorder.Body.String())
	}

	if got := recorder.Header().Get("Location"); got != "https://webmail.example.test/index.php/login/oauth?error=interaction_required&state=state-1" {
		t.Fatalf("redirect = %q, want interaction_required callback", got)
	}

	if got := mgr.GetString(definitions.SessionKeyIDPFlowID, ""); got != "" {
		t.Fatalf("fresh parent flow reference = %q, want abort cleanup", got)
	}
}

func TestOIDCAuthorizeAfterEnrollmentCompletionTTLExpiryClearsOrphanContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler, mock := newRoundcubeOIDCHandlerWithRedis()
	oldParentFlowID := "flow-parent-expired-during-completion"
	expiredFlowID := flowdomain.NewRequireMFAFlowID(oldParentFlowID)
	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyAccount:                "user@example.test",
		definitions.SessionKeyUniqueUserID:           "uid-user",
		definitions.SessionKeyDisplayName:            "User Example",
		definitions.SessionKeySubject:                "uid-user",
		definitions.SessionKeyIDPFlowID:              expiredFlowID,
		definitions.SessionKeyIDPFlowType:            definitions.ProtoOIDC,
		definitions.SessionKeyOIDCGrantType:          definitions.OIDCFlowAuthorizationCode,
		definitions.SessionKeyIDPClientID:            "roundcube-client",
		definitions.SessionKeyRequireMFAParentFlowID: oldParentFlowID,
		definitions.SessionKeyRequireMFAFlow:         true,
		definitions.SessionKeyRequireMFAPending:      definitions.MFAMethodTOTP + "," + definitions.MFAMethodRecoveryCodes,
	}}
	mock.ExpectGet("nt:idp:flow:" + expiredFlowID).RedisNil()

	completionContext, _ := gin.CreateTestContext(httptest.NewRecorder())
	completionContext.Request = httptest.NewRequest(http.MethodPost, "/mfa/totp/register", nil)
	frontendHandler := &FrontendHandler{deps: handler.deps}

	remaining := frontendHandler.removeCompletedRequireMFAMethod(
		completionContext,
		mgr,
		definitions.MFAMethodTOTP,
	)
	if remaining != definitions.MFAMethodRecoveryCodes {
		t.Fatalf("remaining methods = %q, want recovery codes", remaining)
	}

	assertRequiredMFAOrphanAfterCompletionTTLExpiry(t, mgr, oldParentFlowID)

	recorder, authorizeContext, _ := newRoundcubeAuthorizeRecorderContext()
	authorizeContext.Set(definitions.CtxSecureDataKey, mgr)

	request, ok := readOIDCAuthorizeRequest(authorizeContext)
	if !ok {
		t.Fatal("expected valid authorize request")
	}

	mock.Regexp().ExpectSet("nt:idp:flow:.*", ".*", 10*time.Minute).SetVal("OK")

	flowContext := newOIDCAuthorizeFlowContext(mgr)
	if !handler.ensureOIDCAuthorizeFlowState(authorizeContext, mgr, flowContext, request, flowContext.Account()) {
		t.Fatalf("orphaned enrollment context blocked fresh authorize: status=%d body=%q", recorder.Code, recorder.Body.String())
	}

	assertFreshOIDCParentAfterOrphanCleanup(t, mgr, oldParentFlowID)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet Redis expectations: %v", err)
	}
}

func assertRequiredMFAOrphanAfterCompletionTTLExpiry(t *testing.T, mgr *mockCookieManager, oldParentFlowID string) {
	t.Helper()

	if got := mgr.GetString(definitions.SessionKeyIDPFlowID, ""); got != "" {
		t.Fatalf("completion TTL miss left flow id = %q, want reference cleanup", got)
	}

	if mgr.GetBool(definitions.SessionKeyRequireMFAFlow, false) {
		t.Fatal("completion TTL miss left required-MFA flow flag")
	}

	if got := mgr.GetString(definitions.SessionKeyRequireMFAParentFlowID, ""); got != oldParentFlowID {
		t.Fatalf("test precondition parent = %q, want orphan %q", got, oldParentFlowID)
	}

	if got := mgr.GetString(definitions.SessionKeyRequireMFAPending, ""); got != definitions.MFAMethodRecoveryCodes {
		t.Fatalf("test precondition pending = %q, want orphan recovery codes", got)
	}
}

func assertFreshOIDCParentAfterOrphanCleanup(t *testing.T, mgr *mockCookieManager, oldParentFlowID string) {
	t.Helper()

	newParentFlowID := mgr.GetString(definitions.SessionKeyIDPFlowID, "")
	if newParentFlowID == "" || newParentFlowID == oldParentFlowID || flowdomain.IsRequireMFAFlowID(newParentFlowID) {
		t.Fatalf("flow id = %q, want fresh parent", newParentFlowID)
	}

	if got := mgr.GetString(definitions.SessionKeyRequireMFAParentFlowID, ""); got != "" {
		t.Fatalf("stale parent flow = %q, want cleared", got)
	}

	if got := mgr.GetString(definitions.SessionKeyRequireMFAPending, ""); got != "" {
		t.Fatalf("stale pending methods = %q, want cleared", got)
	}
}

func TestOIDCAuthorizeResumeBindsPendingRegistrationToRedisFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, mock := redismock.NewClientMock()
	dependencies := newRoundcubeDeps()
	dependencies.Redis = rediscli.NewTestClient(db)
	handler := NewOIDCHandler(dependencies, idp.NewNauthilusIDP(dependencies), nil)
	recorder, ctx, mgr := newRoundcubeAuthorizeRecorderContext()
	parentFlowID := "flow-parent"
	flowID := flowdomain.NewRequireMFAFlowID(parentFlowID)
	mgr.Set(definitions.SessionKeyIDPFlowID, flowID)
	mgr.Set(definitions.SessionKeyIDPFlowType, definitions.ProtoOIDC)
	mgr.Set(definitions.SessionKeyOIDCGrantType, definitions.OIDCFlowAuthorizationCode)
	mgr.Set(definitions.SessionKeyIDPClientID, "roundcube-client")
	mgr.Set(definitions.SessionKeyRequireMFAParentFlowID, parentFlowID)
	mgr.Set(definitions.SessionKeyRequireMFAFlow, true)
	mgr.Set(definitions.SessionKeyRequireMFAPending, definitions.MFAMethodTOTP)
	expectRequiredMFAFlowState(t, mock, flowID, definitions.MFAMethodTOTP+","+definitions.MFAMethodRecoveryCodes)

	request, ok := readOIDCAuthorizeRequest(ctx)
	if !ok {
		t.Fatal("expected valid authorize request")
	}

	flowContext := newOIDCAuthorizeFlowContext(mgr)
	if handler.ensureOIDCAuthorizeFlowState(ctx, mgr, flowContext, request, flowContext.Account()) {
		t.Fatal("pending required-MFA flow must resume instead of being replaced")
	}

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusFound, recorder.Body.String())
	}

	if got := recorder.Header().Get("Location"); got != definitions.MFARoot+"/totp/register" {
		t.Fatalf("resume target = %q, want TOTP registration", got)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet Redis expectations: %v", err)
	}
}

func TestOIDCAuthorizeDoesNotResumePendingMethodsOutsideBoundRedisFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler, mock := newRoundcubeOIDCHandlerWithRedis()
	recorder, ctx, mgr := newRoundcubeAuthorizeRecorderContext()
	parentFlowID := "flow-parent"
	flowID := flowdomain.NewRequireMFAFlowID(parentFlowID)
	mgr.Set(definitions.SessionKeyIDPFlowID, flowID)
	mgr.Set(definitions.SessionKeyIDPFlowType, definitions.ProtoOIDC)
	mgr.Set(definitions.SessionKeyOIDCGrantType, definitions.OIDCFlowAuthorizationCode)
	mgr.Set(definitions.SessionKeyIDPClientID, "roundcube-client")
	mgr.Set(definitions.SessionKeyRequireMFAParentFlowID, parentFlowID)
	mgr.Set(definitions.SessionKeyRequireMFAFlow, true)
	mgr.Set(definitions.SessionKeyRequireMFAPending, definitions.MFAMethodWebAuthn)
	expectRequiredMFAFlowState(t, mock, flowID, definitions.MFAMethodTOTP+","+definitions.MFAMethodRecoveryCodes)

	request, ok := readOIDCAuthorizeRequest(ctx)
	if !ok {
		t.Fatal("expected valid authorize request")
	}

	flowContext := newOIDCAuthorizeFlowContext(mgr)
	if handler.ensureOIDCAuthorizeFlowState(ctx, mgr, flowContext, request, flowContext.Account()) {
		t.Fatal("unbound pending method must fail closed")
	}

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusConflict, recorder.Body.String())
	}

	if got := recorder.Header().Get("Location"); got != "" {
		t.Fatalf("unbound pending method redirected to %q", got)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet Redis expectations: %v", err)
	}
}

func TestRoundcubeRequireMFADoesNotRestrictUnsetSupportedMethods(t *testing.T) {
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

	if !handler.isMFAMethodSupported(mgr, definitions.MFAMethodWebAuthn) {
		t.Fatal("WebAuthn must stay offered when supported_mfa is unset")
	}

	mgr.Set(definitions.SessionKeyMFAAssuranceMethod, definitions.MFAMethodWebAuthn)
	mgr.Set(definitions.SessionKeyMFAAssuranceAt, time.Now().Unix())
	mgr.Set(definitions.SessionKeyMFAAssuranceScope, oidcMFAAssuranceScope("heimdal-client"))

	if sessionHasFreshMFAAssurance(
		mgr,
		[]string{definitions.MFAMethodTOTP, definitions.MFAMethodRecoveryCodes},
		oidcMFAAssuranceScope("roundcube-client"),
		time.Now(),
	) {
		t.Fatal("legacy exact-scope helper must stay strict")
	}

	if !sessionSatisfiesIDPSSOMFAAssurance(
		mgr,
		[]string{definitions.MFAMethodTOTP, definitions.MFAMethodRecoveryCodes},
		oidcMFAAssuranceScope("roundcube-client"),
		time.Now(),
	) {
		t.Fatal("fresh SSO MFA must satisfy normal Roundcube app assurance")
	}
}

func TestSessionHasFreshMFAAssuranceLevel(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name          string
		level         int
		assuredAt     time.Time
		requiredLevel int
		want          bool
	}{
		{
			name:          "level two fails required level three",
			level:         2,
			assuredAt:     now,
			requiredLevel: 3,
			want:          false,
		},
		{
			name:          "level three satisfies required level three",
			level:         3,
			assuredAt:     now,
			requiredLevel: 3,
			want:          true,
		},
		{
			name:          "stale level three fails freshness",
			level:         3,
			assuredAt:     now.Add(-mfaAssuranceFreshness - time.Second),
			requiredLevel: 3,
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := &mockCookieManager{data: map[string]any{
				definitions.SessionKeyMFAAssuranceMethod: definitions.MFAMethodWebAuthn,
				definitions.SessionKeyMFAAssuranceAt:     tt.assuredAt.Unix(),
				definitions.SessionKeyMFAAssuranceScope:  oidcMFAAssuranceScope("security-admin-client"),
				definitions.SessionKeyMFAAssuranceLevel:  tt.level,
			}}

			got := sessionHasFreshMFAAssuranceLevel(
				mgr,
				tt.requiredLevel,
				oidcMFAAssuranceScope("security-admin-client"),
				now,
			)
			if got != tt.want {
				t.Fatalf("sessionHasFreshMFAAssuranceLevel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNoRequiredMFAAssuranceLevelKeepsSSOCompatibility(t *testing.T) {
	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyMFAAssuranceMethod: definitions.MFAMethodTOTP,
		definitions.SessionKeyMFAAssuranceAt:     time.Now().Unix(),
		definitions.SessionKeyMFAAssuranceScope:  oidcMFAAssuranceScope("heimdal-client"),
	}}

	if !sessionSatisfiesIDPSSOMFAAssurance(
		mgr,
		[]string{definitions.MFAMethodWebAuthn},
		oidcMFAAssuranceScope("roundcube-client"),
		time.Now(),
	) {
		t.Fatal("clients without required_mfa_level must keep fresh SSO MFA compatibility")
	}
}

func TestRequiredMFAAssuranceLevelGatesCrossClientSSO(t *testing.T) {
	now := time.Now()
	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyMFAAssuranceMethod: definitions.MFAMethodTOTP,
		definitions.SessionKeyMFAAssuranceAt:     now.Unix(),
		definitions.SessionKeyMFAAssuranceScope:  oidcMFAAssuranceScope("heimdal-client"),
		definitions.SessionKeyMFAAssuranceLevel:  2,
	}}

	if sessionSatisfiesIDPSSOMFAAssurancePolicy(
		mgr,
		[]string{definitions.MFAMethodWebAuthn},
		oidcMFAAssuranceScope("security-admin-client"),
		3,
		now,
	) {
		t.Fatal("level-2 SSO session must not satisfy a level-3 client")
	}

	mgr.Set(definitions.SessionKeyMFAAssuranceMethod, definitions.MFAMethodWebAuthn)
	mgr.Set(definitions.SessionKeyMFAAssuranceLevel, 3)

	if !sessionSatisfiesIDPSSOMFAAssurancePolicy(
		mgr,
		[]string{definitions.MFAMethodWebAuthn},
		oidcMFAAssuranceScope("security-admin-client"),
		3,
		now,
	) {
		t.Fatal("level-3 SSO session must satisfy a level-3 client")
	}
}

func TestRoundcubeRequireMFAAcceptsFreshWebAuthnSSOSession(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/oidc/authorize", nil)

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyAccount:            "croessner@example.test",
		definitions.SessionKeyMFACompleted:       true,
		definitions.SessionKeyMFAAssuranceMethod: definitions.MFAMethodWebAuthn,
		definitions.SessionKeyMFAAssuranceAt:     time.Now().Unix(),
		definitions.SessionKeyMFAAssuranceScope:  oidcMFAAssuranceScope("heimdal-client"),
	}}
	ctx.Set(definitions.CtxSecureDataKey, mgr)

	handler := newRoundcubeOIDCHandler()
	ok := handler.enforceOIDCClientSSOMFAAssurance(ctx, mgr, &config.OIDCClient{
		ClientID:   "roundcube-client",
		RequireMFA: []string{definitions.MFAMethodTOTP, definitions.MFAMethodRecoveryCodes},
	})

	if !ok {
		t.Fatal("fresh WebAuthn SSO session must not trigger immediate Roundcube step-up")
	}

	if got := recorder.Header().Get("Location"); got != "" {
		t.Fatalf("unexpected MFA redirect = %q", got)
	}
}

func TestRoundcubeAuthorizeCodeAcceptsFreshWebAuthnSSOAssurance(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler, mock := newOIDCAssuranceCodeHandler(t)
	ctx, recorder := newOIDCAssuranceCodeContext(map[string]any{
		definitions.SessionKeyAccount:            "croessner@example.test",
		definitions.SessionKeyMFACompleted:       true,
		definitions.SessionKeyMFAMethod:          definitions.MFAMethodWebAuthn,
		definitions.SessionKeyMFAAssuranceMethod: definitions.MFAMethodWebAuthn,
		definitions.SessionKeyMFAAssuranceAt:     time.Now().Unix(),
		definitions.SessionKeyMFAAssuranceScope:  oidcMFAAssuranceScope("heimdal-client"),
	})
	client := config.OIDCClient{
		ClientID:   "roundcube-client",
		RequireMFA: []string{definitions.MFAMethodTOTP, definitions.MFAMethodRecoveryCodes},
	}
	request := oidcAuthorizeRequest{
		clientID:    "roundcube-client",
		redirectURI: "https://webmail.example.test/index.php/login/oauth",
		scope:       "openid profile email",
		state:       "roundcube-state",
	}
	session := &idp.OIDCSession{
		ClientID:     "roundcube-client",
		UserID:       "uid-croessner",
		Username:     "croessner@example.test",
		Scopes:       []string{definitions.ScopeOpenID, definitions.ScopeProfile, definitions.ScopeEmail},
		RedirectURI:  request.redirectURI,
		MFACompleted: true,
		MFAMethod:    definitions.MFAMethodWebAuthn,
	}

	expectOIDCAuthorizationCodeStorage(mock)

	mgr := cookieManagerFromContext(t, ctx)
	handler.issueOIDCAuthorizeCode(ctx, mgr, newOIDCAuthorizeFlowContext(mgr), &client, request, session, session.Scopes)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusFound)
	}

	location := recorder.Header().Get("Location")
	if !strings.HasPrefix(location, request.redirectURI+"?") {
		t.Fatalf("redirect = %q, want Roundcube callback", location)
	}

	if !strings.Contains(location, oidcParamCode+"=") {
		t.Fatalf("redirect = %q, want authorization code", location)
	}

	if strings.HasPrefix(location, frontendMFASelectPath) || strings.HasPrefix(location, frontendLoginPath) {
		t.Fatalf("fresh SSO assurance must not redirect to MFA/login: %q", location)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func TestRoundcubeMFASelectKeepsWebAuthnFromSessionSnapshot(t *testing.T) {
	handler := newRoundcubeFrontendHandler()
	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyIDPFlowType:           definitions.ProtoOIDC,
		definitions.SessionKeyIDPClientID:           "roundcube-client",
		definitions.SessionKeyHaveTOTP:              true,
		definitions.SessionKeyHaveWebAuthn:          true,
		definitions.SessionKeyHaveRecoveryCodes:     true,
		definitions.SessionKeyMFAAssuranceMethod:    definitions.MFAMethodWebAuthn,
		definitions.SessionKeyMFAAssuranceAt:        time.Now().Add(-30 * time.Minute).Unix(),
		definitions.SessionKeyMFAAssuranceScope:     oidcMFAAssuranceScope("heimdal-client"),
		definitions.SessionKeyMFAFactorAccount:      "croessner@example.test",
		definitions.SessionKeyMFAFactorUniqueUserID: "uid-croessner",
	}}
	availability := mfaAvailability{}

	applySessionMFAAvailabilitySnapshot(mgr, &availability)
	handler.applySupportedMFAFilter(mgr, &availability)
	availability.count = countMFAAvailability(availability)

	if !availability.haveTOTP || !availability.haveWebAuthn || !availability.haveRecoveryCodes {
		t.Fatalf("availability = %#v, want all registered methods from session snapshot", availability)
	}

	if availability.count != 3 {
		t.Fatalf("availability count = %d, want 3", availability.count)
	}

	if target, ok := handler.getMFARedirectURLFromAvailability(availability); ok {
		t.Fatalf("expected MFA select page, got direct redirect %q", target)
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

func TestExistingSessionMFAAssuranceChallengePersistsSession(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/oidc/authorize", nil)
	ctx.Set(definitions.CtxGUIDKey, "roundcube-stepup-test-guid")

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyAccount:      "user@example.test",
		definitions.SessionKeyUniqueUserID: "uid-user",
		definitions.SessionKeyDisplayName:  "User Example",
		definitions.SessionKeySubject:      "uid-user",
		definitions.SessionKeyIDPFlowType:  definitions.ProtoOIDC,
		definitions.SessionKeyIDPClientID:  "roundcube-client",
	}}
	ctx.Set(definitions.CtxSecureDataKey, mgr)

	handler := newRoundcubeOIDCHandler()
	ok := handler.enforceOIDCClientMFAAssurance(ctx, mgr, &config.OIDCClient{
		ClientID:   "roundcube-client",
		RequireMFA: []string{definitions.MFAMethodTOTP, definitions.MFAMethodRecoveryCodes},
	})

	if ok {
		t.Fatal("expected Roundcube require_mfa step-up to block code issuance")
	}

	if got := recorder.Header().Get("Location"); got != frontendMFASelectPath {
		t.Fatalf("step-up redirect = %q, want %q", got, frontendMFASelectPath)
	}

	if got := mgr.GetString(definitions.SessionKeyUsername, ""); got != "user@example.test" {
		t.Fatalf("username = %q, want account fallback", got)
	}

	if mgr.saves == 0 {
		t.Fatal("step-up challenge must persist the MFA session before redirect")
	}
}

func TestReadLoginMFASelectSessionFallsBackToAccount(t *testing.T) {
	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyAccount:     "user@example.test",
		definitions.SessionKeyIDPFlowType: definitions.ProtoOIDC,
	}}

	username, protocol := readLoginMFASelectSession(mgr)
	if username != "user@example.test" {
		t.Fatalf("username = %q, want account fallback", username)
	}

	if protocol != definitions.ProtoOIDC {
		t.Fatalf("protocol = %q, want %q", protocol, definitions.ProtoOIDC)
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

func newRoundcubeOIDCHandlerWithRedis() (*OIDCHandler, redismock.ClientMock) {
	db, mock := redismock.NewClientMock()
	dependencies := newRoundcubeDeps()
	dependencies.Redis = rediscli.NewTestClient(db)

	return NewOIDCHandler(dependencies, idp.NewNauthilusIDP(dependencies), nil), mock
}

func expectRequiredMFAFlowState(t *testing.T, mock redismock.ClientMock, flowID string, required string) {
	expectRequiredMFAFlowStateWithUniqueUserID(t, mock, flowID, required, "uid-user")
}

func expectRequiredMFAFlowStateWithUniqueUserID(t *testing.T, mock redismock.ClientMock, flowID string, required string, uniqueUserID string) {
	t.Helper()

	metadata := map[string]string{
		"require_mfa":                      required,
		flowdomain.FlowMetadataClientID:    "roundcube-client",
		flowdomain.FlowMetadataAccount:     "user@example.test",
		flowdomain.FlowMetadataDisplayName: "User Example",
	}
	if uniqueUserID != "" {
		metadata[flowdomain.FlowMetadataUniqueUserID] = uniqueUserID
	}

	state := &flowdomain.State{
		FlowID:      flowID,
		Type:        flowdomain.FlowTypeRequireMFA,
		Protocol:    flowdomain.FlowProtocolOIDC,
		CurrentStep: flowdomain.FlowStepRequireMFAChallenge,
		PendingMFA:  true,
		Metadata:    metadata,
	}

	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal required-MFA flow: %v", err)
	}

	mock.ExpectGet("nt:idp:flow:" + flowID).SetVal(string(encoded))
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
