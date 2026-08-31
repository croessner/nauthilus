// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//nolint:gocyclo,funlen // Post-login tests keep typed identity, affinity, and step-up assertions together.
package idp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/handler/deps"
	flowdomain "github.com/croessner/nauthilus/v4/server/idp/flow"
	"github.com/croessner/nauthilus/v4/server/idp/mfastate"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/sessionstate"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

type canonicalPostLoginConfig struct {
	config.FileSettings
	server config.ServerSection
}

func (c *canonicalPostLoginConfig) GetServer() *config.ServerSection { return &c.server }

type canonicalPostLoginFixture struct {
	handler       *FrontendHandler
	runtime       *cookie.CanonicalRuntime
	browserCookie *http.Cookie
	flowID        string
	username      string
	password      string
}

func TestCanonicalPostLoginSuccessfulPasswordBeginsParentBoundTypedStepUp(t *testing.T) {
	fixture := newCanonicalPostLoginFixture(t)
	response := fixture.post(t, fixture.password)

	stepUpHandle := canonicalPostLoginRedirectTicket(t, response)
	session := fixture.openResponseSession(t, response)

	identity, authenticated := session.Identity()
	if !authenticated || identity.Account != fixture.username || session.Anchor.Value.Assurance.Level != 0 {
		t.Fatalf("post-login anchor identity = %#v, authenticated = %v, assurance = %#v", identity, authenticated, session.Anchor.Value.Assurance)
	}

	affinity, ok := session.BackendAffinity()
	if !ok || affinity.OpaqueToken != "canonical-target-capability" || affinity.Name != "canonical-remote" {
		t.Fatalf("canonical post-login backend affinity = %#v, ok = %v", affinity, ok)
	}

	stepUp, err := mfastate.NewAggregate(session.Stores, session.Handle, 0).
		LoadStepUp(context.Background(), sessionstate.Handle(stepUpHandle))
	if err != nil || string(stepUp.Value.Flow) != fixture.flowID || stepUp.Value.Completed ||
		len(stepUp.Value.SupportedMethods) != 1 || stepUp.Value.SupportedMethods[0] != definitions.MFAMethodTOTP {
		t.Fatalf("typed post-login step-up = %#v, err = %v", stepUp, err)
	}

	parent, err := flowdomain.NewProtocolAggregate(session.Stores, session.Handle, 0).
		Load(context.Background(), fixture.flowID)
	if err != nil || parent.AuthOutcome != flowdomain.AuthOutcomeOK || parent.CurrentStep != flowdomain.FlowStepLogin {
		t.Fatalf("typed post-login parent = %#v, err = %v", parent, err)
	}
}

func TestCanonicalPostLoginWithoutMFAPolicyResumesTypedFlow(t *testing.T) {
	fixture := newCanonicalPostLoginFixture(t)

	cfg, ok := fixture.handler.deps.Cfg.(*canonicalPostLoginConfig)
	if !ok {
		t.Fatal("canonical post-login config has unexpected type")
	}

	cfg.FileSettings.IDP.OIDC.Clients[0].RequiredMFALevel = 0
	cfg.FileSettings.IDP.OIDC.Clients[0].SupportedMFA = nil

	response := fixture.post(t, fixture.password)

	wantLocation := "/oidc/authorize?client_id=client-a&flow=" + fixture.flowID
	if response.Code != http.StatusFound || response.Header().Get("Location") != wantLocation {
		t.Fatalf(
			"no-policy post-login response = %d %q, want %d %q",
			response.Code, response.Header().Get("Location"), http.StatusFound, wantLocation,
		)
	}

	session := fixture.openResponseSession(t, response)

	identity, authenticated := session.Identity()
	if !authenticated || identity.Account != fixture.username || session.Anchor.Value.Assurance.Level != 0 {
		t.Fatalf(
			"no-policy post-login anchor identity = %#v, authenticated = %v, assurance = %#v",
			identity, authenticated, session.Anchor.Value.Assurance,
		)
	}

	if len(session.Anchor.Value.StepUps) != 0 || len(session.Anchor.Value.Enrollments) != 0 {
		t.Fatalf(
			"no-policy post-login created interaction children: step-ups=%v enrollments=%v",
			session.Anchor.Value.StepUps, session.Anchor.Value.Enrollments,
		)
	}
}

func TestCanonicalPostLoginRejectsSecondPrimaryAuthenticationAfterRotation(t *testing.T) {
	fixture := newCanonicalPostLoginFixture(t)
	authenticatorCalls := 0
	originalAuthenticator := fixture.handler.canonicalPasswordAuthenticator
	fixture.handler.canonicalPasswordAuthenticator = func(
		ctx *gin.Context,
		flowContext postLoginFlowContext,
		credentials postLoginCredentials,
	) (canonicalPasswordAuthentication, error) {
		authenticatorCalls++

		return originalAuthenticator(ctx, flowContext, credentials)
	}

	first := fixture.post(t, fixture.password)

	second := fixture.postWithCookie(t, fixture.password, fixture.responseCookie(first))
	if second.Code != http.StatusConflict || authenticatorCalls != 1 {
		t.Fatalf(
			"second canonical primary login = status %d authenticator calls %d, want %d/1",
			second.Code, authenticatorCalls, http.StatusConflict,
		)
	}

	session := fixture.openResponseSession(t, first)
	if len(session.Anchor.Value.StepUps) != 1 || len(session.Anchor.Value.Enrollments) != 0 {
		t.Fatalf(
			"second canonical primary login duplicated children: step-ups=%v enrollments=%v",
			session.Anchor.Value.StepUps, session.Anchor.Value.Enrollments,
		)
	}
}

func TestCanonicalPostLoginFailLatchedStepUpNeverAuthenticatesAndConsumesOnce(t *testing.T) {
	fixture := newCanonicalPostLoginFixture(t)

	cfg, ok := fixture.handler.deps.Cfg.(*canonicalPostLoginConfig)
	if !ok {
		t.Fatal("canonical post-login config has unexpected type")
	}

	cfg.FileSettings.IDP.OIDC.Clients[0].DelayedResponse = true
	fixture.handler.canonicalPasswordAuthenticator = func(
		_ *gin.Context,
		_ postLoginFlowContext,
		_ postLoginCredentials,
	) (canonicalPasswordAuthentication, error) {
		user := backend.NewUser(fixture.username, "Canonical Alice", "identity-42")

		return canonicalPasswordAuthentication{
			user: user,
			backendRef: core.RemoteBackendRef{
				Type: "remote", Name: "canonical-remote", Protocol: definitions.ProtoOIDC,
				Authority: "canonical-authority", OpaqueToken: "canonical-target-capability",
			},
			availableMethods: []string{definitions.MFAMethodTOTP},
		}, errors.New("invalid password")
	}

	start := fixture.post(t, "wrong-password")
	stepUpHandle := canonicalPostLoginRedirectTicket(t, start)
	assertCanonicalFailLatchedPending(t, fixture, stepUpHandle)

	verifierCalls := 0
	fixture.handler.canonicalTOTPVerifier = func(
		_ *gin.Context,
		selection canonicalMFASelectionState,
		code string,
	) (bool, error) {
		verifierCalls++

		if code != "123456" || selection.identity.Account != fixture.username ||
			selection.stepUp.Value.PendingIdentityReference != "identity-42" ||
			selection.stepUp.Value.PendingBackendAffinity.OpaqueToken != "canonical-target-capability" {
			t.Fatalf("fail-latched TOTP selection = %#v, identity = %#v, code = %q",
				selection.stepUp.Value, selection.identity, code)
		}

		return true, nil
	}

	first := fixture.postTOTP(t, stepUpHandle, "123456")
	if first.Code != http.StatusUnauthorized {
		t.Fatalf("fail-latched TOTP completion status = %d, want %d", first.Code, http.StatusUnauthorized)
	}

	assertCanonicalFailLatchedCompleted(t, fixture, stepUpHandle)

	replay := fixture.postTOTP(t, stepUpHandle, "123456")
	if replay.Code != http.StatusConflict || verifierCalls != 1 {
		t.Fatalf("fail-latched TOTP replay = status %d verifier calls %d, want %d/1",
			replay.Code, verifierCalls, http.StatusConflict)
	}
}

func assertCanonicalFailLatchedPending(
	t *testing.T,
	fixture canonicalPostLoginFixture,
	stepUpHandle string,
) {
	t.Helper()

	session := fixture.openResponseSession(t, httptest.NewRecorder())
	if _, authenticated := session.Identity(); authenticated || session.Anchor.Value.Assurance.Level != 0 {
		t.Fatalf("fail-latched pending anchor authenticated=%v assurance=%#v",
			authenticated, session.Anchor.Value.Assurance)
	}

	stepUp, err := mfastate.NewAggregate(session.Stores, session.Handle, 0).
		LoadStepUp(context.Background(), sessionstate.Handle(stepUpHandle))
	if err != nil || stepUp.Value.AuthOutcome != string(flowdomain.AuthOutcomeFailLatched) ||
		string(stepUp.Value.Flow) != fixture.flowID || stepUp.Value.Completed {
		t.Fatalf("fail-latched pending step-up = %#v, err = %v", stepUp, err)
	}

	parent, err := flowdomain.NewProtocolAggregate(session.Stores, session.Handle, 0).
		Load(context.Background(), fixture.flowID)
	if err != nil || parent.AuthOutcome != flowdomain.AuthOutcomeFailLatched {
		t.Fatalf("fail-latched pending parent = %#v, err = %v", parent, err)
	}
}

func assertCanonicalFailLatchedCompleted(
	t *testing.T,
	fixture canonicalPostLoginFixture,
	stepUpHandle string,
) {
	t.Helper()

	session := fixture.openResponseSession(t, httptest.NewRecorder())
	if _, authenticated := session.Identity(); authenticated || session.Anchor.Value.Assurance.Level != 0 {
		t.Fatalf("fail-latched completed anchor authenticated=%v assurance=%#v",
			authenticated, session.Anchor.Value.Assurance)
	}

	stepUp, err := mfastate.NewAggregate(session.Stores, session.Handle, 0).
		LoadStepUp(context.Background(), sessionstate.Handle(stepUpHandle))
	if !errors.Is(err, sessionstate.ErrNotFound) || len(session.Anchor.Value.StepUps) != 0 {
		t.Fatalf("fail-latched consumed step-up = %#v, err = %v, anchor index = %v",
			stepUp, err, session.Anchor.Value.StepUps)
	}

	parent, err := flowdomain.NewProtocolAggregate(session.Stores, session.Handle, 0).
		Load(context.Background(), fixture.flowID)
	if err != nil || parent.AuthOutcome != flowdomain.AuthOutcomeFailLatched {
		t.Fatalf("fail-latched completed parent = %#v, err = %v", parent, err)
	}
}

func newCanonicalPostLoginFixture(t *testing.T) canonicalPostLoginFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)

	const (
		username = "canonical-post-login-alice"
		password = ""
		flowID   = "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
	)

	serverConfig := config.ServerSection{
		Redis:    config.Redis{Prefix: "canonical-post-login"},
		Frontend: config.Frontend{DefaultLanguage: "en"},
	}
	cfg := &canonicalPostLoginConfig{
		FileSettings: config.FileSettings{IDP: &config.IDPSection{OIDC: config.OIDCConfig{Clients: []config.OIDCClient{{
			ClientID: "client-a", RedirectURIs: []string{"https://client.example.test/callback"},
			SupportedMFA: []string{definitions.MFAMethodTOTP}, RequiredMFALevel: 1, SkipConsent: true,
		}}}}},
		server: serverConfig,
	}
	mini := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mini.Addr()})

	runtime, err := cookie.NewCanonicalRuntime(
		[]byte("canonical-post-login-secret-32bytes"), 1, redisClient, serverConfig.Redis.Prefix,
		canonicalLoginClock{now: time.Date(2026, time.August, 17, 18, 0, 0, 0, time.UTC)},
		sessionstate.NewRandomHandleGenerator(nil), false,
	)
	if err != nil {
		t.Fatalf("create canonical post-login runtime: %v", err)
	}

	dependencies := &deps.Deps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(), Redis: rediscli.NewTestClient(redisClient),
		LangManager: &mockLangManager{}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	handler, err := NewCanonicalFrontendHandler(dependencies, runtime)
	if err != nil {
		t.Fatalf("create canonical post-login handler: %v", err)
	}

	user := backend.NewUser(username, "Canonical Alice", "identity-42")
	user.TOTPSecretField = "totp_secret"
	user.Attributes = map[string][]any{"totp_secret": {"JBSWY3DPEHPK3PXP"}}
	handler.canonicalPasswordAuthenticator = func(
		_ *gin.Context,
		_ postLoginFlowContext,
		_ postLoginCredentials,
	) (canonicalPasswordAuthentication, error) {
		return canonicalPasswordAuthentication{
			user: user,
			backendRef: core.RemoteBackendRef{
				Type: "remote", Name: "canonical-remote", Protocol: definitions.ProtoOIDC,
				Authority: "canonical-authority", OpaqueToken: "canonical-target-capability",
			},
		}, nil
	}

	cookieWriter := httptest.NewRecorder()

	session, err := runtime.Create(context.Background(), cookieWriter, false)
	if err != nil {
		t.Fatalf("create canonical post-login session: %v", err)
	}

	flow := &flowdomain.State{
		FlowID: flowID, Type: flowdomain.FlowTypeOIDCAuthorization, Protocol: flowdomain.FlowProtocolOIDC,
		CurrentStep: flowdomain.FlowStepLogin, AuthOutcome: flowdomain.AuthOutcomeUnknown,
		ReturnTarget: "/oidc/authorize?client_id=client-a",
		Metadata: map[string]string{
			flowdomain.FlowMetadataClientID:     "client-a",
			flowdomain.FlowMetadataRedirectURI:  "https://client.example.test/callback",
			flowdomain.FlowMetadataResponseType: "code",
		},
	}
	if err = flowdomain.NewTypedStore(session.Stores, session.Handle, flowdomain.FlowProtocolOIDC, 10*time.Minute).
		Save(context.Background(), flow); err != nil {
		t.Fatalf("save canonical post-login flow: %v", err)
	}

	return canonicalPostLoginFixture{
		handler: handler, runtime: runtime, browserCookie: cookieWriter.Result().Cookies()[0],
		flowID: flowID, username: username, password: password,
	}
}

func (fixture canonicalPostLoginFixture) post(t *testing.T, password string) *httptest.ResponseRecorder {
	t.Helper()

	return fixture.postWithCookie(t, password, fixture.browserCookie)
}

func (fixture canonicalPostLoginFixture) postWithCookie(
	t *testing.T,
	password string,
	browserCookie *http.Cookie,
) *httptest.ResponseRecorder {
	t.Helper()

	form := url.Values{"username": {fixture.username}, "password": {password}}
	request := httptest.NewRequest(http.MethodPost, "/login?flow="+fixture.flowID, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router := gin.New()
	legacyManager := &mockCookieManager{data: map[string]any{}}
	legacyManager.Set(definitions.SessionKeyRemoteBackendRefType, "remote")
	legacyManager.Set(definitions.SessionKeyRemoteBackendRefName, "stale-legacy")
	legacyManager.Set(definitions.SessionKeyRemoteBackendRefProtocol, definitions.ProtoOIDC)
	legacyManager.Set(definitions.SessionKeyRemoteBackendRefAuthority, "stale-authority")
	legacyManager.Set(definitions.SessionKeyRemoteBackendRefToken, "stale-factor-capability")
	router.POST(
		"/login",
		cookie.CanonicalMiddleware(fixture.runtime, cookie.CanonicalContinuation),
		func(ctx *gin.Context) {
			ctx.Set(definitions.CtxSecureDataKey, legacyManager)
			ctx.Next()
		},
		fixture.handler.PostLogin,
	)
	router.ServeHTTP(writer, request)

	return writer
}

func (fixture canonicalPostLoginFixture) postTOTP(
	t *testing.T,
	stepUpHandle string,
	code string,
) *httptest.ResponseRecorder {
	t.Helper()

	form := url.Values{"code": {code}}
	request := httptest.NewRequest(
		http.MethodPost,
		"/login/totp?flow="+stepUpHandle,
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(fixture.browserCookie)

	writer := httptest.NewRecorder()
	router := gin.New()
	router.POST(
		"/login/totp",
		cookie.CanonicalMiddleware(fixture.runtime, cookie.CanonicalContinuation),
		fixture.handler.PostLoginTOTP,
	)
	router.ServeHTTP(writer, request)

	return writer
}

func canonicalPostLoginRedirectTicket(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()

	if response.Code != http.StatusFound {
		t.Fatalf("post-login status = %d, want %d", response.Code, http.StatusFound)
	}

	target, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse post-login redirect: %v", err)
	}

	ticket := target.Query().Get("flow")
	if ticket == "" {
		t.Fatalf("post-login redirect lacks typed ticket: %q", response.Header().Get("Location"))
	}

	return ticket
}

func (fixture canonicalPostLoginFixture) responseCookie(response *httptest.ResponseRecorder) *http.Cookie {
	for _, responseCookie := range response.Result().Cookies() {
		if responseCookie.MaxAge >= 0 && responseCookie.Value != "" {
			return responseCookie
		}
	}

	return fixture.browserCookie
}

func (fixture canonicalPostLoginFixture) openResponseSession(
	t *testing.T,
	response *httptest.ResponseRecorder,
) *cookie.CanonicalSession {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	request.AddCookie(fixture.responseCookie(response))

	session, err := fixture.runtime.Open(context.Background(), request)
	if err != nil {
		t.Fatalf("open post-login canonical session: %v", err)
	}

	return session
}
