// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//nolint:gocyclo,funlen // OIDC tests keep complete single-use and parallel-flow contracts together.
package idp

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	domainidp "github.com/croessner/nauthilus/v3/server/idp"
	"github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func TestOIDCAuthorizeCanonicalAuthenticatedIssuesOnceWithoutLegacyManager(t *testing.T) {
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)

	client := latchedConsentOIDCClient()
	client.SkipConsent = true
	handler, mockRedis := newOIDCCallbackRedirectTestHandlerWithClient(t, client)
	handler.canonicalAuthorizeUserLoader = func(
		_ *gin.Context,
		_ *cookie.CanonicalSession,
		identity cookie.SessionIdentity,
		_ *config.OIDCClient,
		_ []string,
	) (*backend.User, error) {
		return &backend.User{ID: identity.Reference, Name: identity.Account, DisplayName: identity.DisplayName}, nil
	}

	expectOIDCAuthorizationCodeStorage(mockRedis)

	router := gin.New()
	router.GET("/oidc/authorize", cookie.CanonicalMiddleware(runtime, cookie.CanonicalProtocolEntry), handler.AuthorizeCanonical)

	query := url.Values{
		oidcParamClientID: {client.ClientID}, oidcParamRedirectURI: {client.RedirectURIs[0]},
		oidcParamScope: {definitions.ScopeOpenID}, oidcParamState: {"state-a"},
		oidcParamResponseType: {oidcResponseTypeCode},
	}
	request := httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+query.Encode(), nil)
	request.AddCookie(browserCookie)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || response.Code != http.StatusFound || location.Scheme != "https" ||
		location.Query().Get(oidcParamCode) == "" || location.Query().Get(oidcParamState) != "state-a" {
		t.Fatalf("canonical authenticated authorize = %d %q, err = %v", response.Code, response.Header().Get("Location"), err)
	}

	session := openCanonicalFixture(t, runtime, browserCookie)
	if len(session.Anchor.Value.OIDCFlows) != 0 {
		t.Fatalf("completed canonical authorize index = %v, want empty", session.Anchor.Value.OIDCFlows)
	}

	assertCanonicalOIDCLogoutClient(t, session, client.ClientID)

	if err = mockRedis.ExpectationsWereMet(); err != nil {
		t.Fatalf("OIDC code storage expectations: %v", err)
	}
}

func TestCanonicalOIDCAuthorizeResumesOriginalPendingEnrollment(t *testing.T) {
	gin.SetMode(gin.TestMode)

	state := canonicalDecisionOIDCState("")
	runtime, browserCookie, flowID := seedCanonicalIDPFlow(t, state)
	authenticateCanonicalFixture(t, runtime, browserCookie)
	enrollment := seedCanonicalEnrollmentForMethods(
		t, runtime, browserCookie, flowID, []string{definitions.MFAMethodTOTP},
	)
	session := openCanonicalFixture(t, runtime, browserCookie)

	response := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(response)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/oidc/authorize?client_id=client-a", nil)

	resumed, err := resumeCanonicalPendingOIDCEnrollment(ctx, session, cookie.SessionIdentity{
		Reference: "identity-42", Account: "alice", Subject: "identity-42", DisplayName: "Alice", Protocol: "oidc",
	}, oidcAuthorizeRequest{
		clientID: "client-a", redirectURI: "https://client.example.test/callback",
	})
	if err != nil || !resumed || response.Code != http.StatusFound {
		t.Fatalf("resume pending enrollment = %t, status = %d, err = %v", resumed, response.Code, err)
	}

	want := flow.AppendTicket(definitions.MFARoot+"/totp/register", string(enrollment))
	if location := response.Header().Get("Location"); location != want {
		t.Fatalf("pending enrollment redirect = %q, want %q", location, want)
	}

	indexed := openCanonicalFixture(t, runtime, browserCookie)
	if len(indexed.Anchor.Value.OIDCFlows) != 1 || indexed.Anchor.Value.OIDCFlows[0] != sessionstate.Handle(flowID) ||
		len(indexed.Anchor.Value.Enrollments) != 1 || indexed.Anchor.Value.Enrollments[0] != enrollment {
		t.Fatalf("pending enrollment indexes = oidc %v enrollment %v", indexed.Anchor.Value.OIDCFlows,
			indexed.Anchor.Value.Enrollments)
	}
}

func TestCanonicalOIDCResumeTargetAcceptsOneLocalizedAuthorizeSegment(t *testing.T) {
	t.Parallel()

	for _, target := range []string{
		"/oidc/authorize?client_id=test-client",
		"/oidc/authorize/en?client_id=test-client",
		"/oidc/authorize/de-DE?client_id=test-client",
	} {
		if !validCanonicalOIDCResumeTarget(target) {
			t.Fatalf("valid localized authorize target rejected: %q", target)
		}
	}

	for _, target := range []string{
		"/oidc/authorize/en/extra?client_id=test-client",
		"https://attacker.example/oidc/authorize/en",
		"/oidc/consent/en",
	} {
		if validCanonicalOIDCResumeTarget(target) {
			t.Fatalf("invalid authorize target accepted: %q", target)
		}
	}
}

func TestOIDCAuthorizeCanonicalUsesOnlyTypedRememberedConsent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)

	client := latchedConsentOIDCClient()
	handler, mockRedis := newOIDCCallbackRedirectTestHandlerWithClient(t, client)
	handler.canonicalAuthorizeUserLoader = func(
		_ *gin.Context,
		_ *cookie.CanonicalSession,
		identity cookie.SessionIdentity,
		_ *config.OIDCClient,
		_ []string,
	) (*backend.User, error) {
		return &backend.User{ID: identity.Reference, Name: identity.Account, DisplayName: identity.DisplayName}, nil
	}

	session := openCanonicalFixture(t, runtime, browserCookie)

	reference, err := sessionstate.ConsentGrantReference("identity-42", client.ClientID)
	if err != nil {
		t.Fatalf("derive remembered-consent reference: %v", err)
	}

	now := session.EvaluationTime()

	grant := sessionstate.ConsentGrant{
		Record: sessionstate.Record{Handle: reference.Record}, IdentityReference: "identity-42",
		ClientID: client.ClientID, Scopes: []string{definitions.ScopeOpenID, "profile"},
		GrantedAt: now, GrantExpiresAt: now.Add(time.Hour),
	}
	if _, err = session.Stores.Consent.Commit(context.Background(), sessionstate.CommitRequest[sessionstate.ConsentGrant]{
		Reference: reference, Value: grant, TTL: time.Hour,
	}); err != nil {
		t.Fatalf("commit typed remembered consent: %v", err)
	}

	expectOIDCAuthorizationCodeStorage(mockRedis)

	router := gin.New()
	router.GET("/oidc/authorize", cookie.CanonicalMiddleware(runtime, cookie.CanonicalProtocolEntry), handler.AuthorizeCanonical)

	query := url.Values{
		oidcParamClientID: {client.ClientID}, oidcParamRedirectURI: {client.RedirectURIs[0]},
		oidcParamScope: {"openid profile"}, oidcParamState: {"remembered-state"},
		oidcParamResponseType: {oidcResponseTypeCode},
	}
	request := httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+query.Encode(), nil)
	request.AddCookie(browserCookie)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || response.Code != http.StatusFound || location.Query().Get(oidcParamCode) == "" ||
		location.Query().Get(oidcParamState) != "remembered-state" || location.Path != "/callback" {
		t.Fatalf("typed remembered-consent authorize = %d %q, err = %v", response.Code, response.Header().Get("Location"), err)
	}

	if err = mockRedis.ExpectationsWereMet(); err != nil {
		t.Fatalf("remembered-consent Redis expectations: %v", err)
	}
}

func TestOIDCAuthorizeCanonicalPromptNoneRejectsConsentWithoutUIState(t *testing.T) {
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)

	client := latchedConsentOIDCClient()
	handler, mockRedis := newOIDCCallbackRedirectTestHandlerWithClient(t, client)
	handler.canonicalAuthorizeUserLoader = func(
		_ *gin.Context,
		_ *cookie.CanonicalSession,
		identity cookie.SessionIdentity,
		_ *config.OIDCClient,
		_ []string,
	) (*backend.User, error) {
		return &backend.User{ID: identity.Reference, Name: identity.Account, DisplayName: identity.DisplayName}, nil
	}

	router := gin.New()
	router.GET("/oidc/authorize", cookie.CanonicalMiddleware(runtime, cookie.CanonicalProtocolEntry), handler.AuthorizeCanonical)

	query := url.Values{
		oidcParamClientID: {client.ClientID}, oidcParamRedirectURI: {client.RedirectURIs[0]},
		oidcParamScope: {definitions.ScopeOpenID}, oidcParamState: {"prompt-none-state"},
		oidcParamResponseType: {oidcResponseTypeCode}, oidcParamPrompt: {oidcClientAuthMethodNone},
	}
	request := httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+query.Encode(), nil)
	request.AddCookie(browserCookie)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || response.Code != http.StatusFound ||
		location.Query().Get(definitions.LogKeyError) != "consent_required" ||
		location.Query().Get(oidcParamState) != "prompt-none-state" {
		t.Fatalf("prompt=none canonical consent = %d %q, err = %v", response.Code, response.Header().Get("Location"), err)
	}

	session := openCanonicalFixture(t, runtime, browserCookie)
	if len(session.Anchor.Value.OIDCFlows) != 0 {
		t.Fatalf("prompt=none left UI flow state: %v", session.Anchor.Value.OIDCFlows)
	}

	if err = mockRedis.ExpectationsWereMet(); err != nil {
		t.Fatalf("prompt=none unexpectedly wrote consent state: %v", err)
	}
}

func TestOIDCAuthorizeProtocolEntryStartsTypedFlowWithoutLegacyManager(t *testing.T) {
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	handler, _ := newOIDCCallbackRedirectTestHandler(t)
	router := gin.New()
	router.GET("/oidc/authorize", cookie.CanonicalMiddleware(runtime, cookie.CanonicalProtocolEntry), handler.AuthorizeCanonical)

	query := url.Values{
		oidcParamClientID:     {latchedConsentClientID},
		oidcParamRedirectURI:  {"https://app.example.com/callback"},
		oidcParamScope:        {"openid profile"},
		oidcParamState:        {"state-a"},
		oidcParamNonce:        {"nonce-a"},
		oidcParamResponseType: {oidcResponseTypeCode},
	}
	request := httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+query.Encode(), nil)
	request.AddCookie(browserCookie)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || response.Code != http.StatusFound || location.Path != frontendLoginPath {
		t.Fatalf("canonical authorize entry = %d %q, err = %v", response.Code, response.Header().Get("Location"), err)
	}

	flowID := location.Query().Get(flow.FlowTicketParameter)
	if _, err = sessionstate.ParseHandle(flowID); err != nil {
		t.Fatalf("canonical authorize flow ticket = %q: %v", flowID, err)
	}

	session := openCanonicalFixture(t, runtime, browserCookie)

	state, err := flow.NewTypedStore(session.Stores, session.Handle, flow.FlowProtocolOIDC, canonicalOIDCAuthorizationTTL).
		Load(context.Background(), flowID)
	if err != nil || state.CurrentStep != flow.FlowStepLogin ||
		state.Metadata[flow.FlowMetadataClientID] != latchedConsentClientID ||
		state.Metadata[flow.FlowMetadataResumeTarget] != request.URL.RequestURI() {
		t.Fatalf("canonical authorize typed flow = %#v, err = %v", state, err)
	}
}

func TestOIDCConsentCanonicalGETAndPOSTBindTypedFlowAndIgnorePostedState(t *testing.T) {
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)
	handler, mockRedis := newOIDCCallbackRedirectTestHandler(t)
	session := openCanonicalFixture(t, runtime, browserCookie)
	request := oidcAuthorizeRequest{
		clientID: latchedConsentClientID, redirectURI: "https://app.example.com/callback",
		scope: "openid profile", state: "typed-state", responseType: oidcResponseTypeCode,
	}

	state, _, err := startCanonicalOIDCAuthorization(
		context.Background(), session, request, "/oidc/authorize?client_id=test-client",
	)
	if err != nil {
		t.Fatalf("start canonical consent flow: %v", err)
	}

	state.AuthOutcome = flow.AuthOutcomeOK

	store := flow.NewTypedStore(session.Stores, session.Handle, flow.FlowProtocolOIDC, canonicalOIDCAuthorizationTTL)
	if err = store.Save(context.Background(), state); err != nil {
		t.Fatalf("mark canonical consent flow authenticated: %v", err)
	}

	const challenge = "canonical-consent-challenge"
	if _, err = bindCanonicalOIDCConsent(context.Background(), session, state.FlowID, challenge); err != nil {
		t.Fatalf("bind canonical consent: %v", err)
	}

	consentSession := &domainidp.OIDCSession{
		ClientID: request.clientID, UserID: "identity-42", Username: "alice", DisplayName: "Alice",
		Scopes: []string{definitions.ScopeOpenID, "profile"}, RedirectURI: request.redirectURI,
	}
	mockRedis.ExpectGet("test:oidc:code:consent:" + challenge).SetVal(mustMarshalOIDCSession(t, consentSession))
	mockRedis.ExpectGetDel("test:oidc:code:consent:" + challenge).SetVal(mustMarshalOIDCSession(t, consentSession))
	expectOIDCAuthorizationCodeStorage(mockRedis)

	router := gin.New()
	router.SetHTMLTemplate(template.Must(template.New("idp_consent.html").Parse(
		`{{define "idp_consent.html"}}{{.FlowTicket}}|{{.ConsentChallenge}}|{{.State}}{{end}}`,
	)))
	router.GET("/oidc/consent", cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation), handler.ConsentGETCanonical)
	router.POST("/oidc/consent", cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation), handler.ConsentPOSTCanonical)

	getRequest := httptest.NewRequest(http.MethodGet, "/oidc/consent?flow="+url.QueryEscape(state.FlowID)+
		"&consent_challenge="+url.QueryEscape(challenge), nil)
	getRequest.AddCookie(browserCookie)

	getResponse := httptest.NewRecorder()
	router.ServeHTTP(getResponse, getRequest)

	if getResponse.Code != http.StatusOK ||
		!strings.Contains(getResponse.Body.String(), state.FlowID+"|"+challenge+"|typed-state") {
		t.Fatalf("canonical consent GET = %d %q", getResponse.Code, getResponse.Body.String())
	}

	form := url.Values{
		flow.FlowTicketParameter: {state.FlowID}, "consent_challenge": {challenge},
		"submit": {oidcConsentDecisionAllow}, oidcParamState: {"attacker-posted-state"},
	}
	postRequest := httptest.NewRequest(http.MethodPost, "/oidc/consent", strings.NewReader(form.Encode()))
	postRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRequest.AddCookie(browserCookie)

	postResponse := httptest.NewRecorder()
	router.ServeHTTP(postResponse, postRequest)

	location, err := url.Parse(postResponse.Header().Get("Location"))
	if err != nil || postResponse.Code != http.StatusFound ||
		location.Query().Get(oidcParamCode) == "" || location.Query().Get(oidcParamState) != "typed-state" {
		t.Fatalf("canonical consent POST = %d %q, err = %v", postResponse.Code, postResponse.Header().Get("Location"), err)
	}

	if _, err = store.Load(context.Background(), state.FlowID); !errors.Is(err, sessionstate.ErrNotFound) &&
		!errors.Is(err, flow.ErrFlowNotFound) {
		t.Fatalf("completed canonical consent flow reload error = %v", err)
	}

	grantReference, err := sessionstate.ConsentGrantReference("identity-42", latchedConsentClientID)
	if err != nil {
		t.Fatalf("derive persisted consent reference: %v", err)
	}

	persistedGrant, err := session.Stores.Consent.Load(context.Background(), grantReference)
	if err != nil || !persistedGrant.Value.Covers(
		[]string{definitions.ScopeOpenID, "profile"}, session.EvaluationTime(),
	) {
		t.Fatalf("persisted typed consent grant = %#v, err = %v", persistedGrant, err)
	}

	assertCanonicalOIDCLogoutClient(t, openCanonicalFixture(t, runtime, browserCookie), latchedConsentClientID)

	if err = mockRedis.ExpectationsWereMet(); err != nil {
		t.Fatalf("canonical consent Redis expectations: %v", err)
	}

	replayRequest := httptest.NewRequest(http.MethodPost, "/oidc/consent", strings.NewReader(form.Encode()))
	replayRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replayRequest.AddCookie(browserCookie)

	replayResponse := httptest.NewRecorder()
	router.ServeHTTP(replayResponse, replayRequest)

	if replayResponse.Code != http.StatusConflict {
		t.Fatalf("canonical consent replay status = %d, want %d", replayResponse.Code, http.StatusConflict)
	}
}

func assertCanonicalOIDCLogoutClient(
	t *testing.T,
	session *cookie.CanonicalSession,
	clientID string,
) {
	t.Helper()

	logout, err := session.OIDCLogoutContext(context.Background())
	if err != nil || logout.Identity.Reference != "identity-42" || logout.Identity.Account != "alice" ||
		len(logout.ClientIDs) != 1 || logout.ClientIDs[0] != clientID {
		t.Fatalf("canonical OIDC logout context = %#v, want client %q, err = %v", logout, clientID, err)
	}
}

func TestOIDCConsentCanonicalDenyDeletesOnlySelectedParallelFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)
	handler, mockRedis := newOIDCCallbackRedirectTestHandler(t)
	session := openCanonicalFixture(t, runtime, browserCookie)
	firstRequest := oidcAuthorizeRequest{
		clientID: latchedConsentClientID, redirectURI: "https://app.example.com/callback",
		scope: definitions.ScopeOpenID, state: "deny-state", responseType: oidcResponseTypeCode,
	}

	first, _, err := startCanonicalOIDCAuthorization(
		context.Background(), session, firstRequest, "/oidc/authorize?client_id=test-client&state=deny-state",
	)
	if err != nil {
		t.Fatalf("start selected consent flow: %v", err)
	}

	secondRequest := firstRequest
	secondRequest.state = "parallel-state"

	second, _, err := startCanonicalOIDCAuthorization(
		context.Background(), session, secondRequest, "/oidc/authorize?client_id=test-client&state=parallel-state",
	)
	if err != nil {
		t.Fatalf("start parallel consent flow: %v", err)
	}

	store := flow.NewTypedStore(session.Stores, session.Handle, flow.FlowProtocolOIDC, canonicalOIDCAuthorizationTTL)
	first.AuthOutcome = flow.AuthOutcomeOK
	second.AuthOutcome = flow.AuthOutcomeOK

	if err = store.Save(context.Background(), first); err != nil {
		t.Fatalf("authenticate selected consent flow: %v", err)
	}

	if err = store.Save(context.Background(), second); err != nil {
		t.Fatalf("authenticate parallel consent flow: %v", err)
	}

	const challenge = "canonical-deny-challenge"
	if _, err = bindCanonicalOIDCConsent(context.Background(), session, first.FlowID, challenge); err != nil {
		t.Fatalf("bind selected consent flow: %v", err)
	}

	pending := &domainidp.OIDCSession{
		ClientID: firstRequest.clientID, UserID: "identity-42", Username: "alice",
		Scopes: []string{definitions.ScopeOpenID}, RedirectURI: firstRequest.redirectURI,
	}
	mockRedis.ExpectGetDel("test:oidc:code:consent:" + challenge).SetVal(mustMarshalOIDCSession(t, pending))

	router := gin.New()
	router.POST("/oidc/consent", cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation), handler.ConsentPOSTCanonical)

	form := url.Values{
		flow.FlowTicketParameter: {first.FlowID}, "consent_challenge": {challenge}, "submit": {"deny"},
	}
	request := httptest.NewRequest(http.MethodPost, "/oidc/consent", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(browserCookie)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("canonical consent deny status = %d, want %d", response.Code, http.StatusForbidden)
	}

	if _, err = store.Load(context.Background(), first.FlowID); !errors.Is(err, sessionstate.ErrNotFound) &&
		!errors.Is(err, flow.ErrFlowNotFound) {
		t.Fatalf("denied selected flow reload error = %v", err)
	}

	remaining, err := store.Load(context.Background(), second.FlowID)
	if err != nil || remaining.FlowID != second.FlowID {
		t.Fatalf("parallel consent flow = %#v, err = %v", remaining, err)
	}

	indexed := openCanonicalFixture(t, runtime, browserCookie)
	if len(indexed.Anchor.Value.OIDCFlows) != 1 || string(indexed.Anchor.Value.OIDCFlows[0]) != second.FlowID {
		t.Fatalf("remaining OIDC flow index = %v", indexed.Anchor.Value.OIDCFlows)
	}

	if err = mockRedis.ExpectationsWereMet(); err != nil {
		t.Fatalf("canonical deny Redis expectations: %v", err)
	}
}

func TestCanonicalOIDCConsentCleanupFailureReturnsServiceUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)

	now := time.Date(2026, time.August, 18, 12, 0, 0, 0, time.UTC)
	mini := miniredis.RunT(t)

	runtime, err := cookie.NewCanonicalRuntime(
		[]byte("canonical-consent-failure-secret-32b"), 1,
		redis.NewClient(&redis.Options{Addr: mini.Addr()}), "canonical-consent-failure",
		canonicalLoginClock{now: now}, sessionstate.NewRandomHandleGenerator(nil), false,
	)
	if err != nil {
		t.Fatalf("create canonical consent failure runtime: %v", err)
	}

	writer := httptest.NewRecorder()

	session, err := runtime.Create(context.Background(), writer, false)
	if err != nil {
		t.Fatalf("create canonical consent failure session: %v", err)
	}

	request := oidcAuthorizeRequest{
		clientID: latchedConsentClientID, redirectURI: "https://app.example.com/callback",
		scope: definitions.ScopeOpenID, state: "cleanup-state", responseType: oidcResponseTypeCode,
	}

	state, _, err := startCanonicalOIDCAuthorization(
		context.Background(), session, request, "/oidc/authorize?client_id=test-client",
	)
	if err != nil {
		t.Fatalf("start cleanup-failure consent flow: %v", err)
	}

	state.AuthOutcome = flow.AuthOutcomeOK

	store := flow.NewTypedStore(session.Stores, session.Handle, flow.FlowProtocolOIDC, canonicalOIDCAuthorizationTTL)
	if err = store.Save(context.Background(), state); err != nil {
		t.Fatalf("authenticate cleanup-failure consent flow: %v", err)
	}

	const challenge = "cleanup-failure-challenge"
	if _, err = bindCanonicalOIDCConsent(context.Background(), session, state.FlowID, challenge); err != nil {
		t.Fatalf("bind cleanup-failure consent flow: %v", err)
	}

	loaded, err := loadCanonicalOIDCConsent(context.Background(), session, state.FlowID, challenge)
	if err != nil {
		t.Fatalf("load cleanup-failure consent flow: %v", err)
	}

	mini.Close()

	response := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(response)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/oidc/consent", nil)
	abortCanonicalOIDCConsent(ctx, canonicalOIDCConsentSelection{session: session, state: loaded}, http.StatusConflict)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("canonical consent cleanup failure status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func TestCanonicalOIDCAuthorizationBindsConsentAndCompletesOnlySelectedFlow(t *testing.T) {
	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	session := openCanonicalFixture(t, runtime, browserCookie)
	request := oidcAuthorizeRequest{
		clientID: "client-a", redirectURI: "https://client.example.test/callback",
		scope: "openid profile", state: "state-a", nonce: "nonce-a", responseType: oidcResponseTypeCode,
		codeChallenge: "challenge-a", codeChallengeMethod: "S256",
	}

	first, firstTarget, err := startCanonicalOIDCAuthorization(
		context.Background(), session, request, "/oidc/authorize?client_id=client-a",
	)
	if err != nil {
		t.Fatalf("start first canonical OIDC authorization: %v", err)
	}

	second, _, err := startCanonicalOIDCAuthorization(
		context.Background(), session, request, "/oidc/authorize?client_id=client-a&state=state-b",
	)
	if err != nil {
		t.Fatalf("start second canonical OIDC authorization: %v", err)
	}

	assertCanonicalOIDCAuthorizationStart(t, first, firstTarget, request)

	indexedSession := openCanonicalFixture(t, runtime, browserCookie)
	if first.FlowID == second.FlowID || len(indexedSession.Anchor.Value.OIDCFlows) != 2 {
		t.Fatalf("parallel OIDC flows = %q/%q, anchor index = %v", first.FlowID, second.FlowID, indexedSession.Anchor.Value.OIDCFlows)
	}

	first.AuthOutcome = flow.AuthOutcomeOK
	if err = flow.NewTypedStore(session.Stores, session.Handle, flow.FlowProtocolOIDC, 10*time.Minute).
		Save(context.Background(), first); err != nil {
		t.Fatalf("mark first canonical OIDC flow authenticated: %v", err)
	}

	consentTarget, err := bindCanonicalOIDCConsent(context.Background(), session, first.FlowID, "consent-a")
	if err != nil {
		t.Fatalf("bind canonical OIDC consent: %v", err)
	}

	parsedConsent, err := url.Parse(consentTarget)
	if err != nil || parsedConsent.Path != "/oidc/consent" ||
		parsedConsent.Query().Get(flow.FlowTicketParameter) != first.FlowID ||
		parsedConsent.Query().Get("consent_challenge") != "consent-a" {
		t.Fatalf("consent target = %q, err = %v", consentTarget, err)
	}

	loaded, err := loadCanonicalOIDCConsent(context.Background(), session, first.FlowID, "consent-a")
	if err != nil || loaded.CurrentStep != flow.FlowStepConsent {
		t.Fatalf("load bound consent = %#v, err = %v", loaded, err)
	}

	if _, err = loadCanonicalOIDCConsent(context.Background(), session, first.FlowID, "consent-b"); !errors.Is(err, sessionstate.ErrBindingMismatch) {
		t.Fatalf("mismatched consent error = %v, want %v", err, sessionstate.ErrBindingMismatch)
	}

	if err = completeCanonicalOIDCAuthorization(context.Background(), session, first.FlowID, "consent-a"); err != nil {
		t.Fatalf("complete canonical OIDC authorization: %v", err)
	}

	if err = completeCanonicalOIDCAuthorization(context.Background(), session, first.FlowID, "consent-a"); !errors.Is(err, sessionstate.ErrNotFound) {
		t.Fatalf("replayed canonical OIDC completion error = %v, want %v", err, sessionstate.ErrNotFound)
	}

	if _, err = loadCanonicalOIDCConsent(context.Background(), session, first.FlowID, "consent-a"); !errors.Is(err, sessionstate.ErrNotFound) && !errors.Is(err, flow.ErrFlowNotFound) {
		t.Fatalf("completed flow reload error = %v", err)
	}

	remaining, err := flow.NewTypedStore(session.Stores, session.Handle, flow.FlowProtocolOIDC, 10*time.Minute).
		Load(context.Background(), second.FlowID)

	indexedSession = openCanonicalFixture(t, runtime, browserCookie)
	if err != nil || remaining.FlowID != second.FlowID || len(indexedSession.Anchor.Value.OIDCFlows) != 1 {
		t.Fatalf("remaining parallel flow = %#v, err = %v, anchor index = %v", remaining, err, indexedSession.Anchor.Value.OIDCFlows)
	}
}

func assertCanonicalOIDCAuthorizationStart(
	t *testing.T,
	state *flow.State,
	target string,
	request oidcAuthorizeRequest,
) {
	t.Helper()

	if state == nil || state.Type != flow.FlowTypeOIDCAuthorization || state.Protocol != flow.FlowProtocolOIDC ||
		state.CurrentStep != flow.FlowStepLogin || state.AuthOutcome != flow.AuthOutcomeUnknown {
		t.Fatalf("canonical OIDC start state = %#v", state)
	}

	if state.Metadata[flow.FlowMetadataClientID] != request.clientID ||
		state.Metadata[flow.FlowMetadataRedirectURI] != request.redirectURI ||
		state.Metadata[flow.FlowMetadataState] != request.state || state.Metadata[flow.FlowMetadataNonce] != request.nonce ||
		state.Metadata[flow.FlowMetadataCodeChallenge] != request.codeChallenge ||
		state.Metadata[flow.FlowMetadataCodeChallengeMethod] != request.codeChallengeMethod {
		t.Fatalf("canonical OIDC metadata = %#v", state.Metadata)
	}

	if !strings.HasPrefix(target, "/login?") || !strings.Contains(target, flow.FlowTicketParameter+"="+state.FlowID) {
		t.Fatalf("canonical OIDC login target = %q", target)
	}

	if _, err := http.NewRequest(http.MethodGet, target, nil); err != nil {
		t.Fatalf("canonical OIDC login target is invalid: %v", err)
	}
}
