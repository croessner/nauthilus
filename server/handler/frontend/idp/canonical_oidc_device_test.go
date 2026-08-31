// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//nolint:funlen // Device tests keep claim, consent, terminal CAS, and replay in one contract.
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

	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	domainidp "github.com/croessner/nauthilus/v4/server/idp"
	"github.com/croessner/nauthilus/v4/server/idp/flow"
	"github.com/croessner/nauthilus/v4/server/sessionstate"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestCanonicalOIDCDeviceVerifyGETAndPOSTStartTypedLoginWithoutLegacyManager(t *testing.T) {
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	session := openCanonicalFixture(t, runtime, browserCookie)
	request := &domainidp.DeviceCodeRequest{
		ClientID: latchedConsentClientID, Scopes: []string{definitions.ScopeOpenID, "profile"},
		UserCode: "ABCD-EFGH", Status: domainidp.DeviceCodeStatusPending,
		ExpiresAt: session.EvaluationTime().Add(10 * time.Minute),
	}
	deviceStore := &canonicalDeviceStoreFixture{deviceCode: "device-http-entry", request: request}
	handler, _ := newOIDCCallbackRedirectTestHandler(t)
	handler.deviceStore = deviceStore

	router := gin.New()
	router.SetHTMLTemplate(template.Must(template.New("idp_device_verify.html").Parse(
		`{{define "idp_device_verify.html"}}{{.UserCode}}|{{.DeviceCodeOnly}}|{{.PostDeviceVerifyEndpoint}}{{end}}`,
	)))
	router.GET(frontendDeviceVerifyPath,
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalProtocolEntry), handler.DeviceVerifyPageCanonical,
	)
	router.POST(frontendDeviceVerifyPath,
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalProtocolEntry), handler.DeviceVerifyCanonical,
	)

	getResponse := performCanonicalDeviceRequest(
		router, browserCookie, http.MethodGet,
		frontendDeviceVerifyPath+"?user_code="+url.QueryEscape(request.UserCode), nil,
	)
	if getResponse.Code != http.StatusOK ||
		!strings.Contains(getResponse.Body.String(), request.UserCode+"|true|"+frontendDeviceVerifyPath) {
		t.Fatalf("canonical device GET = %d %q", getResponse.Code, getResponse.Body.String())
	}

	form := url.Values{"user_code": {request.UserCode}}
	postResponse := performCanonicalDeviceRequest(
		router, browserCookie, http.MethodPost, frontendDeviceVerifyPath, form,
	)

	location, err := url.Parse(postResponse.Header().Get("Location"))
	if err != nil || postResponse.Code != http.StatusSeeOther || location.Path != frontendLoginPath {
		t.Fatalf("canonical device POST = %d %q, err = %v", postResponse.Code, postResponse.Header().Get("Location"), err)
	}

	flowID := location.Query().Get(flow.FlowTicketParameter)

	state, err := flow.NewTypedStore(
		session.Stores, session.Handle, flow.FlowProtocolOIDC, canonicalOIDCDeviceTTL,
	).Load(context.Background(), flowID)
	if err != nil || state.CurrentStep != flow.FlowStepLogin ||
		state.Metadata[flow.FlowMetadataDeviceCode] != deviceStore.deviceCode ||
		state.Metadata[flow.FlowMetadataDeviceUserCodeDigest] == "" {
		t.Fatalf("canonical device login state = %#v, err = %v", state, err)
	}

	replayResponse := performCanonicalDeviceRequest(
		router, browserCookie, http.MethodPost, frontendDeviceVerifyPath, form,
	)
	if replayResponse.Code != http.StatusConflict {
		t.Fatalf("replayed canonical device POST = %d, want %d", replayResponse.Code, http.StatusConflict)
	}
}

func TestCanonicalOIDCDeviceLifecycleClaimsBindsAndCompletesOnce(t *testing.T) {
	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)
	session := openCanonicalFixture(t, runtime, browserCookie)
	now := session.EvaluationTime()
	request := &domainidp.DeviceCodeRequest{
		ClientID: latchedConsentClientID, Scopes: []string{definitions.ScopeOpenID, "profile"},
		UserCode: "ABCD-EFGH", Status: domainidp.DeviceCodeStatusPending, ExpiresAt: now.Add(10 * time.Minute),
		UserID: "identity-42", Username: "alice", DisplayName: "Alice",
		IDTokenClaims: map[string]any{}, AccessTokenClaims: map[string]any{},
	}
	deviceStore := &canonicalDeviceStoreFixture{deviceCode: "device-code-opaque", request: request}
	handler, _ := newOIDCCallbackRedirectTestHandler(t)
	handler.deviceStore = deviceStore

	selection, err := handler.beginCanonicalOIDCDeviceVerification(
		context.Background(), session, request.UserCode,
	)
	assert.NoError(t, err)
	assert.Equal(t, flow.FlowTypeOIDCDeviceCode, selection.state.Type)
	assert.Equal(t, flow.FlowStepDeviceVerification, selection.state.CurrentStep)
	assert.Equal(t, deviceStore.deviceCode, selection.state.Metadata[flow.FlowMetadataDeviceCode])
	assert.Equal(t, request.ClientID, selection.state.Metadata[flow.FlowMetadataClientID])

	for key, value := range selection.state.Metadata {
		assert.NotContains(t, value, request.UserCode, "typed device metadata %q disclosed user code", key)
	}

	_, err = handler.beginCanonicalOIDCDeviceVerification(
		context.Background(), session, request.UserCode,
	)
	assert.ErrorIs(t, err, sessionstate.ErrNotFound)

	store := flow.NewTypedStore(session.Stores, session.Handle, flow.FlowProtocolOIDC, canonicalOIDCDeviceTTL)

	controller := flow.NewController(store)
	_, err = controller.Advance(context.Background(), selection.state.FlowID, flow.FlowStepLogin, now)
	assert.NoError(t, err)

	state, err := store.Load(context.Background(), selection.state.FlowID)
	assert.NoError(t, err)

	state.AuthOutcome = flow.AuthOutcomeOK
	assert.NoError(t, store.Save(context.Background(), state))
	_, err = controller.Advance(context.Background(), state.FlowID, flow.FlowStepConsent, now)
	assert.NoError(t, err)
	_, err = controller.Advance(context.Background(), state.FlowID, flow.FlowStepCallback, now)
	assert.NoError(t, err)

	err = handler.completeCanonicalOIDCDeviceVerification(
		context.Background(), selection, true,
	)
	assert.NoError(t, err)
	assert.Equal(t, 1, deviceStore.completed)
	assert.Equal(t, domainidp.DeviceCodeStatusAuthorized, deviceStore.request.Status)

	err = handler.completeCanonicalOIDCDeviceVerification(
		context.Background(), selection, true,
	)
	assert.True(t, errors.Is(err, sessionstate.ErrNotFound) || errors.Is(err, flow.ErrFlowNotFound))

	assertCanonicalDeviceGrant(t, session, request.ClientID, request.Scopes)
}

func TestCanonicalOIDCDeviceLoginContinuationCompletesSkipConsentClient(t *testing.T) {
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)
	session := openCanonicalFixture(t, runtime, browserCookie)
	client := latchedConsentOIDCClient()
	client.SkipConsent = true
	handler, _ := newOIDCCallbackRedirectTestHandlerWithClient(t, client)
	handler.canonicalAuthorizeUserLoader = func(
		_ *gin.Context,
		_ *cookie.CanonicalSession,
		identity cookie.SessionIdentity,
		_ *config.OIDCClient,
		_ []string,
	) (*backend.User, error) {
		return &backend.User{ID: identity.Reference, Name: identity.Account, DisplayName: identity.DisplayName}, nil
	}
	request := &domainidp.DeviceCodeRequest{
		ClientID: client.ClientID, Scopes: []string{definitions.ScopeOpenID, "profile"},
		UserCode: "SKIP-CNST", Status: domainidp.DeviceCodeStatusPending,
		ExpiresAt: session.EvaluationTime().Add(10 * time.Minute),
	}
	deviceStore := &canonicalDeviceStoreFixture{deviceCode: "device-skip-consent", request: request}
	handler.deviceStore = deviceStore

	selection, err := handler.beginCanonicalOIDCDeviceVerification(context.Background(), session, request.UserCode)
	if err != nil {
		t.Fatalf("begin canonical device verification: %v", err)
	}

	store := flow.NewTypedStore(session.Stores, session.Handle, flow.FlowProtocolOIDC, canonicalOIDCDeviceTTL)

	controller := flow.NewController(store)
	if _, err = controller.Advance(
		context.Background(), selection.state.FlowID, flow.FlowStepLogin, session.EvaluationTime(),
	); err != nil {
		t.Fatalf("advance device to login: %v", err)
	}

	state, err := store.Load(context.Background(), selection.state.FlowID)
	if err != nil {
		t.Fatalf("load device login state: %v", err)
	}

	state.AuthOutcome = flow.AuthOutcomeOK
	if err = store.Save(context.Background(), state); err != nil {
		t.Fatalf("save successful device login state: %v", err)
	}

	writer := httptest.NewRecorder()
	ctx, engine := gin.CreateTestContext(writer)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/login?flow="+selection.state.FlowID, nil)
	cookie.SetCanonicalSession(ctx, session)
	engine.SetHTMLTemplate(template.Must(template.New("idp_device_verify_success.html").Parse(
		`{{define "idp_device_verify_success.html"}}{{.DeviceVerifySuccessMessage}}{{end}}`,
	)))

	if !handler.ContinueDeviceLoginCanonical(ctx, session, state) {
		t.Fatal("canonical device login continuation was not handled")
	}

	if writer.Code != http.StatusOK || deviceStore.completed != 1 ||
		deviceStore.request.Status != domainidp.DeviceCodeStatusAuthorized {
		t.Fatalf("skip-consent continuation = %d, request %#v, completions %d", writer.Code, deviceStore.request, deviceStore.completed)
	}
}

func TestCanonicalOIDCDeviceTerminalCASFailureCreatesNoConsentGrant(t *testing.T) {
	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)
	session := openCanonicalFixture(t, runtime, browserCookie)
	request := &domainidp.DeviceCodeRequest{
		ClientID: latchedConsentClientID, Scopes: []string{definitions.ScopeOpenID, "profile"},
		UserCode: "WXYZ-MNPQ", Status: domainidp.DeviceCodeStatusPending,
		ExpiresAt: session.EvaluationTime().Add(10 * time.Minute),
		UserID:    "identity-42", Username: "alice", DisplayName: "Alice",
		IDTokenClaims: map[string]any{}, AccessTokenClaims: map[string]any{},
	}
	deviceStore := &canonicalDeviceStoreFixture{
		deviceCode: "device-code-cas-failure", request: request,
		terminalErr: sessionstate.ErrRevisionConflict,
	}
	handler, _ := newOIDCCallbackRedirectTestHandler(t)
	handler.deviceStore = deviceStore

	selection, err := handler.beginCanonicalOIDCDeviceVerification(
		context.Background(), session, request.UserCode,
	)
	if err != nil {
		t.Fatalf("begin canonical device verification: %v", err)
	}

	advanceCanonicalDeviceToCallback(t, session, selection.state.FlowID)

	if err = handler.completeCanonicalOIDCDeviceVerification(
		context.Background(), selection, true,
	); !errors.Is(err, sessionstate.ErrRevisionConflict) {
		t.Fatalf("terminal CAS failure = %v, want %v", err, sessionstate.ErrRevisionConflict)
	}

	if deviceStore.request.Status != domainidp.DeviceCodeStatusPending || !deviceStore.request.VerificationLocked {
		t.Fatalf("device after failed terminal CAS = %#v", deviceStore.request)
	}

	store := flow.NewTypedStore(session.Stores, session.Handle, flow.FlowProtocolOIDC, canonicalOIDCDeviceTTL)
	if _, err = store.Load(context.Background(), selection.state.FlowID); err != nil {
		t.Fatalf("typed flow consumed before terminal CAS: %v", err)
	}

	grantReference, err := sessionstate.ConsentGrantReference("identity-42", request.ClientID)
	if err != nil {
		t.Fatalf("derive consent reference: %v", err)
	}

	if _, err = session.Stores.Consent.Load(context.Background(), grantReference); !errors.Is(err, sessionstate.ErrNotFound) {
		t.Fatalf("orphan consent grant after terminal CAS failure: %v", err)
	}
}

func TestCanonicalOIDCDeviceConsentDenyConsumesOnlyBoundFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)
	session := openCanonicalFixture(t, runtime, browserCookie)
	request := &domainidp.DeviceCodeRequest{
		ClientID: latchedConsentClientID, Scopes: []string{definitions.ScopeOpenID, "profile"},
		UserCode: "QRST-VWXY", Status: domainidp.DeviceCodeStatusPending,
		ExpiresAt: session.EvaluationTime().Add(10 * time.Minute),
		UserID:    "identity-42", Username: "alice", DisplayName: "Alice",
	}
	deviceStore := &canonicalDeviceStoreFixture{deviceCode: "device-consent-deny", request: request}
	handler, _ := newOIDCCallbackRedirectTestHandler(t)
	handler.deviceStore = deviceStore

	selection, err := handler.beginCanonicalOIDCDeviceVerification(
		context.Background(), session, request.UserCode,
	)
	if err != nil {
		t.Fatalf("begin canonical device consent: %v", err)
	}

	advanceCanonicalDeviceToConsent(t, session, selection.state.FlowID)

	router := canonicalDeviceConsentTestRouter(runtime, handler,
		`{{define "idp_consent.html"}}{{.FlowTicket}}|{{.ClientID}}{{end}}`+
			`{{define "idp_device_verify_failed.html"}}{{.DeviceVerifyFailedMessage}}{{end}}`,
	)

	getResponse := performCanonicalDeviceRequest(
		router, browserCookie, http.MethodGet,
		frontendDeviceConsentPath+"?flow="+url.QueryEscape(selection.state.FlowID), nil,
	)
	if getResponse.Code != http.StatusOK || !strings.Contains(
		getResponse.Body.String(), selection.state.FlowID+"|"+request.ClientID,
	) {
		t.Fatalf("canonical device consent GET = %d %q", getResponse.Code, getResponse.Body.String())
	}

	form := url.Values{"flow": {selection.state.FlowID}, "submit": {"deny"}}

	postResponse := performCanonicalDeviceRequest(
		router, browserCookie, http.MethodPost, frontendDeviceConsentPath, form,
	)
	if postResponse.Code != http.StatusOK || postResponse.Body.Len() == 0 {
		t.Fatalf("canonical device consent deny = %d %q", postResponse.Code, postResponse.Body.String())
	}

	if deviceStore.request.Status != domainidp.DeviceCodeStatusDenied || deviceStore.completed != 1 {
		t.Fatalf("denied device request = %#v, completions = %d", deviceStore.request, deviceStore.completed)
	}

	replayResponse := performCanonicalDeviceRequest(
		router, browserCookie, http.MethodPost, frontendDeviceConsentPath, form,
	)
	if replayResponse.Code != http.StatusConflict {
		t.Fatalf("replayed canonical consent deny = %d, want %d", replayResponse.Code, http.StatusConflict)
	}

	assertCanonicalDeviceGrantAbsent(t, session, request.ClientID)
}

func TestCanonicalOIDCDeviceConsentAllowHydratesClaimsAndCompletes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)
	session := openCanonicalFixture(t, runtime, browserCookie)
	request := &domainidp.DeviceCodeRequest{
		ClientID: latchedConsentClientID, Scopes: []string{definitions.ScopeOpenID, "profile"},
		UserCode: "HJKM-NPQR", Status: domainidp.DeviceCodeStatusPending,
		ExpiresAt: session.EvaluationTime().Add(10 * time.Minute),
	}
	deviceStore := &canonicalDeviceStoreFixture{deviceCode: "device-consent-allow", request: request}
	handler, _ := newOIDCCallbackRedirectTestHandler(t)
	handler.deviceStore = deviceStore
	loadedIdentity := false
	handler.canonicalAuthorizeUserLoader = func(
		_ *gin.Context,
		_ *cookie.CanonicalSession,
		identity cookie.SessionIdentity,
		_ *config.OIDCClient,
		_ []string,
	) (*backend.User, error) {
		loadedIdentity = true

		return &backend.User{
			ID: identity.Reference, Name: identity.Account, DisplayName: identity.DisplayName,
		}, nil
	}

	selection, err := handler.beginCanonicalOIDCDeviceVerification(
		context.Background(), session, request.UserCode,
	)
	if err != nil {
		t.Fatalf("begin canonical device approval: %v", err)
	}

	advanceCanonicalDeviceToConsent(t, session, selection.state.FlowID)

	router := canonicalDeviceConsentTestRouter(runtime, handler,
		`{{define "idp_device_verify_success.html"}}{{.DeviceVerifySuccessMessage}}{{end}}`,
	)
	form := url.Values{
		"flow": {selection.state.FlowID}, "submit": {oidcConsentDecisionAllow}, "optional_scope": {"profile"},
	}

	postResponse := performCanonicalDeviceRequest(
		router, browserCookie, http.MethodPost, frontendDeviceConsentPath, form,
	)
	if postResponse.Code != http.StatusOK || postResponse.Body.Len() == 0 {
		t.Fatalf("canonical device consent allow = %d %q", postResponse.Code, postResponse.Body.String())
	}

	if !loadedIdentity || deviceStore.completed != 1 ||
		deviceStore.request.Status != domainidp.DeviceCodeStatusAuthorized ||
		deviceStore.request.UserID != "identity-42" || deviceStore.request.Username != "alice" ||
		deviceStore.request.IDTokenClaims == nil || deviceStore.request.AccessTokenClaims == nil {
		t.Fatalf("authorized hydrated device request = %#v, completions = %d", deviceStore.request, deviceStore.completed)
	}

	store := flow.NewTypedStore(session.Stores, session.Handle, flow.FlowProtocolOIDC, canonicalOIDCDeviceTTL)
	if _, err = store.Load(context.Background(), selection.state.FlowID); !errors.Is(err, sessionstate.ErrNotFound) {
		t.Fatalf("completed device flow remains loadable: %v", err)
	}

	assertCanonicalOIDCLogoutClient(
		t, openCanonicalFixture(t, runtime, browserCookie), latchedConsentClientID,
	)
}

func canonicalDeviceConsentTestRouter(
	runtime *cookie.CanonicalRuntime,
	handler *OIDCHandler,
	templates string,
) *gin.Engine {
	router := gin.New()
	router.SetHTMLTemplate(template.Must(template.New("canonical-device").Parse(templates)))
	router.GET(
		frontendDeviceConsentPath,
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.DeviceConsentGETCanonical,
	)
	router.POST(
		frontendDeviceConsentPath,
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.DeviceConsentPOSTCanonical,
	)

	return router
}

func assertCanonicalDeviceGrant(
	t *testing.T,
	session *cookie.CanonicalSession,
	clientID string,
	scopes []string,
) {
	t.Helper()

	grantReference, err := sessionstate.ConsentGrantReference("identity-42", clientID)
	assert.NoError(t, err)

	grant, err := session.Stores.Consent.Load(context.Background(), grantReference)
	assert.NoError(t, err)
	assert.True(t, grant.Value.Covers(scopes, session.EvaluationTime()))
}

func assertCanonicalDeviceGrantAbsent(
	t *testing.T,
	session *cookie.CanonicalSession,
	clientID string,
) {
	t.Helper()

	grantReference, err := sessionstate.ConsentGrantReference("identity-42", clientID)
	if err != nil {
		t.Fatalf("derive denied consent reference: %v", err)
	}

	if _, err = session.Stores.Consent.Load(context.Background(), grantReference); !errors.Is(err, sessionstate.ErrNotFound) {
		t.Fatalf("denied device flow persisted grant: %v", err)
	}
}

func performCanonicalDeviceRequest(
	router http.Handler,
	browserCookie *http.Cookie,
	method string,
	target string,
	form url.Values,
) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}

	request := httptest.NewRequest(method, target, body)
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	request.AddCookie(browserCookie)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	return response
}

func TestCanonicalOIDCDevicePostTerminalFailuresAreExplicitAndNonReplayable(t *testing.T) {
	t.Run("grant persistence", func(t *testing.T) {
		handler, session, selection, deviceStore := canonicalDeviceCallbackFixture(t, "grant-failure")
		handler.canonicalDeviceGrantPersister = func(
			context.Context,
			canonicalOIDCConsentSelection,
			*domainidp.OIDCSession,
		) error {
			return errCanonicalDeviceTestFailure
		}

		err := handler.completeCanonicalOIDCDeviceVerification(context.Background(), selection, true)
		assertCanonicalDevicePostTerminalFailure(
			t, err, handler, session, selection, deviceStore, false,
		)
	})

	t.Run("flow cleanup", func(t *testing.T) {
		handler, session, selection, deviceStore := canonicalDeviceCallbackFixture(t, "cleanup-failure")
		handler.canonicalDeviceFlowConsumer = func(
			context.Context,
			*flow.TypedStore,
			*flow.State,
		) error {
			return errCanonicalDeviceTestFailure
		}

		err := handler.completeCanonicalOIDCDeviceVerification(context.Background(), selection, true)
		assertCanonicalDevicePostTerminalFailure(
			t, err, handler, session, selection, deviceStore, true,
		)
	})
}

var errCanonicalDeviceTestFailure = errors.New("injected canonical device failure")

func canonicalDeviceCallbackFixture(
	t *testing.T,
	suffix string,
) (*OIDCHandler, *cookie.CanonicalSession, canonicalOIDCDeviceSelection, *canonicalDeviceStoreFixture) {
	t.Helper()

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)
	session := openCanonicalFixture(t, runtime, browserCookie)
	request := &domainidp.DeviceCodeRequest{
		ClientID: latchedConsentClientID, Scopes: []string{definitions.ScopeOpenID, "profile"},
		UserCode: "BCDE-FGHJ", Status: domainidp.DeviceCodeStatusPending,
		ExpiresAt: session.EvaluationTime().Add(10 * time.Minute),
		UserID:    "identity-42", Username: "alice", DisplayName: "Alice",
		IDTokenClaims: map[string]any{}, AccessTokenClaims: map[string]any{},
	}
	deviceStore := &canonicalDeviceStoreFixture{deviceCode: "device-" + suffix, request: request}
	handler, _ := newOIDCCallbackRedirectTestHandler(t)
	handler.deviceStore = deviceStore

	selection, err := handler.beginCanonicalOIDCDeviceVerification(
		context.Background(), session, request.UserCode,
	)
	if err != nil {
		t.Fatalf("begin terminal-failure device flow: %v", err)
	}

	advanceCanonicalDeviceToCallback(t, session, selection.state.FlowID)

	return handler, session, selection, deviceStore
}

func assertCanonicalDevicePostTerminalFailure(
	t *testing.T,
	err error,
	handler *OIDCHandler,
	session *cookie.CanonicalSession,
	selection canonicalOIDCDeviceSelection,
	deviceStore *canonicalDeviceStoreFixture,
	wantGrant bool,
) {
	t.Helper()

	if !errors.Is(err, errCanonicalOIDCDeviceTerminal) ||
		!errors.Is(err, errCanonicalDeviceTestFailure) {
		t.Fatalf("post-terminal error = %v", err)
	}

	if deviceStore.completed != 1 || deviceStore.request.Status != domainidp.DeviceCodeStatusAuthorized {
		t.Fatalf("post-terminal device = %#v, completions = %d", deviceStore.request, deviceStore.completed)
	}

	store := flow.NewTypedStore(session.Stores, session.Handle, flow.FlowProtocolOIDC, canonicalOIDCDeviceTTL)
	if _, loadErr := store.Load(context.Background(), selection.state.FlowID); loadErr != nil {
		t.Fatalf("post-terminal failure lost cleanup evidence: %v", loadErr)
	}

	grantReference, referenceErr := sessionstate.ConsentGrantReference("identity-42", latchedConsentClientID)
	if referenceErr != nil {
		t.Fatalf("derive post-terminal grant reference: %v", referenceErr)
	}

	_, grantErr := session.Stores.Consent.Load(context.Background(), grantReference)
	if wantGrant && grantErr != nil {
		t.Fatalf("flow-cleanup failure lost committed grant: %v", grantErr)
	}

	if !wantGrant && !errors.Is(grantErr, sessionstate.ErrNotFound) {
		t.Fatalf("grant-persistence failure left grant: %v", grantErr)
	}

	if replayErr := handler.completeCanonicalOIDCDeviceVerification(
		context.Background(), selection, true,
	); replayErr == nil {
		t.Fatal("post-terminal device completion replay succeeded")
	}
}

func advanceCanonicalDeviceToCallback(
	t *testing.T,
	session *cookie.CanonicalSession,
	flowID string,
) {
	t.Helper()

	advanceCanonicalDeviceToConsent(t, session, flowID)
	store := flow.NewTypedStore(session.Stores, session.Handle, flow.FlowProtocolOIDC, canonicalOIDCDeviceTTL)
	controller := flow.NewController(store)

	now := session.EvaluationTime()
	if _, err := controller.Advance(context.Background(), flowID, flow.FlowStepCallback, now); err != nil {
		t.Fatalf("advance canonical device to callback: %v", err)
	}
}

func advanceCanonicalDeviceToConsent(
	t *testing.T,
	session *cookie.CanonicalSession,
	flowID string,
) {
	t.Helper()

	store := flow.NewTypedStore(session.Stores, session.Handle, flow.FlowProtocolOIDC, canonicalOIDCDeviceTTL)
	controller := flow.NewController(store)

	now := session.EvaluationTime()
	if _, err := controller.Advance(context.Background(), flowID, flow.FlowStepLogin, now); err != nil {
		t.Fatalf("advance canonical device to login: %v", err)
	}

	state, err := store.Load(context.Background(), flowID)
	if err != nil {
		t.Fatalf("load canonical device login: %v", err)
	}

	state.AuthOutcome = flow.AuthOutcomeOK
	if err = store.Save(context.Background(), state); err != nil {
		t.Fatalf("authenticate canonical device flow: %v", err)
	}

	if _, err = controller.Advance(context.Background(), flowID, flow.FlowStepConsent, now); err != nil {
		t.Fatalf("advance canonical device to consent: %v", err)
	}
}

type canonicalDeviceStoreFixture struct {
	deviceCode  string
	request     *domainidp.DeviceCodeRequest
	claimed     bool
	completed   int
	terminalErr error
}

func (s *canonicalDeviceStoreFixture) ClaimDeviceCodeByUserCode(
	_ context.Context,
	_ string,
) (string, *domainidp.DeviceCodeRequest, error) {
	if s.claimed {
		return "", nil, sessionstate.ErrNotFound
	}

	s.claimed = true
	s.request.VerificationLocked = true
	claimed := *s.request

	return s.deviceCode, &claimed, nil
}

func (s *canonicalDeviceStoreFixture) CompleteClaimedDeviceCode(
	_ context.Context,
	deviceCode string,
	request *domainidp.DeviceCodeRequest,
) error {
	if deviceCode != s.deviceCode || request == nil || s.completed != 0 {
		return sessionstate.ErrRevisionConflict
	}

	if s.terminalErr != nil {
		return s.terminalErr
	}

	completed := *request
	s.request = &completed
	s.completed++

	return nil
}

func (s *canonicalDeviceStoreFixture) StoreDeviceCode(context.Context, string, *domainidp.DeviceCodeRequest, time.Duration) error {
	return nil
}

func (s *canonicalDeviceStoreFixture) GetDeviceCode(context.Context, string) (*domainidp.DeviceCodeRequest, error) {
	request := *s.request

	return &request, nil
}

func (s *canonicalDeviceStoreFixture) GetDeviceCodeByUserCode(context.Context, string) (string, *domainidp.DeviceCodeRequest, error) {
	return s.deviceCode, s.request, nil
}

func (s *canonicalDeviceStoreFixture) UpdateDeviceCode(context.Context, string, *domainidp.DeviceCodeRequest) error {
	return nil
}

func (s *canonicalDeviceStoreFixture) DeleteDeviceCode(context.Context, string) error { return nil }

var _ domainidp.DeviceCodeStore = (*canonicalDeviceStoreFixture)(nil)
