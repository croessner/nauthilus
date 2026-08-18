// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//nolint:gocyclo,funlen // SAML tests keep validation, assertion, terminal consume, and replay together.
package idp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/crewjam/saml"
	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/croessner/nauthilus/v3/server/idp/mfastate"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/gin-gonic/gin"
)

func TestCanonicalSAMLPolicyStartsBoundStepUpBeforeAssertion(t *testing.T) {
	const entityID = "https://sp.example.com/saml/metadata"

	handler, target, _, _ := newSAMLSSOTestFixture(t, config.SAML2ServiceProvider{
		EntityID: entityID, ACSURL: "https://sp.example.com/saml/acs", RequiredMFALevel: 2,
	}, nil)
	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	request := httptest.NewRequest(http.MethodGet, target, nil)
	parsed := parseCanonicalSAMLTestRequest(t, handler, target)
	digest := sha256.Sum256(parsed.RequestBuffer)
	binding := canonicalSAMLRequestBinding{
		EntityID: entityID, RequestID: parsed.Request.ID,
		RequestDigest: "sha256:" + hex.EncodeToString(digest[:]), RelayState: parsed.RelayState,
		Destination: parsed.Request.Destination, OriginalURL: canonicalSAMLOriginalURL(request.URL),
	}

	session := openCanonicalFixture(t, runtime, browserCookie)

	state, _, err := startCanonicalSAMLSSO(context.Background(), session, binding)
	if err != nil {
		t.Fatalf("start policy-bound canonical SAML flow: %v", err)
	}

	authenticateCanonicalFixture(t, runtime, browserCookie)
	session = openCanonicalFixture(t, runtime, browserCookie)

	identity, authenticated := session.Identity()
	if !authenticated {
		t.Fatal("canonical SAML policy fixture is not authenticated")
	}

	state, err = flow.NewTypedStore(
		session.Stores, session.Handle, flow.FlowProtocolSAML, canonicalSAMLSSOTTL,
	).Load(context.Background(), state.FlowID)
	if err != nil {
		t.Fatalf("load policy-bound canonical SAML flow: %v", err)
	}

	state.AuthOutcome = flow.AuthOutcomeOK

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, flow.AppendTicket(binding.OriginalURL, state.FlowID), nil)

	ready, err := handler.canonicalSAMLPolicyReady(ctx, session, state, identity)
	if err != nil || ready || recorder.Code != http.StatusFound {
		t.Fatalf("canonical SAML policy = ready %t status %d, err = %v", ready, recorder.Code, err)
	}

	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil || location.Path != frontendMFASelectPath {
		t.Fatalf("canonical SAML step-up target = %q, err = %v", recorder.Header().Get("Location"), err)
	}

	stepUpHandle, err := sessionstate.ParseHandle(location.Query().Get(flow.FlowTicketParameter))
	if err != nil {
		t.Fatalf("parse canonical SAML step-up ticket: %v", err)
	}

	stepUp, err := mfastate.NewAggregate(session.Stores, session.Handle, 0).
		LoadStepUp(context.Background(), stepUpHandle)
	if err != nil || stepUp.Value.Flow != sessionstate.Handle(state.FlowID) ||
		stepUp.Value.Scope != samlMFAAssuranceScope(entityID) || stepUp.Value.RequestedLevel != 2 {
		t.Fatalf("canonical SAML step-up = %#v, err = %v", stepUp.Value, err)
	}
}

func TestSAMLCanonicalAuthenticatedIssuesAssertionOnceWithoutLegacyManager(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler, target, legacyManager, _ := newSAMLSSOTestFixture(t, config.SAML2ServiceProvider{
		EntityID: "https://sp.example.com/saml/metadata",
		ACSURL:   "https://sp.example.com/saml/acs",
	}, map[string]any{definitions.SessionKeyAccount: "legacy-mallory"})
	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	request := httptest.NewRequest(http.MethodGet, target, nil)
	expectedRequest := parseCanonicalSAMLTestRequest(t, handler, target)
	digest := sha256.Sum256(expectedRequest.RequestBuffer)
	binding := canonicalSAMLRequestBinding{
		EntityID: samlAuthnRequestIssuer(expectedRequest), RequestID: expectedRequest.Request.ID,
		RequestDigest: "sha256:" + hex.EncodeToString(digest[:]), RelayState: expectedRequest.RelayState,
		Destination: expectedRequest.Request.Destination, OriginalURL: canonicalSAMLOriginalURL(request.URL),
	}

	session := openCanonicalFixture(t, runtime, browserCookie)

	state, _, err := startCanonicalSAMLSSO(context.Background(), session, binding)
	if err != nil {
		t.Fatalf("start authenticated canonical SAML flow: %v", err)
	}

	authenticateCanonicalFixture(t, runtime, browserCookie)
	session = openCanonicalFixture(t, runtime, browserCookie)
	store := flow.NewTypedStore(session.Stores, session.Handle, flow.FlowProtocolSAML, canonicalSAMLSSOTTL)

	state, err = store.Load(context.Background(), state.FlowID)
	if err != nil {
		t.Fatalf("reload authenticated canonical SAML flow: %v", err)
	}

	state.AuthOutcome = flow.AuthOutcomeOK
	if err = store.Save(context.Background(), state); err != nil {
		t.Fatalf("persist authenticated canonical SAML flow: %v", err)
	}

	lookupCalls := 0
	handler.canonicalSAMLUserLoader = func(
		_ *gin.Context,
		_ *cookie.CanonicalSession,
		identity cookie.SessionIdentity,
		sp *config.SAML2ServiceProvider,
	) (*backend.User, error) {
		lookupCalls++

		if identity.Account != "alice" || identity.Reference != "identity-42" || sp.EntityID != binding.EntityID {
			t.Fatalf("canonical SAML lookup binding = identity %#v SP %#v", identity, sp)
		}

		return &backend.User{ID: identity.Reference, Name: identity.Account, DisplayName: identity.DisplayName}, nil
	}

	router := gin.New()
	router.SetHTMLTemplate(template.Must(template.New("idp_saml_post.html").Parse(
		`{{define "idp_saml_post.html"}}{{.SAMLResponse}}{{end}}`,
	)))
	router.Use(func(ctx *gin.Context) {
		ctx.Set(definitions.CtxSecureDataKey, legacyManager)
		ctx.Next()
	})
	router.GET(
		"/saml/sso",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalProtocolEntry),
		handler.SSOCanonical,
	)

	continuation := flow.AppendTicket(canonicalSAMLOriginalURL(request.URL), state.FlowID)
	preflightRecorder := httptest.NewRecorder()
	preflightContext, _ := gin.CreateTestContext(preflightRecorder)
	preflightContext.Request = httptest.NewRequest(http.MethodGet, continuation, nil)

	continuationBinding, _, err := handler.canonicalSAMLRequestFromContext(preflightContext)
	if err != nil || continuationBinding != binding {
		t.Fatalf("canonical SAML continuation binding = %#v, want %#v, err = %v", continuationBinding, binding, err)
	}

	preflightState, err := loadCanonicalSAMLSSO(
		context.Background(), session, state.FlowID, continuationBinding,
	)
	if err != nil {
		t.Fatalf("preflight canonical SAML continuation: %v", err)
	}

	if preflightState.AuthOutcome != flow.AuthOutcomeOK || preflightState.CurrentStep != flow.FlowStepLogin {
		t.Fatalf("preflight canonical SAML state = %#v", preflightState)
	}

	response := performCanonicalSAMLRequest(router, browserCookie, continuation)
	if response.Code != http.StatusOK || response.Body.Len() == 0 || lookupCalls != 1 {
		t.Fatalf("canonical SAML assertion = %d %q, lookups = %d", response.Code, response.Body.String(), lookupCalls)
	}

	session = openCanonicalFixture(t, runtime, browserCookie)
	if len(session.Anchor.Value.SAMLFlows) != 0 {
		t.Fatalf("completed canonical SAML indexes = %v, want empty", session.Anchor.Value.SAMLFlows)
	}

	replay := performCanonicalSAMLRequest(router, browserCookie, continuation)
	if replay.Code != http.StatusConflict || lookupCalls != 1 {
		t.Fatalf("replayed canonical SAML assertion = %d, lookups = %d", replay.Code, lookupCalls)
	}

	if legacyManager.GetString(definitions.SessionKeyAccount, "") != "legacy-mallory" {
		t.Fatalf("canonical SAML assertion mutated legacy manager: %#v", legacyManager.data)
	}
}

func TestCanonicalSAMLTerminalFailuresDoNotPublishOrReplayAssertion(t *testing.T) {
	t.Run("response preparation", func(t *testing.T) {
		handler, router, browserCookie, continuation, flowID, session := canonicalSAMLTerminalFixture(t)
		consumeCalls := 0
		participantCalls := 0
		handler.canonicalSAMLPostBinder = func(*saml.IdpAuthnRequest) (saml.IdpAuthnRequestForm, error) {
			return saml.IdpAuthnRequestForm{}, errCanonicalSAMLTerminalTest
		}
		handler.canonicalSAMLFlowConsumer = func(
			context.Context,
			*cookie.CanonicalSession,
			string,
			canonicalSAMLRequestBinding,
		) (*flow.State, error) {
			consumeCalls++

			return nil, nil
		}
		handler.canonicalSAMLParticipantRegistrar = func(
			context.Context,
			string,
			string,
			*saml.Session,
		) error {
			participantCalls++

			return nil
		}

		response := performCanonicalSAMLRequest(router, browserCookie, continuation)
		if response.Code != http.StatusServiceUnavailable || response.Body.Len() != 0 ||
			consumeCalls != 0 || participantCalls != 0 {
			t.Fatalf(
				"canonical SAML response preparation failure = %d %q, consume calls = %d, participant calls = %d",
				response.Code, response.Body.String(), consumeCalls, participantCalls,
			)
		}

		store := flow.NewTypedStore(session.Stores, session.Handle, flow.FlowProtocolSAML, canonicalSAMLSSOTTL)

		remaining, err := store.Load(context.Background(), flowID)
		if err != nil || remaining.CurrentStep != flow.FlowStepLogin {
			t.Fatalf("canonical SAML pre-terminal failure evidence = %#v, err = %v", remaining, err)
		}
	})

	t.Run("flow consume", func(t *testing.T) {
		handler, router, browserCookie, continuation, flowID, session := canonicalSAMLTerminalFixture(t)
		participantCalls := 0
		handler.canonicalSAMLParticipantRegistrar = func(
			context.Context,
			string,
			string,
			*saml.Session,
		) error {
			participantCalls++

			return nil
		}
		handler.canonicalSAMLFlowConsumer = func(
			context.Context,
			*cookie.CanonicalSession,
			string,
			canonicalSAMLRequestBinding,
		) (*flow.State, error) {
			return nil, sessionstate.ErrRevisionConflict
		}

		response := performCanonicalSAMLRequest(router, browserCookie, continuation)
		if response.Code != http.StatusConflict || response.Body.Len() != 0 || participantCalls != 0 {
			t.Fatalf(
				"canonical SAML terminal CAS failure = %d %q, participant calls = %d",
				response.Code, response.Body.String(), participantCalls,
			)
		}

		store := flow.NewTypedStore(session.Stores, session.Handle, flow.FlowProtocolSAML, canonicalSAMLSSOTTL)

		remaining, err := store.Load(context.Background(), flowID)
		if err != nil || remaining.CurrentStep != flow.FlowStepCallback {
			t.Fatalf("canonical SAML terminal CAS evidence = %#v, err = %v", remaining, err)
		}
	})

	t.Run("participant persistence after consume", func(t *testing.T) {
		handler, router, browserCookie, continuation, flowID, session := canonicalSAMLTerminalFixture(t)
		participantCalls := 0
		handler.canonicalSAMLParticipantRegistrar = func(
			context.Context,
			string,
			string,
			*saml.Session,
		) error {
			participantCalls++

			return errCanonicalSAMLTerminalTest
		}

		response := performCanonicalSAMLRequest(router, browserCookie, continuation)
		if response.Code != http.StatusServiceUnavailable || response.Body.Len() != 0 || participantCalls != 1 {
			t.Fatalf(
				"canonical SAML participant failure = %d %q, participant calls = %d",
				response.Code, response.Body.String(), participantCalls,
			)
		}

		replay := performCanonicalSAMLRequest(router, browserCookie, continuation)
		if replay.Code != http.StatusConflict || replay.Body.Len() != 0 || participantCalls != 1 {
			t.Fatalf(
				"canonical SAML post-terminal replay = %d %q, participant calls = %d",
				replay.Code, replay.Body.String(), participantCalls,
			)
		}

		store := flow.NewTypedStore(session.Stores, session.Handle, flow.FlowProtocolSAML, canonicalSAMLSSOTTL)
		if _, err := store.Load(context.Background(), flowID); !errors.Is(err, sessionstate.ErrNotFound) {
			t.Fatalf("canonical SAML post-terminal flow load error = %v, want not found", err)
		}
	})
}

func TestSLOCanonicalRevokesTypedSessionWithoutLegacyManager(t *testing.T) {
	fixture := newSignedRedirectSLOFixture(t, "id-canonical-slo", "relay-canonical", "_idx-canonical", nil)
	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)

	legacyManager := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyAccount:   "legacy-mallory",
		definitions.SessionKeyIDPFlowID: "legacy-flow",
	}}

	router := gin.New()
	router.Use(func(ctx *gin.Context) {
		ctx.Set(definitions.CtxSecureDataKey, legacyManager)
		ctx.Next()
	})
	router.GET(
		frontendSAMLLogoutPath,
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalProtocolEntry),
		fixture.handler.SLOCanonical,
	)

	response := performCanonicalSAMLRequest(router, browserCookie, fixture.target)
	if response.Code != http.StatusFound {
		t.Fatalf("canonical SLO response = %d %q", response.Code, response.Body.String())
	}

	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Query().Get("SAMLResponse") == "" {
		t.Fatalf("canonical SLO response target = %q, err = %v", response.Header().Get("Location"), err)
	}

	request := httptest.NewRequest(http.MethodGet, frontendLoginPath, nil)
	request.AddCookie(browserCookie)

	if _, err = runtime.Open(context.Background(), request); !errors.Is(err, cookie.ErrEnvelopeRejected) {
		t.Fatalf("canonical SLO revoked session open error = %v, want envelope rejected", err)
	}

	if legacyManager.GetString(definitions.SessionKeyAccount, "") != "legacy-mallory" ||
		legacyManager.GetString(definitions.SessionKeyIDPFlowID, "") != "legacy-flow" {
		t.Fatalf("canonical SLO mutated legacy manager: %#v", legacyManager.data)
	}

	deleted := response.Result().Cookies()
	if len(deleted) != 2 || deleted[0].MaxAge >= 0 || deleted[1].MaxAge >= 0 {
		t.Fatalf("canonical SLO browser purge = %#v", deleted)
	}

	if err = fixture.mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("canonical SLO registry expectations: %v", err)
	}
}

var errCanonicalSAMLTerminalTest = errors.New("injected canonical SAML terminal failure")

func canonicalSAMLTerminalFixture(
	t *testing.T,
) (*SAMLHandler, *gin.Engine, *http.Cookie, string, string, *cookie.CanonicalSession) {
	t.Helper()

	handler, target, _, _ := newSAMLSSOTestFixture(t, config.SAML2ServiceProvider{
		EntityID: "https://sp.example.com/saml/metadata",
		ACSURL:   "https://sp.example.com/saml/acs",
	}, nil)
	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	request := httptest.NewRequest(http.MethodGet, target, nil)
	parsed := parseCanonicalSAMLTestRequest(t, handler, target)
	digest := sha256.Sum256(parsed.RequestBuffer)
	binding := canonicalSAMLRequestBinding{
		EntityID: samlAuthnRequestIssuer(parsed), RequestID: parsed.Request.ID,
		RequestDigest: "sha256:" + hex.EncodeToString(digest[:]), RelayState: parsed.RelayState,
		Destination: parsed.Request.Destination, OriginalURL: canonicalSAMLOriginalURL(request.URL),
	}

	session := openCanonicalFixture(t, runtime, browserCookie)

	state, _, err := startCanonicalSAMLSSO(context.Background(), session, binding)
	if err != nil {
		t.Fatalf("start canonical SAML terminal fixture: %v", err)
	}

	authenticateCanonicalFixture(t, runtime, browserCookie)
	session = openCanonicalFixture(t, runtime, browserCookie)
	store := flow.NewTypedStore(session.Stores, session.Handle, flow.FlowProtocolSAML, canonicalSAMLSSOTTL)

	state, err = store.Load(context.Background(), state.FlowID)
	if err != nil {
		t.Fatalf("load canonical SAML terminal fixture: %v", err)
	}

	state.AuthOutcome = flow.AuthOutcomeOK
	if err = store.Save(context.Background(), state); err != nil {
		t.Fatalf("persist canonical SAML terminal fixture: %v", err)
	}

	handler.canonicalSAMLUserLoader = func(
		_ *gin.Context,
		_ *cookie.CanonicalSession,
		identity cookie.SessionIdentity,
		_ *config.SAML2ServiceProvider,
	) (*backend.User, error) {
		return &backend.User{ID: identity.Reference, Name: identity.Account}, nil
	}

	router := gin.New()
	router.SetHTMLTemplate(template.Must(template.New("idp_saml_post.html").Parse(
		`{{define "idp_saml_post.html"}}{{.SAMLResponse}}{{end}}`,
	)))
	router.GET(
		"/saml/sso",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalProtocolEntry),
		handler.SSOCanonical,
	)

	return handler, router, browserCookie,
		flow.AppendTicket(canonicalSAMLOriginalURL(request.URL), state.FlowID), state.FlowID, session
}

func performCanonicalSAMLRequest(
	router http.Handler,
	browserCookie *http.Cookie,
	target string,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.AddCookie(browserCookie)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	return response
}

func TestSAMLCanonicalProtocolEntryStartsTypedFlowWithoutLegacyManager(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler, target, legacyManager, _ := newSAMLSSOTestFixture(t, config.SAML2ServiceProvider{
		EntityID: "https://sp.example.com/saml/metadata",
		ACSURL:   "https://sp.example.com/saml/acs",
	}, map[string]any{
		definitions.SessionKeyAccount:         "legacy-mallory",
		definitions.SessionKeyIDPFlowID:       "legacy-flow",
		definitions.SessionKeyIDPSAMLEntityID: "https://legacy-sp.example.test/metadata",
	})
	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)

	expectedRequest := parseCanonicalSAMLTestRequest(t, handler, target)
	router := gin.New()
	router.Use(func(ctx *gin.Context) {
		ctx.Set(definitions.CtxSecureDataKey, legacyManager)
		ctx.Next()
	})
	router.GET(
		"/saml/sso",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalProtocolEntry),
		handler.SSOCanonical,
	)

	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.AddCookie(browserCookie)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || response.Code != http.StatusFound || location.Path != frontendLoginPath {
		t.Fatalf("canonical SAML protocol entry = %d %q, err = %v", response.Code, response.Header().Get("Location"), err)
	}

	flowID := location.Query().Get(flow.FlowTicketParameter)
	session := openCanonicalFixture(t, runtime, browserCookie)

	state, err := flow.NewTypedStore(
		session.Stores, session.Handle, flow.FlowProtocolSAML, canonicalSAMLSSOTTL,
	).Load(context.Background(), flowID)
	if err != nil {
		t.Fatalf("load canonical SAML protocol entry: %v", err)
	}

	digest := sha256.Sum256(expectedRequest.RequestBuffer)
	binding := canonicalSAMLRequestBinding{
		EntityID:      samlAuthnRequestIssuer(expectedRequest),
		RequestID:     expectedRequest.Request.ID,
		RequestDigest: "sha256:" + hex.EncodeToString(digest[:]),
		RelayState:    expectedRequest.RelayState,
		Destination:   expectedRequest.Request.Destination,
		OriginalURL:   canonicalSAMLOriginalURL(request.URL),
	}
	assertCanonicalSAMLRequestBinding(t, state, binding)

	if legacyManager.GetString(definitions.SessionKeyIDPFlowID, "") != "legacy-flow" ||
		legacyManager.GetString(definitions.SessionKeyAccount, "") != "legacy-mallory" {
		t.Fatalf("canonical SAML entry mutated legacy manager: %#v", legacyManager.data)
	}
}

func parseCanonicalSAMLTestRequest(t *testing.T, handler *SAMLHandler, target string) *saml.IdpAuthnRequest {
	t.Helper()

	provider, err := handler.getSAMLIDP()
	if err != nil {
		t.Fatalf("create test SAML identity provider: %v", err)
	}

	request, err := saml.NewIdpAuthnRequest(provider, httptest.NewRequest(http.MethodGet, target, nil))
	if err != nil {
		t.Fatalf("parse test SAML request: %v", err)
	}

	if err = request.Validate(); err != nil {
		t.Fatalf("validate test SAML request: %v", err)
	}

	return request
}

func TestCanonicalSAMLSSOLifecycleBindsValidatedRequestAndConsumesOnce(t *testing.T) {
	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	session := openCanonicalFixture(t, runtime, browserCookie)
	binding := canonicalSAMLRequestBinding{
		EntityID:      "https://sp.example.test/metadata",
		RequestID:     "saml-request-42",
		RequestDigest: "sha256:validated-request-digest",
		RelayState:    "relay-state-42",
		Destination:   "https://idp.example.test/saml/sso",
		OriginalURL:   "/saml/sso?SAMLRequest=opaque&RelayState=relay-state-42",
	}

	state, target, err := startCanonicalSAMLSSO(context.Background(), session, binding)
	if err != nil {
		t.Fatalf("start canonical SAML SSO: %v", err)
	}

	location, err := url.Parse(target)
	if err != nil || location.Path != frontendLoginPath || location.Query().Get(flow.FlowTicketParameter) != state.FlowID {
		t.Fatalf("canonical SAML login target = %q, err = %v", target, err)
	}

	loaded, err := loadCanonicalSAMLSSO(context.Background(), session, state.FlowID, binding)
	if err != nil {
		t.Fatalf("load canonical SAML SSO: %v", err)
	}

	assertCanonicalSAMLRequestBinding(t, loaded, binding)

	tampered := binding

	tampered.RelayState = "relay-state-tampered"
	if _, err = loadCanonicalSAMLSSO(
		context.Background(), session, state.FlowID, tampered,
	); !errors.Is(err, sessionstate.ErrBindingMismatch) {
		t.Fatalf("tampered SAML request binding error = %v, want binding mismatch", err)
	}

	store := flow.NewTypedStore(session.Stores, session.Handle, flow.FlowProtocolSAML, canonicalSAMLSSOTTL)

	loaded.AuthOutcome = flow.AuthOutcomeOK
	if err = store.Save(context.Background(), loaded); err != nil {
		t.Fatalf("persist canonical SAML authentication outcome: %v", err)
	}

	if _, err = flow.NewController(store).Advance(
		context.Background(), state.FlowID, flow.FlowStepCallback, session.EvaluationTime(),
	); err != nil {
		t.Fatalf("advance canonical SAML SSO to callback: %v", err)
	}

	consumed, err := consumeCanonicalSAMLSSO(context.Background(), session, state.FlowID, binding)
	if err != nil {
		t.Fatalf("consume canonical SAML SSO: %v", err)
	}

	assertCanonicalSAMLRequestBinding(t, consumed, binding)

	if _, err = consumeCanonicalSAMLSSO(
		context.Background(), session, state.FlowID, binding,
	); !errors.Is(err, sessionstate.ErrNotFound) {
		t.Fatalf("replayed canonical SAML consume error = %v, want not found", err)
	}
}

func assertCanonicalSAMLRequestBinding(
	t *testing.T,
	state *flow.State,
	binding canonicalSAMLRequestBinding,
) {
	t.Helper()

	if state == nil || state.Type != flow.FlowTypeSAML || state.Protocol != flow.FlowProtocolSAML ||
		state.Metadata[flow.FlowMetadataSAMLEntityID] != binding.EntityID ||
		state.Metadata[flow.FlowMetadataSAMLRequestID] != binding.RequestID ||
		state.Metadata[flow.FlowMetadataSAMLRequestDigest] != binding.RequestDigest ||
		state.Metadata[flow.FlowMetadataSAMLRelayState] != binding.RelayState ||
		state.Metadata[flow.FlowMetadataSAMLDestination] != binding.Destination ||
		state.Metadata[flow.FlowMetadataOriginalURL] != binding.OriginalURL ||
		state.Metadata[flow.FlowMetadataResumeTarget] != binding.OriginalURL {
		t.Fatalf("canonical SAML request binding = %#v, want %#v", state, binding)
	}
}
