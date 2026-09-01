// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//nolint:gocyclo,funlen // Login-policy tests keep each parent-bound lifecycle in one security contract.
package idp

import (
	"context"
	"errors"
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
	"github.com/croessner/nauthilus/v4/server/sessionstate"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

type canonicalLoginClock struct {
	now time.Time
}

func (c canonicalLoginClock) Now() time.Time { return c.now }

func TestLoginFlowValidationUsesCanonicalTypedOIDCState(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, flowID := seedCanonicalLoginFlow(t)

	router := gin.New()
	router.GET("/login", cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation), assertCanonicalLoginFlow)

	request := httptest.NewRequest(http.MethodGet, "/login?flow="+flowID, nil)
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	if writer.Code != http.StatusNoContent {
		t.Fatalf("canonical login validation status = %d, want %d", writer.Code, http.StatusNoContent)
	}
}

func TestCanonicalAuthMiddlewareUsesOnlyTypedIdentity(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	t.Run("authenticated canonical identity is allowed", func(t *testing.T) {
		runtime, browserCookie, _ := seedCanonicalLoginFlow(t)
		authenticateCanonicalFixture(t, runtime, browserCookie)

		router := gin.New()
		router.GET(
			"/mfa/register/home",
			cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
			(&FrontendHandler{}).CanonicalAuthMiddleware(),
			func(ctx *gin.Context) { ctx.Status(http.StatusNoContent) },
		)

		request := httptest.NewRequest(http.MethodGet, "/mfa/register/home", nil)
		request.AddCookie(browserCookie)

		writer := httptest.NewRecorder()
		router.ServeHTTP(writer, request)

		if writer.Code != http.StatusNoContent {
			t.Fatalf("authenticated canonical route status = %d, want %d", writer.Code, http.StatusNoContent)
		}
	})

	t.Run("legacy identity cannot replace missing canonical session", func(t *testing.T) {
		router := gin.New()
		router.Use(func(ctx *gin.Context) {
			ctx.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: map[string]any{
				definitions.SessionKeyAccount: "alice",
			}})
		})
		router.GET(
			"/mfa/register/home",
			(&FrontendHandler{}).CanonicalAuthMiddleware(),
			func(ctx *gin.Context) { ctx.Status(http.StatusNoContent) },
		)

		writer := httptest.NewRecorder()
		router.ServeHTTP(writer, httptest.NewRequest(http.MethodGet, "/mfa/register/home", nil))

		if writer.Code != http.StatusUnauthorized {
			t.Fatalf("legacy-only route status = %d, want %d", writer.Code, http.StatusUnauthorized)
		}
	})

	t.Run("unauthenticated canonical anchor is rejected", func(t *testing.T) {
		runtime, browserCookie, _ := seedCanonicalLoginFlow(t)
		router := gin.New()
		router.GET(
			"/mfa/register/home",
			cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
			(&FrontendHandler{}).CanonicalAuthMiddleware(),
			func(ctx *gin.Context) { ctx.Status(http.StatusNoContent) },
		)

		request := httptest.NewRequest(http.MethodGet, "/mfa/register/home", nil)
		request.AddCookie(browserCookie)

		writer := httptest.NewRecorder()
		router.ServeHTTP(writer, request)

		if writer.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated canonical route status = %d, want %d", writer.Code, http.StatusUnauthorized)
		}
	})
}

func seedCanonicalLoginFlow(t *testing.T) (*cookie.CanonicalRuntime, *http.Cookie, string) {
	t.Helper()

	flowID := "PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP"

	return seedCanonicalIDPFlow(t, &flowdomain.State{
		FlowID: flowID, Type: flowdomain.FlowTypeOIDCAuthorization, Protocol: flowdomain.FlowProtocolOIDC,
		CurrentStep: flowdomain.FlowStepLogin, AuthOutcome: flowdomain.AuthOutcomeUnknown,
		ReturnTarget: "/oidc/authorize?client_id=client-a",
		Metadata: map[string]string{
			flowdomain.FlowMetadataClientID: "client-a", flowdomain.FlowMetadataRedirectURI: "https://client.example.test/callback",
			flowdomain.FlowMetadataResponseType: "code",
		},
	})
}

func TestCanonicalResumeRedirectUsesOnlyRotatedTypedFlow(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, flowID := seedCanonicalLoginFlow(t)
	router := gin.New()
	router.GET("/login", cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation), func(ctx *gin.Context) {
		handler := &FrontendHandler{}

		state, ok := handler.canonicalIDPFlow(ctx)
		if !ok || !handler.resumeCanonicalIDPFlow(ctx, cookie.GetCanonicalSession(ctx), state) {
			ctx.Status(http.StatusConflict)
		}
	})

	request := httptest.NewRequest(http.MethodGet, "/login?flow="+flowID, nil)
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	if writer.Code != http.StatusFound {
		t.Fatalf("canonical resume status = %d, want %d", writer.Code, http.StatusFound)
	}

	want := "/oidc/authorize?client_id=client-a&flow=" + flowID
	if location := writer.Header().Get("Location"); location != want {
		t.Fatalf("canonical resume location = %q, want %q", location, want)
	}
}

func TestCanonicalRequiredMFAEnrollmentPersistsTypedParentBindingBeforeRedirect(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, flowID := seedCanonicalLoginFlow(t)
	authenticateCanonicalFixture(t, runtime, browserCookie)

	router := gin.New()
	router.GET("/login", cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation), func(ctx *gin.Context) {
		handler := &FrontendHandler{}
		session := cookie.GetCanonicalSession(ctx)
		state, ok := handler.canonicalIDPFlow(ctx)
		identity, authenticated := session.Identity()

		if !ok || !authenticated || !handler.startCanonicalRequiredMFAEnrollment(
			ctx, session, state, identity, []string{"totp", "webauthn"},
		) {
			ctx.Status(http.StatusConflict)
		}
	})

	request := httptest.NewRequest(http.MethodGet, "/login?flow="+flowID, nil)
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	if writer.Code != http.StatusFound {
		t.Fatalf("typed enrollment status = %d, want %d", writer.Code, http.StatusFound)
	}

	location, err := url.Parse(writer.Header().Get("Location"))
	if err != nil || location.Path != "/mfa/totp/register" {
		t.Fatalf("typed enrollment location = %q, err = %v", writer.Header().Get("Location"), err)
	}

	handle, err := sessionstate.ParseHandle(location.Query().Get(flowdomain.FlowTicketParameter))
	if err != nil {
		t.Fatalf("parse enrollment ticket: %v", err)
	}

	request = httptest.NewRequest(http.MethodGet, "/login?flow="+flowID, nil)
	request.AddCookie(browserCookie)

	session, err := runtime.Open(context.Background(), request)
	if err != nil {
		t.Fatalf("reopen canonical session: %v", err)
	}

	loaded, err := mfastate.NewAggregate(session.Stores, session.Handle, 0).
		LoadEnrollment(context.Background(), handle)
	if err != nil || loaded.Value.Flow != sessionstate.Handle(flowID) ||
		loaded.Value.IdentityReference != "identity-42" || loaded.Value.CurrentStep != "totp" {
		t.Fatalf("typed enrollment = %#v, err = %v", loaded, err)
	}
}

// TestCanonicalStateWriteStatusPreservesConflictSemantics proves stale writers remain retry-safe conflicts.
func TestCanonicalStateWriteStatusPreservesConflictSemantics(t *testing.T) {
	tests := []struct {
		err  error
		want int
		name string
	}{
		{name: "revision conflict", err: sessionstate.ErrRevisionConflict, want: http.StatusConflict},
		{name: "revoked", err: sessionstate.ErrRevoked, want: http.StatusConflict},
		{name: "missing stale state", err: sessionstate.ErrNotFound, want: http.StatusConflict},
		{name: "storage failure", err: errors.New("storage unavailable"), want: http.StatusServiceUnavailable},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := canonicalStateWriteStatus(test.err); got != test.want {
				t.Fatalf("canonicalStateWriteStatus() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestCanonicalFlowMFAPolicyUsesOnlyTypedProtocolIdentifiers(t *testing.T) {
	t.Parallel()

	handler := &FrontendHandler{deps: &deps.Deps{Cfg: &mockFrontendCfg{FileSettings: config.FileSettings{
		IDP: &config.IDPSection{
			OIDC: config.OIDCConfig{Clients: []config.OIDCClient{{
				ClientID: "client-a", RequireMFA: []string{definitions.MFAMethodTOTP},
				SupportedMFA: []string{definitions.MFAMethodTOTP, definitions.MFAMethodWebAuthn}, RequiredMFALevel: 2,
			}}},
			SAML2: config.SAML2Config{ServiceProviders: []config.SAML2ServiceProvider{{
				EntityID: "sp-a", RequireMFA: []string{definitions.MFAMethodWebAuthn},
				SupportedMFA: []string{definitions.MFAMethodWebAuthn}, RequiredMFALevel: 3,
			}}},
		},
	}}}}

	tests := []struct {
		name      string
		state     *flowdomain.State
		wantScope string
		wantLevel int
		want      string
		ok        bool
	}{
		{
			name: "OIDC", state: &flowdomain.State{Protocol: flowdomain.FlowProtocolOIDC,
				Metadata: map[string]string{flowdomain.FlowMetadataClientID: "client-a"}},
			wantScope: "oidc:client-a", wantLevel: 2, want: definitions.MFAMethodTOTP, ok: true,
		},
		{
			name: "SAML", state: &flowdomain.State{Protocol: flowdomain.FlowProtocolSAML,
				Metadata: map[string]string{flowdomain.FlowMetadataSAMLEntityID: "sp-a"}},
			wantScope: "saml:sp-a", wantLevel: 3, want: definitions.MFAMethodWebAuthn, ok: true,
		},
		{
			name: "unknown OIDC client fails closed", state: &flowdomain.State{Protocol: flowdomain.FlowProtocolOIDC,
				Metadata: map[string]string{flowdomain.FlowMetadataClientID: "unknown"}},
		},
		{name: "missing typed identifier fails closed", state: &flowdomain.State{Protocol: flowdomain.FlowProtocolSAML}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, ok := handler.canonicalFlowMFAPolicy(context.Background(), test.state)
			if ok != test.ok {
				t.Fatalf("canonical policy ok = %t, want %t", ok, test.ok)
			}

			if !ok {
				return
			}

			if policy.scope != test.wantScope || policy.requiredLevel != test.wantLevel ||
				len(policy.required) != 1 || policy.required[0] != test.want {
				t.Fatalf("canonical policy = %#v", policy)
			}
		})
	}
}

func TestCanonicalSessionMFAPolicyRequiresLiveMatchingAssurance(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, _ := seedCanonicalLoginFlow(t)
	authenticateCanonicalFixture(t, runtime, browserCookie)
	session := openCanonicalFixture(t, runtime, browserCookie)
	now := time.Date(2026, time.August, 17, 12, 0, 0, 0, time.UTC)

	if !canonicalSessionSatisfiesMFAPolicy(session, canonicalMFAPolicy{}, now) {
		t.Fatal("policy-free canonical session should not require assurance")
	}

	policy := canonicalMFAPolicy{required: []string{definitions.MFAMethodTOTP}, scope: "oidc:client-a", requiredLevel: 2}
	if canonicalSessionSatisfiesMFAPolicy(session, policy, now) {
		t.Fatal("missing canonical assurance satisfied MFA policy")
	}

	if err := session.CommitAssurance(context.Background(), cookie.SessionAssurance{
		Level: 2, Method: definitions.MFAMethodTOTP, Scope: "", ProvenAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("commit canonical assurance: %v", err)
	}

	if !canonicalSessionSatisfiesMFAPolicy(session, policy, now) {
		t.Fatal("live unscoped canonical assurance did not satisfy SSO policy")
	}

	policy.required = []string{definitions.MFAMethodWebAuthn}
	if canonicalSessionSatisfiesMFAPolicy(session, policy, now) {
		t.Fatal("wrong canonical MFA method satisfied policy")
	}

	policy.required = nil

	policy.requiredLevel = 3
	if canonicalSessionSatisfiesMFAPolicy(session, policy, now) {
		t.Fatal("lower canonical assurance level satisfied policy")
	}

	policy.requiredLevel = 2
	if canonicalSessionSatisfiesMFAPolicy(session, policy, now.Add(6*time.Minute)) {
		t.Fatal("expired canonical assurance satisfied policy")
	}
}

func TestCanonicalMFAStepUpPersistsTypedParentBindingBeforeRedirect(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, flowID := seedCanonicalLoginFlow(t)
	authenticateCanonicalFixture(t, runtime, browserCookie)

	router := gin.New()
	router.GET("/login", cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation), func(ctx *gin.Context) {
		handler := &FrontendHandler{}
		session := cookie.GetCanonicalSession(ctx)
		state, ok := handler.canonicalIDPFlow(ctx)
		identity, authenticated := session.Identity()

		policy := canonicalMFAPolicy{
			required:  []string{definitions.MFAMethodTOTP},
			supported: []string{definitions.MFAMethodTOTP, definitions.MFAMethodWebAuthn},
			scope:     "oidc:client-a", requiredLevel: 2,
		}
		if !ok || !authenticated || !handler.startCanonicalMFAAssuranceStepUp(ctx, session, state, identity, policy) {
			ctx.Status(http.StatusConflict)
		}
	})

	request := httptest.NewRequest(http.MethodGet, "/login?flow="+flowID, nil)
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	if writer.Code != http.StatusFound {
		t.Fatalf("typed step-up status = %d, want %d", writer.Code, http.StatusFound)
	}

	location, err := url.Parse(writer.Header().Get("Location"))
	if err != nil || location.Path != "/login/mfa" {
		t.Fatalf("typed step-up location = %q, err = %v", writer.Header().Get("Location"), err)
	}

	handle, err := sessionstate.ParseHandle(location.Query().Get(flowdomain.FlowTicketParameter))
	if err != nil {
		t.Fatalf("parse step-up ticket: %v", err)
	}

	session := openCanonicalFixture(t, runtime, browserCookie)

	loaded, err := mfastate.NewAggregate(session.Stores, session.Handle, 0).LoadStepUp(context.Background(), handle)
	if err != nil || loaded.Value.Flow != sessionstate.Handle(flowID) || loaded.Value.Scope != "oidc:client-a" ||
		loaded.Value.RequestedLevel != 2 || len(loaded.Value.SupportedMethods) != 2 {
		t.Fatalf("typed step-up = %#v, err = %v", loaded, err)
	}
}

func TestCanonicalExistingLoginSessionDecisionOrdersPolicyWithoutLegacyFallback(t *testing.T) {
	t.Parallel()

	tests := []canonicalExistingLoginDecisionCase{
		{name: "no policy resumes typed flow", wantLocationPart: "/oidc/authorize"},
		{
			name: "missing enrollment starts typed enrollment", required: []string{definitions.MFAMethodTOTP},
			missing: []string{definitions.MFAMethodTOTP}, wantLocationPart: "/mfa/totp/register",
			wantEnrollments: 1, resolverMustRun: true,
		},
		{
			name: "insufficient assurance starts typed step-up", required: []string{definitions.MFAMethodTOTP},
			wantLocationPart: "/login/mfa", wantStepUps: 1, resolverMustRun: true,
		},
		{
			name: "sufficient assurance resumes typed flow", required: []string{definitions.MFAMethodTOTP},
			assurance: &cookie.SessionAssurance{
				Level: 1, Method: definitions.MFAMethodTOTP, Scope: "oidc:client-a",
			},
			wantLocationPart: "/oidc/authorize", resolverMustRun: true,
		},
		{
			name:     "prompt none returns interaction required without UI state",
			required: []string{definitions.MFAMethodTOTP}, missing: []string{definitions.MFAMethodTOTP},
			prompt: "none", wantLocationPart: "error=interaction_required&state=state-a", resolverMustRun: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runCanonicalExistingLoginDecisionCase(t, test)
		})
	}
}

func TestCanonicalLoginErrorPresentationIsRequestLocal(t *testing.T) {
	t.Parallel()

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/login", nil)
	ctx.Set(canonicalLoginErrorContextKey, "Invalid login or password")

	data := gin.H{}

	canonicalLoginRedirectHandler().applyLoginErrorData(ctx, data)

	if haveError, _ := data["HaveError"].(bool); !haveError || data["ErrorMessage"] == "" {
		t.Fatalf("request-local login error data = %#v", data)
	}
}

type canonicalExistingLoginDecisionCase struct {
	name             string
	required         []string
	missing          []string
	assurance        *cookie.SessionAssurance
	prompt           string
	wantLocationPart string
	wantEnrollments  int
	wantStepUps      int
	resolverMustRun  bool
	requiredMFALevel int
}

func runCanonicalExistingLoginDecisionCase(t *testing.T, test canonicalExistingLoginDecisionCase) {
	t.Helper()

	state := canonicalDecisionOIDCState(test.prompt)
	runtime, browserCookie, flowID := seedCanonicalIDPFlow(t, state)
	authenticateCanonicalFixture(t, runtime, browserCookie)

	commitCanonicalDecisionAssurance(t, runtime, browserCookie, test.assurance)

	resolverCalls := 0
	handler := canonicalDecisionHandler(test.required, test.requiredMFALevel, func(
		_ *gin.Context, _ *cookie.CanonicalSession, _ *flowdomain.State, _ cookie.SessionIdentity, _ []string,
	) ([]string, error) {
		resolverCalls++

		return append([]string(nil), test.missing...), nil
	})
	router := gin.New()
	router.GET("/login", cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation), func(ctx *gin.Context) {
		loaded, ok := handler.canonicalIDPFlow(ctx)
		if !ok || !handler.resumeCanonicalExistingLoginSession(ctx, cookie.GetCanonicalSession(ctx), loaded) {
			ctx.Status(http.StatusConflict)
		}
	})

	request := httptest.NewRequest(http.MethodGet, "/login?flow="+flowID, nil)
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	assertCanonicalExistingLoginDecision(t, test, writer, resolverCalls, runtime, browserCookie)
}

func commitCanonicalDecisionAssurance(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	assurance *cookie.SessionAssurance,
) {
	t.Helper()

	if assurance == nil {
		return
	}

	session := openCanonicalFixture(t, runtime, browserCookie)
	proof := *assurance
	proof.ProvenAt = session.EvaluationTime()
	proof.ExpiresAt = proof.ProvenAt.Add(5 * time.Minute)

	if err := session.CommitAssurance(context.Background(), proof); err != nil {
		t.Fatalf("commit assurance: %v", err)
	}
}

func assertCanonicalExistingLoginDecision(
	t *testing.T,
	test canonicalExistingLoginDecisionCase,
	writer *httptest.ResponseRecorder,
	resolverCalls int,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
) {
	t.Helper()

	if writer.Code != http.StatusFound || !strings.Contains(writer.Header().Get("Location"), test.wantLocationPart) {
		t.Fatalf("decision status/location = %d %q, want redirect containing %q",
			writer.Code, writer.Header().Get("Location"), test.wantLocationPart)
	}

	if (resolverCalls > 0) != test.resolverMustRun {
		t.Fatalf("enrollment resolver calls = %d, required = %t", resolverCalls, test.resolverMustRun)
	}

	session := openCanonicalFixture(t, runtime, browserCookie)
	if len(session.Anchor.Value.Enrollments) != test.wantEnrollments || len(session.Anchor.Value.StepUps) != test.wantStepUps {
		t.Fatalf("decision indexes = enrollments %d step-ups %d, want %d/%d",
			len(session.Anchor.Value.Enrollments), len(session.Anchor.Value.StepUps), test.wantEnrollments, test.wantStepUps)
	}
}

func canonicalDecisionOIDCState(prompt string) *flowdomain.State {
	return &flowdomain.State{
		FlowID: "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ", Type: flowdomain.FlowTypeOIDCAuthorization,
		Protocol: flowdomain.FlowProtocolOIDC, CurrentStep: flowdomain.FlowStepLogin,
		AuthOutcome: flowdomain.AuthOutcomeOK, ReturnTarget: "/oidc/authorize?client_id=client-a",
		Metadata: map[string]string{
			flowdomain.FlowMetadataClientID: "client-a", flowdomain.FlowMetadataRedirectURI: "https://client.example.test/callback",
			flowdomain.FlowMetadataResponseType: oidcParamCode, flowdomain.FlowMetadataState: "state-a",
			flowdomain.FlowMetadataPrompt: prompt,
		},
	}
}

func canonicalDecisionHandler(
	required []string,
	requiredLevel int,
	resolver canonicalEnrollmentResolver,
) *FrontendHandler {
	return &FrontendHandler{
		deps: &deps.Deps{Cfg: &mockFrontendCfg{FileSettings: config.FileSettings{IDP: &config.IDPSection{
			OIDC: config.OIDCConfig{Clients: []config.OIDCClient{{
				ClientID: "client-a", RequireMFA: append([]string(nil), required...),
				SupportedMFA:     []string{definitions.MFAMethodTOTP, definitions.MFAMethodWebAuthn},
				RequiredMFALevel: requiredLevel,
			}}},
		}}}},
		canonicalEnrollmentResolver: resolver,
	}
}

func authenticateCanonicalFixture(t *testing.T, runtime *cookie.CanonicalRuntime, browserCookie *http.Cookie) {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	request.AddCookie(browserCookie)

	session, err := runtime.Open(context.Background(), request)
	if err != nil {
		t.Fatalf("open canonical fixture: %v", err)
	}

	if err = session.CommitIdentity(context.Background(), cookie.IdentityUpdate{
		Reference: "identity-42", Account: "alice", Subject: "identity-42", DisplayName: "Alice", Protocol: "oidc",
	}); err != nil {
		t.Fatalf("authenticate canonical fixture: %v", err)
	}
}

func openCanonicalFixture(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
) *cookie.CanonicalSession {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	request.AddCookie(browserCookie)

	session, err := runtime.Open(context.Background(), request)
	if err != nil {
		t.Fatalf("open canonical fixture: %v", err)
	}

	return session
}

func seedCanonicalIDPFlow(t *testing.T, state *flowdomain.State) (*cookie.CanonicalRuntime, *http.Cookie, string) {
	t.Helper()

	now := time.Date(2026, time.August, 17, 12, 0, 0, 0, time.UTC)
	mini := miniredis.RunT(t)

	runtime, err := cookie.NewCanonicalRuntime(
		[]byte("canonical-login-flow-test-secret-32bytes"), 1,
		redis.NewClient(&redis.Options{Addr: mini.Addr()}), "canonical-login-flow",
		canonicalLoginClock{now: now}, sessionstate.NewRandomHandleGenerator(nil), false,
	)
	if err != nil {
		t.Fatalf("create canonical runtime: %v", err)
	}

	cookieWriter := httptest.NewRecorder()

	session, err := runtime.Create(context.Background(), cookieWriter, false)
	if err != nil {
		t.Fatalf("create canonical session: %v", err)
	}

	flowID := ""
	if state != nil {
		flowID = state.FlowID
		store := flowdomain.NewTypedStore(session.Stores, session.Handle, state.Protocol, 10*time.Minute)

		if err = store.Save(context.Background(), state); err != nil {
			t.Fatalf("save typed %s flow: %v", state.Protocol, err)
		}
	}

	return runtime, cookieWriter.Result().Cookies()[0], flowID
}

func assertCanonicalLoginFlow(ctx *gin.Context) {
	handler := &FrontendHandler{}

	state, ok := handler.canonicalIDPFlow(ctx)
	if !ok {
		ctx.Status(http.StatusBadRequest)

		return
	}

	loginState := handler.loginFlowState(state)
	if loginState.flowType != "oidc" || loginState.grantType != "" || loginState.oidcCID != "client-a" ||
		loginState.samlEntityID != "" {
		ctx.Status(http.StatusInternalServerError)

		return
	}

	ctx.Status(http.StatusNoContent)
}

func TestPostLoginFlowContextUsesCanonicalTypedState(t *testing.T) {
	t.Parallel()

	state := &flowdomain.State{
		FlowID: "PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP",
		Type:   flowdomain.FlowTypeOIDCDeviceCode, Protocol: flowdomain.FlowProtocolOIDC,
		GrantType: "device_code",
		Metadata:  map[string]string{flowdomain.FlowMetadataClientID: "client-a"},
	}

	flowContext := postLoginFlowContextFromState(state)
	if flowContext.flowType != "oidc" || flowContext.oidcCID != "client-a" ||
		flowContext.samlEntityID != "" || flowContext.protocol != "oidc" ||
		!flowContext.isDeviceCodeLoginFlow() {
		t.Fatalf("post-login flow context = %#v", flowContext)
	}
}

func TestSuccessfulPostLoginCommitsCanonicalIdentity(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, flowID := seedCanonicalLoginFlow(t)
	router := gin.New()
	router.POST("/login", cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation), completeCanonicalPostLogin)

	request := httptest.NewRequest(http.MethodPost, "/login?flow="+flowID, nil)
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	assertCompletedCanonicalLogin(t, runtime, browserCookie, flowID, writer)
}

func assertCompletedCanonicalLogin(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	flowID string,
	writer *httptest.ResponseRecorder,
) {
	t.Helper()

	rotated := assertCanonicalLoginRotation(t, runtime, browserCookie, writer)
	assertCanonicalLoginState(t, rotated, flowID)
}

func assertCanonicalLoginRotation(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	writer *httptest.ResponseRecorder,
) *cookie.CanonicalSession {
	t.Helper()

	if writer.Code != http.StatusNoContent {
		t.Fatalf("successful canonical login status = %d, want %d", writer.Code, http.StatusNoContent)
	}

	cookies := writer.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value == browserCookie.Value {
		t.Fatalf("rotated canonical cookies = %#v", cookies)
	}

	oldRequest := httptest.NewRequest(http.MethodGet, "/login", nil)
	oldRequest.AddCookie(browserCookie)

	if _, err := runtime.Open(context.Background(), oldRequest); !errors.Is(err, cookie.ErrEnvelopeRejected) {
		t.Fatalf("old canonical envelope error = %v, want rejected", err)
	}

	newRequest := httptest.NewRequest(http.MethodGet, "/login", nil)
	newRequest.AddCookie(cookies[0])

	rotated, err := runtime.Open(context.Background(), newRequest)
	if err != nil {
		t.Fatalf("open rotated canonical session: %v", err)
	}

	return rotated
}

func assertCanonicalLoginState(t *testing.T, rotated *cookie.CanonicalSession, flowID string) {
	t.Helper()

	identity, ok := rotated.Identity()
	if !ok || identity.Reference != "identity-42" || identity.Account != "alice" || identity.Protocol != "oidc" {
		t.Fatalf("rotated identity = %#v, ok = %v", identity, ok)
	}

	state, err := flowdomain.NewProtocolAggregate(rotated.Stores, rotated.Handle, 0).Load(context.Background(), flowID)
	if err != nil || state.AuthOutcome != flowdomain.AuthOutcomeOK || state.CurrentStep != flowdomain.FlowStepLogin {
		t.Fatalf("rotated protocol state = %#v, err = %v", state, err)
	}
}

func completeCanonicalPostLogin(ctx *gin.Context) {
	handler := &FrontendHandler{}

	state, ok := handler.canonicalIDPFlow(ctx)
	if !ok {
		ctx.Status(http.StatusBadRequest)

		return
	}

	flowContext := postLoginFlowContextFromState(state)
	flowContext.session = cookie.GetCanonicalSession(ctx)

	flowContext.state = state

	if handler.storeSuccessfulPostLoginSession(
		ctx,
		flowContext,
		postLoginCredentials{},
		&backend.User{ID: "identity-42", Name: "alice", DisplayName: "Alice Example"},
		core.RemoteBackendRef{},
		nil,
		core.RemoteBackendRef{},
	) {
		ctx.Status(http.StatusNoContent)
	}
}
