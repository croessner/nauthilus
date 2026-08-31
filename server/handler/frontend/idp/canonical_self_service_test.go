// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//nolint:dupl,gocyclo,funlen // Self-service tests keep each selected-backend mutation lifecycle intact.
package idp

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/backend/accountcache"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/handler/deps"
	flowdomain "github.com/croessner/nauthilus/v4/server/idp/flow"
	"github.com/croessner/nauthilus/v4/server/model/mfa"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/sessionstate"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
)

func TestCanonicalSelfServicePOSTPersistsTypedOperationThenAcceptsFreshAssurance(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)

	handler := &FrontendHandler{}

	writer := serveCanonicalSelfServiceMutation(t, runtime, browserCookie, handler)
	if writer.Code != http.StatusSeeOther {
		t.Fatalf("unassured mutation status = %d, want %d", writer.Code, http.StatusSeeOther)
	}

	location, err := url.Parse(writer.Header().Get("Location"))
	if err != nil || location.Path != frontendMFASelectPath {
		t.Fatalf("step-up redirect = %q, err = %v", writer.Header().Get("Location"), err)
	}

	handle, err := sessionstate.ParseHandle(location.Query().Get(flowdomain.FlowTicketParameter))
	if err != nil {
		t.Fatalf("parse self-service ticket: %v", err)
	}

	session := openCanonicalFixture(t, runtime, browserCookie)

	loaded, err := session.Stores.StepUp.Load(context.Background(), sessionstate.Reference{
		Session: session.Handle, Record: handle,
	})
	if err != nil || loaded.Value.Flow != "" ||
		loaded.Value.SelfServiceOperation != mfaSelfServiceActionRecoveryGenerate ||
		loaded.Value.Scope != canonicalSelfServiceAssuranceScope || loaded.Value.RequestedLevel != 1 ||
		len(loaded.Value.SupportedMethods) != 1 || loaded.Value.SupportedMethods[0] != definitions.MFAMethodTOTP {
		t.Fatalf("typed self-service operation = %#v, err = %v", loaded, err)
	}

	if _, err = session.CompleteStepUp(context.Background(), handle, definitions.MFAMethodTOTP, mfaAssuranceFreshness); err != nil {
		t.Fatalf("complete self-service step-up: %v", err)
	}

	writer = serveCanonicalSelfServiceMutation(t, runtime, browserCookie, handler)
	if writer.Code != http.StatusNoContent {
		t.Fatalf("freshly assured mutation status = %d, want %d", writer.Code, http.StatusNoContent)
	}
}

func TestCanonicalFrontendCompositionProvidesContinuationMiddleware(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)

	handler, err := NewCanonicalFrontendHandler(&deps.Deps{
		Cfg: &mockFrontendCfg{}, Env: config.NewTestEnvironmentConfig(), Logger: slog.Default(),
	}, runtime)
	if err != nil {
		t.Fatalf("compose canonical frontend handler: %v", err)
	}

	if _, err = NewCanonicalFrontendHandler(&deps.Deps{
		Cfg: &mockFrontendCfg{}, Env: config.NewTestEnvironmentConfig(), Logger: slog.Default(),
	}, nil); err == nil {
		t.Fatal("compose canonical frontend handler with nil runtime: error = nil")
	}

	passthrough := func(ctx *gin.Context) { ctx.Next() }
	middlewares := handler.newFrontendRouteMiddlewares()
	middlewares.security = passthrough
	middlewares.csrf = passthrough
	middlewares.i18n = passthrough

	router := gin.New()
	router.GET("/protected", middlewares.canonical, handler.CanonicalAuthMiddleware(), func(ctx *gin.Context) {
		ctx.Status(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.AddCookie(browserCookie)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("canonical auth route status = %d, want %d", response.Code, http.StatusNoContent)
	}

	request = httptest.NewRequest(http.MethodGet, "/protected", nil)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusConflict {
		t.Fatalf("missing canonical envelope status = %d, want %d", response.Code, http.StatusConflict)
	}
}

func TestCanonicalSelfServicePOSTRejectsProtocolScopedAssurance(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)
	session := openCanonicalFixture(t, runtime, browserCookie)
	now := session.EvaluationTime()

	if err := session.CommitAssurance(context.Background(), cookie.SessionAssurance{
		Level: 1, Method: definitions.MFAMethodTOTP, Scope: "oidc:client-a",
		ProvenAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("commit protocol assurance: %v", err)
	}

	writer := serveCanonicalSelfServiceMutation(t, runtime, browserCookie, &FrontendHandler{})
	if writer.Code != http.StatusSeeOther {
		t.Fatalf("protocol-scoped mutation status = %d, want %d", writer.Code, http.StatusSeeOther)
	}
}

func TestCanonicalSelfServiceTOTPCompletesToBoundRetrySurface(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)

	handler := &FrontendHandler{
		canonicalMFAAvailabilityResolver: func(
			_ *gin.Context,
			_ *cookie.CanonicalSession,
			_ cookie.SessionIdentity,
			parent *flowdomain.State,
			_ []string,
		) (mfaAvailability, error) {
			if parent != nil {
				t.Fatalf("self-service selection received protocol parent: %#v", parent)
			}

			return mfaAvailability{haveTOTP: true, count: 1}, nil
		},
		canonicalTOTPVerifier: func(*gin.Context, canonicalMFASelectionState, string) (bool, error) {
			return true, nil
		},
	}

	start := serveCanonicalSelfServiceMutation(t, runtime, browserCookie, handler)

	location, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse selection redirect: %v", err)
	}

	ticket := location.Query().Get(flowdomain.FlowTicketParameter)
	selection := serveCanonicalSelfServiceSelection(t, runtime, browserCookie, handler, ticket)

	wantChallenge := flowdomain.AppendTicket("/login/totp", ticket)
	if selection.Code != http.StatusFound || selection.Header().Get("Location") != wantChallenge {
		t.Fatalf("self-service selection = %d %q, want %d %q",
			selection.Code, selection.Header().Get("Location"), http.StatusFound, wantChallenge)
	}

	completion := serveCanonicalSelfServiceTOTP(t, runtime, browserCookie, handler, ticket)
	if completion.Code != http.StatusFound || completion.Header().Get("Location") != definitions.MFARoot+"/register/home" {
		t.Fatalf("self-service completion = %d %q, want %d %q",
			completion.Code, completion.Header().Get("Location"), http.StatusFound, definitions.MFARoot+"/register/home")
	}
}

func TestCanonicalSelfServiceRecoveryCompletesToBoundRetrySurface(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)
	handler := canonicalSelfServiceMethodHandler(t, definitions.MFAMethodRecoveryCodes)

	start := serveCanonicalSelfServiceMutationWithMethods(
		t, runtime, browserCookie, handler, []string{definitions.MFAMethodRecoveryCodes},
	)
	ticket := mustSelfServiceTicket(t, start)

	completion := serveCanonicalSelfServiceRecovery(t, runtime, browserCookie, handler, ticket)
	if completion.Code != http.StatusFound || completion.Header().Get("Location") != definitions.MFARoot+"/register/home" {
		t.Fatalf("recovery self-service completion = %d %q, want %d %q",
			completion.Code, completion.Header().Get("Location"), http.StatusFound, definitions.MFARoot+"/register/home")
	}
}

func TestCanonicalSelfServiceWebAuthnCompletesToBoundRetrySurface(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)
	handler := canonicalSelfServiceMethodHandler(t, definitions.MFAMethodWebAuthn)

	start := serveCanonicalSelfServiceMutationWithMethods(
		t, runtime, browserCookie, handler, []string{definitions.MFAMethodWebAuthn},
	)
	ticket := mustSelfServiceTicket(t, start)

	completion := serveCanonicalSelfServiceWebAuthn(t, runtime, browserCookie, handler, ticket)
	if completion.Code != http.StatusOK ||
		!strings.Contains(completion.Body.String(), `"redirect":"`+definitions.MFARoot+`/register/home"`) {
		t.Fatalf("WebAuthn self-service completion = %d %q", completion.Code, completion.Body.String())
	}
}

func TestCanonicalSelfServiceMutationCallersPersistTypedOperations(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name    string
		method  string
		pattern string
		target  string
		body    string
		action  string
		handle  gin.HandlerFunc
	}{
		{
			name: "recovery generation", method: http.MethodPost,
			pattern: definitions.MFARoot + "/recovery/generate", target: definitions.MFARoot + "/recovery/generate",
			action: mfaSelfServiceActionRecoveryGenerate,
		},
		{
			name: "TOTP delete", method: http.MethodDelete,
			pattern: definitions.MFARoot + "/totp", target: definitions.MFARoot + "/totp",
			action: mfaSelfServiceActionTOTPDelete,
		},
		{
			name: "all WebAuthn delete", method: http.MethodDelete,
			pattern: definitions.MFARoot + "/webauthn", target: definitions.MFARoot + "/webauthn",
			action: mfaSelfServiceActionWebAuthnDelete,
		},
		{
			name: "one WebAuthn delete", method: http.MethodDelete,
			pattern: definitions.MFARoot + "/webauthn/device/:id", target: definitions.MFARoot + "/webauthn/device/Y3JlZC0x",
			action: mfaSelfServiceActionWebAuthnDeviceDrop,
		},
		{
			name: "WebAuthn rename", method: http.MethodPost,
			pattern: definitions.MFARoot + "/webauthn/device/:id/name", target: definitions.MFARoot + "/webauthn/device/Y3JlZC0x/name",
			body: "name=Renamed+key", action: mfaSelfServiceActionWebAuthnDeviceName,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
			authenticateCanonicalFixture(t, runtime, browserCookie)

			handler, provider := newMFASelfServiceTestHandler()
			handler.canonicalMFAAvailabilityResolver = canonicalSelfServiceMethodHandler(
				t, definitions.MFAMethodTOTP,
			).canonicalMFAAvailabilityResolver

			switch test.action {
			case mfaSelfServiceActionRecoveryGenerate:
				test.handle = handler.PostGenerateRecoveryCodes
			case mfaSelfServiceActionTOTPDelete:
				test.handle = handler.DeleteTOTP
			case mfaSelfServiceActionWebAuthnDelete:
				test.handle = handler.DeleteWebAuthn
			case mfaSelfServiceActionWebAuthnDeviceDrop:
				test.handle = handler.DeleteWebAuthnDevice
			case mfaSelfServiceActionWebAuthnDeviceName:
				test.handle = handler.UpdateWebAuthnDeviceName
			}

			writer := serveCanonicalSelfServiceCaller(t, runtime, browserCookie, handler, test)
			ticket := mustSelfServiceTicket(t, writer)
			session := openCanonicalFixture(t, runtime, browserCookie)

			loaded, err := session.Stores.StepUp.Load(context.Background(), sessionstate.Reference{
				Session: session.Handle, Record: sessionstate.Handle(ticket),
			})
			if err != nil || loaded.Value.SelfServiceOperation != test.action || loaded.Value.Flow != "" {
				t.Fatalf("caller typed operation = %#v, err = %v", loaded, err)
			}

			if test.action == mfaSelfServiceActionWebAuthnDeviceName &&
				(loaded.Value.SelfServiceCredentialID != "Y3JlZC0x" || loaded.Value.SelfServiceDeviceName != "Renamed key") {
				t.Fatalf("typed rename payload = %#v", loaded.Value)
			}

			if provider.deleteTOTPCalls != 0 || provider.generateRecoveryCalls != 0 {
				t.Fatalf("mutation ran before assurance: delete=%d generate=%d",
					provider.deleteTOTPCalls, provider.generateRecoveryCalls)
			}
		})
	}
}

func TestCanonicalSelfServiceHTMXMutationStartsClientRedirect(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)

	handler, _ := newMFASelfServiceTestHandler()
	handler.canonicalMFAAvailabilityResolver = canonicalSelfServiceMethodHandler(
		t, definitions.MFAMethodTOTP,
	).canonicalMFAAvailabilityResolver

	router := gin.New()
	router.POST(
		definitions.MFARoot+"/recovery/generate",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.PostGenerateRecoveryCodes,
	)

	request := httptest.NewRequest(http.MethodPost, definitions.MFARoot+"/recovery/generate", nil)
	request.Header.Set("HX-Request", "true")
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	redirect := writer.Header().Get("HX-Redirect")

	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("parse HTMX redirect: %v", err)
	}

	if writer.Code != http.StatusOK || writer.Header().Get("Location") != "" || parsed.Path != "/login/mfa" {
		t.Fatalf("HTMX self-service start = status:%d location:%q redirect:%q",
			writer.Code, writer.Header().Get("Location"), redirect)
	}

	if _, err = sessionstate.ParseHandle(parsed.Query().Get(flowdomain.FlowTicketParameter)); err != nil {
		t.Fatalf("parse HTMX self-service ticket: %v", err)
	}
}

func TestCanonicalSelfServiceRenameContinueConsumesTypedOperationOnce(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)

	handler, _ := newMFASelfServiceTestHandler()
	handler.canonicalMFAAvailabilityResolver = canonicalSelfServiceMethodHandler(
		t, definitions.MFAMethodTOTP,
	).canonicalMFAAvailabilityResolver
	handler.canonicalTOTPVerifier = func(*gin.Context, canonicalMFASelectionState, string) (bool, error) {
		return true, nil
	}

	renameCalls := 0
	handler.canonicalSelfServiceRename = func(
		_ *gin.Context,
		session *cookie.CanonicalSession,
		identity cookie.SessionIdentity,
		credentialID []byte,
		deviceName string,
	) error {
		renameCalls++

		if session == nil || identity.Account != "alice" || identity.Reference != "identity-42" ||
			string(credentialID) != "cred-1" || deviceName != "Renamed key" {
			t.Fatalf("canonical rename input: session=%v identity=%#v credential=%q name=%q",
				session != nil, identity, string(credentialID), deviceName)
		}

		return nil
	}

	start := serveCanonicalSelfServiceRenameStart(t, runtime, browserCookie, handler)
	ticket := mustSelfServiceTicket(t, start)
	completion := serveCanonicalSelfServiceTOTP(t, runtime, browserCookie, handler, ticket)

	wantContinue := flowdomain.AppendTicket(definitions.MFARoot+"/self-service/continue", ticket)
	if completion.Code != http.StatusFound || completion.Header().Get("Location") != wantContinue {
		t.Fatalf("rename completion = %d %q, want %d %q",
			completion.Code, completion.Header().Get("Location"), http.StatusFound, wantContinue)
	}

	continued := serveCanonicalSelfServiceContinue(t, runtime, browserCookie, handler, ticket)
	if continued.Code != http.StatusSeeOther || continued.Header().Get("Location") != definitions.MFARoot+"/webauthn/devices" {
		t.Fatalf("rename continue = %d %q", continued.Code, continued.Header().Get("Location"))
	}

	replayed := serveCanonicalSelfServiceContinue(t, runtime, browserCookie, handler, ticket)
	if replayed.Code != http.StatusConflict || renameCalls != 1 {
		t.Fatalf("rename replay = status %d calls %d, want %d/1", replayed.Code, renameCalls, http.StatusConflict)
	}
}

func TestCanonicalSelfServiceTOTPDeleteUsesCanonicalIdentityOnFreshSuccess(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)
	session := openCanonicalFixture(t, runtime, browserCookie)

	now := session.EvaluationTime()
	if err := session.CommitAssurance(context.Background(), cookie.SessionAssurance{
		Level: 1, Method: definitions.MFAMethodTOTP, Scope: canonicalSelfServiceAssuranceScope,
		ProvenAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("commit self-service assurance: %v", err)
	}

	handler, provider := newMFASelfServiceTestHandler()
	resolverCalls := 0
	handler.canonicalSelfServiceBackendResolver = func(
		_ *gin.Context,
		resolvedSession *cookie.CanonicalSession,
		identity cookie.SessionIdentity,
	) (*UserBackendData, uint8, error) {
		resolverCalls++

		if resolvedSession == nil || identity.Account != "alice" || identity.Reference != "identity-42" {
			t.Fatalf("canonical backend identity = session:%v identity:%#v", resolvedSession != nil, identity)
		}

		return &UserBackendData{
			Username: "alice", UniqueUserID: "identity-42", HaveTOTP: true,
		}, uint8(definitions.BackendLDAP), nil
	}

	router := gin.New()
	router.DELETE(
		definitions.MFARoot+"/totp",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.CanonicalAuthMiddleware(),
		staleLegacySelfServiceIdentity,
		handler.DeleteTOTP,
	)

	request := httptest.NewRequest(http.MethodDelete, definitions.MFARoot+"/totp", nil)
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	if writer.Code != http.StatusOK || provider.deleteTOTPCalls != 1 ||
		provider.lastAccount != "alice" || resolverCalls != 1 {
		t.Fatalf("canonical TOTP delete = status:%d calls:%d account:%q resolvers:%d",
			writer.Code, provider.deleteTOTPCalls, provider.lastAccount, resolverCalls)
	}
}

func TestCanonicalSelfServiceRecoveryGenerationUsesCanonicalIdentityOnFreshSuccess(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)
	session := openCanonicalFixture(t, runtime, browserCookie)

	now := session.EvaluationTime()
	if err := session.CommitAssurance(context.Background(), cookie.SessionAssurance{
		Level: 1, Method: definitions.MFAMethodTOTP, Scope: canonicalSelfServiceAssuranceScope,
		ProvenAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("commit self-service assurance: %v", err)
	}

	handler, provider := newMFASelfServiceTestHandler()
	resolverCalls := 0
	handler.canonicalSelfServiceBackendResolver = func(
		_ *gin.Context,
		_ *cookie.CanonicalSession,
		identity cookie.SessionIdentity,
	) (*UserBackendData, uint8, error) {
		resolverCalls++

		return &UserBackendData{
			Username: identity.Account, UniqueUserID: identity.Reference, HaveTOTP: true,
		}, uint8(definitions.BackendLDAP), nil
	}

	ctx, _ := newMFASelfServiceContext(http.MethodPost, definitions.MFARoot+"/recovery/generate", map[string]any{
		definitions.SessionKeyAccount: "legacy-bob",
	}, nil)
	cookie.SetCanonicalSession(ctx, session)
	handler.PostGenerateRecoveryCodes(ctx)

	if provider.generateRecoveryCalls != 1 || provider.lastAccount != "alice" || resolverCalls != 1 {
		t.Fatalf("canonical recovery generation = calls:%d account:%q resolvers:%d",
			provider.generateRecoveryCalls, provider.lastAccount, resolverCalls)
	}
}

func TestCanonicalSelfServiceMFAMutationsUseOnlySelectedBackend(t *testing.T) {
	t.Parallel()

	handler, _ := newMFASelfServiceTestHandler()
	ctx, _ := newMFASelfServiceContext(http.MethodPost, definitions.MFARoot+"/recovery/generate", map[string]any{
		definitions.SessionKeyUserBackend:     uint8(definitions.BackendRemote),
		definitions.SessionKeyUserBackendName: "legacy-remote-backend",
	}, nil)
	authState := core.NewAuthStateFromContextWithDeps(ctx, handler.deps.Auth()).(*core.AuthState)
	authState.SetUsername("alice")
	authState.Runtime.UsedPassDBBackend = definitions.BackendTest
	authState.Runtime.BackendName = "canonical-selected-backend"
	data := &UserBackendData{
		Username: "alice", UniqueUserID: "identity-42", AuthState: authState,
	}

	if err := handler.deleteCanonicalSelfServiceTOTP(ctx, data); err != nil {
		t.Fatalf("delete selected-backend TOTP: %v", err)
	}

	codes, err := handler.generateCanonicalSelfServiceRecoveryCodes(ctx, data)
	if err != nil {
		t.Fatalf("generate selected-backend recovery codes: %v", err)
	}

	if len(codes) == 0 {
		t.Fatal("generate selected-backend recovery codes: empty result")
	}
}

func TestCanonicalSelfServiceWebAuthnMutationsUseSelectedBackendOnFreshSuccess(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		body   string
		params gin.Params
		status int
		header string
		target string
		handle func(*FrontendHandler, *gin.Context)
	}{
		{
			name: "delete all", method: http.MethodDelete, path: definitions.MFARoot + "/webauthn",
			status: http.StatusOK, header: "HX-Redirect", target: definitions.MFARoot + "/register/home",
			handle: func(handler *FrontendHandler, ctx *gin.Context) { handler.DeleteWebAuthn(ctx) },
		},
		{
			name: "delete device", method: http.MethodDelete, path: definitions.MFARoot + "/webauthn/device/Y3JlZC0x",
			params: gin.Params{{Key: "id", Value: "Y3JlZC0x"}},
			status: http.StatusSeeOther, header: "Location", target: definitions.MFARoot + "/webauthn/devices",
			handle: func(handler *FrontendHandler, ctx *gin.Context) { handler.DeleteWebAuthnDevice(ctx) },
		},
		{
			name: "rename device", method: http.MethodPost, path: definitions.MFARoot + "/webauthn/device/Y3JlZC0x/name",
			body: "name=Canonical+key", params: gin.Params{{Key: "id", Value: "Y3JlZC0x"}},
			status: http.StatusSeeOther, header: "Location", target: definitions.MFARoot + "/webauthn/devices",
			handle: func(handler *FrontendHandler, ctx *gin.Context) { handler.UpdateWebAuthnDeviceName(ctx) },
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
			authenticateCanonicalFixture(t, runtime, browserCookie)
			session := openCanonicalFixture(t, runtime, browserCookie)

			now := session.EvaluationTime()
			if err := session.CommitAssurance(context.Background(), cookie.SessionAssurance{
				Level: 1, Method: definitions.MFAMethodTOTP, Scope: canonicalSelfServiceAssuranceScope,
				ProvenAt: now, ExpiresAt: now.Add(5 * time.Minute),
			}); err != nil {
				t.Fatalf("commit self-service assurance: %v", err)
			}

			handler, _ := newMFASelfServiceTestHandler()
			db, mockRedis := redismock.NewClientMock()
			handler.deps.Redis = rediscli.NewTestClient(db)
			handler.deps.AccountCache = accountcache.NewManager(handler.deps.Cfg)
			mockRedis.ExpectDel(webAuthnRedisUserKey(handler.deps.Cfg, "identity-42")).SetVal(1)

			credential := mfa.PersistentCredential{
				Name: "Original key",
			}
			credential.ID = []byte("cred-1")

			var authState *core.AuthState

			handler.canonicalSelfServiceBackendResolver = func(
				ctx *gin.Context,
				_ *cookie.CanonicalSession,
				identity cookie.SessionIdentity,
			) (*UserBackendData, uint8, error) {
				authState = core.NewAuthStateFromContextWithDeps(ctx, handler.deps.Auth()).(*core.AuthState)
				authState.Runtime.UsedPassDBBackend = definitions.BackendRemote

				return &UserBackendData{
					Username: identity.Account, UniqueUserID: identity.Reference,
					AuthState: authState,
					WebAuthnUser: &backend.User{
						ID: identity.Reference, Name: identity.Account,
						Credentials: []mfa.PersistentCredential{credential},
					},
				}, uint8(definitions.BackendRemote), nil
			}

			deleteCalls := 0
			updateCalls := 0
			handler.canonicalWebAuthnCredentialDelete = func(state *core.AuthState, got *mfa.PersistentCredential) error {
				deleteCalls++

				if state != authState || got == nil || string(got.ID) != "cred-1" {
					t.Fatalf("selected delete input = state:%p credential:%#v", state, got)
				}

				return nil
			}
			handler.canonicalWebAuthnCredentialUpdate = func(
				state *core.AuthState,
				oldCredential *mfa.PersistentCredential,
				newCredential *mfa.PersistentCredential,
			) error {
				updateCalls++

				if state != authState || oldCredential == nil || newCredential == nil ||
					string(oldCredential.ID) != "cred-1" || newCredential.Name != "Canonical key" {
					t.Fatalf("selected update input = state:%p old:%#v new:%#v", state, oldCredential, newCredential)
				}

				return nil
			}

			var body *strings.Reader
			if testCase.body != "" {
				body = strings.NewReader(testCase.body)
			} else {
				body = strings.NewReader("")
			}

			ctx, recorder := newMFASelfServiceContext(testCase.method, testCase.path, map[string]any{
				definitions.SessionKeyAccount: "legacy-bob",
			}, nil)

			ctx.Request = httptest.NewRequest(testCase.method, testCase.path, body)
			if testCase.body != "" {
				ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}

			ctx.Params = testCase.params
			cookie.SetCanonicalSession(ctx, session)
			testCase.handle(handler, ctx)

			if ctx.Writer.Status() != testCase.status || recorder.Header().Get(testCase.header) != testCase.target {
				t.Fatalf("canonical WebAuthn mutation response = %d headers %#v", ctx.Writer.Status(), recorder.Header())
			}

			if testCase.name == "rename device" {
				if updateCalls != 1 || deleteCalls != 0 {
					t.Fatalf("rename calls = update:%d delete:%d", updateCalls, deleteCalls)
				}
			} else if deleteCalls != 1 || updateCalls != 0 {
				t.Fatalf("delete calls = delete:%d update:%d", deleteCalls, updateCalls)
			}

			if err := mockRedis.ExpectationsWereMet(); err != nil {
				t.Fatalf("Redis expectations: %v", err)
			}
		})
	}
}

func TestCanonicalSelfServiceGETViewsUseCanonicalIdentity(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		handle   func(*FrontendHandler, *gin.Context)
		wantBody string
	}{
		{
			name: "home", path: definitions.MFARoot + "/register/home",
			handle:   func(handler *FrontendHandler, ctx *gin.Context) { handler.TwoFAHome(ctx) },
			wantBody: "alice|Canonical Alice",
		},
		{
			name: "devices", path: definitions.MFARoot + "/webauthn/devices",
			handle:   func(handler *FrontendHandler, ctx *gin.Context) { handler.WebAuthnDevices(ctx) },
			wantBody: "Canonical key",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
			authenticateCanonicalFixture(t, runtime, browserCookie)
			session := openCanonicalFixture(t, runtime, browserCookie)
			handler, _ := newMFASelfServiceTestHandler()
			resolverCalls := 0
			handler.canonicalSelfServiceBackendResolver = func(
				_ *gin.Context,
				_ *cookie.CanonicalSession,
				identity cookie.SessionIdentity,
			) (*UserBackendData, uint8, error) {
				resolverCalls++

				if identity.Account != "alice" || identity.Reference != "identity-42" {
					t.Fatalf("canonical view identity = %#v", identity)
				}

				credential := mfa.PersistentCredential{Name: "Canonical key"}
				credential.ID = []byte("cred-1")

				return &UserBackendData{
					Username: "alice", UniqueUserID: "identity-42", DisplayName: "Canonical Alice",
					HaveTOTP: true, HaveWebAuthn: true, NumRecoveryCodes: 2,
					WebAuthnUser: &backend.User{
						ID: "identity-42", Name: "alice", DisplayName: "Canonical Alice",
						Credentials: []mfa.PersistentCredential{credential},
					},
				}, uint8(definitions.BackendRemote), nil
			}

			ctx, recorder := newMFASelfServiceContext(http.MethodGet, testCase.path, map[string]any{
				definitions.SessionKeyAccount: "legacy-bob",
			}, nil)
			cookie.SetCanonicalSession(ctx, session)
			testCase.handle(handler, ctx)

			if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), testCase.wantBody) || resolverCalls != 1 {
				t.Fatalf("canonical view = status:%d body:%q resolvers:%d",
					recorder.Code, recorder.Body.String(), resolverCalls)
			}
		})
	}
}

func serveCanonicalSelfServiceCaller(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	_ *FrontendHandler,
	test struct {
		name    string
		method  string
		pattern string
		target  string
		body    string
		action  string
		handle  gin.HandlerFunc
	},
) *httptest.ResponseRecorder {
	t.Helper()

	router := gin.New()
	router.Handle(
		test.method,
		test.pattern,
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		func(ctx *gin.Context) {
			ctx.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: map[string]any{
				definitions.SessionKeyAccount: "legacy-alice",
			}})
			ctx.Next()
		},
		test.handle,
	)

	request := httptest.NewRequest(test.method, test.target, strings.NewReader(test.body))
	if test.body != "" {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	return writer
}

func serveCanonicalSelfServiceRenameStart(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	handler *FrontendHandler,
) *httptest.ResponseRecorder {
	t.Helper()

	router := gin.New()
	router.POST(
		definitions.MFARoot+"/webauthn/device/:id/name",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		staleLegacySelfServiceIdentity,
		handler.UpdateWebAuthnDeviceName,
	)

	request := httptest.NewRequest(
		http.MethodPost,
		definitions.MFARoot+"/webauthn/device/Y3JlZC0x/name",
		strings.NewReader("name=Renamed+key"),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	return writer
}

func serveCanonicalSelfServiceContinue(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	handler *FrontendHandler,
	ticket string,
) *httptest.ResponseRecorder {
	t.Helper()

	router := gin.New()
	router.GET(
		definitions.MFARoot+"/self-service/continue",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.CanonicalAuthMiddleware(),
		staleLegacySelfServiceIdentity,
		handler.ContinueMFASelfServiceStepUp,
	)

	request := httptest.NewRequest(
		http.MethodGet,
		flowdomain.AppendTicket(definitions.MFARoot+"/self-service/continue", ticket),
		nil,
	)
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	return writer
}

func staleLegacySelfServiceIdentity(ctx *gin.Context) {
	ctx.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: map[string]any{
		definitions.SessionKeyAccount: "legacy-bob",
	}})
	ctx.Next()
}

func canonicalSelfServiceMethodHandler(t *testing.T, method string) *FrontendHandler {
	t.Helper()

	handler := &FrontendHandler{}
	handler.canonicalMFAAvailabilityResolver = func(
		_ *gin.Context,
		_ *cookie.CanonicalSession,
		_ cookie.SessionIdentity,
		parent *flowdomain.State,
		_ []string,
	) (mfaAvailability, error) {
		if parent != nil {
			t.Fatalf("self-service selection received protocol parent: %#v", parent)
		}

		availability := mfaAvailability{}

		switch method {
		case definitions.MFAMethodTOTP:
			availability.haveTOTP = true
		case definitions.MFAMethodRecoveryCodes:
			availability.haveRecoveryCodes = true
		case definitions.MFAMethodWebAuthn:
			availability.haveWebAuthn = true
		default:
			t.Fatalf("unsupported test method %q", method)
		}

		availability.count = 1

		return availability, nil
	}
	handler.canonicalRecoveryVerifier = func(*gin.Context, canonicalMFASelectionState, string) (bool, error) {
		return true, nil
	}
	handler.canonicalWebAuthnFinish = func(
		*gin.Context,
		canonicalMFASelectionState,
		sessionstate.Handle,
	) (*backend.User, error) {
		return nil, nil
	}

	return handler
}

func serveCanonicalSelfServiceMutation(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	handler *FrontendHandler,
) *httptest.ResponseRecorder {
	t.Helper()

	return serveCanonicalSelfServiceMutationWithMethods(
		t, runtime, browserCookie, handler, []string{definitions.MFAMethodTOTP},
	)
}

func serveCanonicalSelfServiceMutationWithMethods(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	handler *FrontendHandler,
	supportedMethods []string,
) *httptest.ResponseRecorder {
	t.Helper()

	router := gin.New()
	router.POST(
		definitions.MFARoot+"/recovery/generate",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.CanonicalAuthMiddleware(),
		func(ctx *gin.Context) {
			if !handler.authorizeCanonicalSelfServiceMutation(ctx, supportedMethods, nil) {
				return
			}

			ctx.Status(http.StatusNoContent)
		},
	)

	request := httptest.NewRequest(http.MethodPost, definitions.MFARoot+"/recovery/generate", nil)
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	return writer
}

func mustSelfServiceTicket(t *testing.T, writer *httptest.ResponseRecorder) string {
	t.Helper()

	location, err := url.Parse(writer.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse self-service redirect: %v", err)
	}

	ticket := location.Query().Get(flowdomain.FlowTicketParameter)
	if _, err = sessionstate.ParseHandle(ticket); err != nil {
		t.Fatalf("parse self-service ticket: %v", err)
	}

	return ticket
}

func serveCanonicalSelfServiceSelection(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	handler *FrontendHandler,
	ticket string,
) *httptest.ResponseRecorder {
	t.Helper()

	router := gin.New()
	router.GET(
		frontendMFASelectPath,
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.LoginMFASelect,
	)

	request := httptest.NewRequest(http.MethodGet, flowdomain.AppendTicket(frontendMFASelectPath, ticket), nil)
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	return writer
}

func serveCanonicalSelfServiceTOTP(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	handler *FrontendHandler,
	ticket string,
) *httptest.ResponseRecorder {
	t.Helper()

	router := gin.New()
	router.POST(
		"/login/totp",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.PostLoginTOTP,
	)

	form := url.Values{"code": {"123456"}}
	request := httptest.NewRequest(
		http.MethodPost,
		flowdomain.AppendTicket("/login/totp", ticket),
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	return writer
}

func serveCanonicalSelfServiceRecovery(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	handler *FrontendHandler,
	ticket string,
) *httptest.ResponseRecorder {
	t.Helper()

	router := gin.New()
	router.POST(
		"/login/recovery",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.PostLoginRecovery,
	)

	form := url.Values{"code": {"recovery-code"}}
	request := httptest.NewRequest(
		http.MethodPost,
		flowdomain.AppendTicket("/login/recovery", ticket),
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	return writer
}

func serveCanonicalSelfServiceWebAuthn(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	handler *FrontendHandler,
	ticket string,
) *httptest.ResponseRecorder {
	t.Helper()

	router := gin.New()
	router.POST(
		"/login/webauthn/finish",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.PostLoginWebAuthnFinish,
	)

	target := flowdomain.AppendTicket("/login/webauthn/finish", ticket) +
		"&" + canonicalWebAuthnCeremonyParameter + "=CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	return writer
}
