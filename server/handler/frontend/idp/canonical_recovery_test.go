// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//nolint:dupl,gocyclo // Recovery tests mirror other MFA methods while proving distinct consume semantics.
package idp

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/croessner/nauthilus/v3/server/idp/mfastate"
	"github.com/croessner/nauthilus/v3/server/middleware/csrf"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/gin-gonic/gin"
)

func TestCanonicalRecoveryWrongCodeRetriesThenConsumesAndResumesOnce(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, flowID := seedCanonicalIDPFlow(t, canonicalDecisionOIDCState(""))
	authenticateCanonicalFixture(t, runtime, browserCookie)
	stepUpHandle := seedCanonicalRecoveryStepUp(t, runtime, browserCookie, flowID)

	verificationCalls := 0
	handler := newLoginMFAViewHandler()
	handler.canonicalMFAAvailabilityResolver = canonicalRecoveryAvailability
	handler.canonicalRecoveryVerifier = func(
		_ *gin.Context,
		selection canonicalMFASelectionState,
		code string,
	) (bool, error) {
		verificationCalls++

		if selection.identity.Reference != "identity-42" || selection.identity.Account != "alice" ||
			selection.parent.FlowID != flowID || selection.stepUp.Value.Flow != sessionstate.Handle(flowID) {
			t.Fatalf("typed recovery binding = identity %#v parent %#v step-up %#v",
				selection.identity, selection.parent, selection.stepUp.Value)
		}

		return code == "recovery-good", nil
	}

	router := canonicalRecoveryTestRouter(t, runtime, handler)
	csrfCookie, firstToken := loadCanonicalRecoveryForm(t, router, browserCookie, stepUpHandle)

	retry := postCanonicalRecovery(t, router, browserCookie, csrfCookie, stepUpHandle, firstToken, "recovery-wrong")
	if retry.Code != http.StatusOK || !strings.Contains(retry.Body.String(), "error=true") {
		t.Fatalf("wrong recovery response = %d %q, want retry form", retry.Code, retry.Body.String())
	}

	retryToken := canonicalTOTPTemplateValue(t, retry.Body.String(), "csrf")
	if retryToken == "" || canonicalTOTPTemplateValue(t, retry.Body.String(), "ticket") != string(stepUpHandle) {
		t.Fatalf("wrong recovery retry lost bound state: %q", retry.Body.String())
	}

	assertCanonicalTOTPPending(t, runtime, browserCookie, stepUpHandle)

	success := postCanonicalRecovery(t, router, browserCookie, csrfCookie, stepUpHandle, retryToken, "recovery-good")

	wantLocation := "/oidc/authorize?client_id=client-a&flow=" + flowID
	if success.Code != http.StatusFound || success.Header().Get("Location") != wantLocation {
		t.Fatalf("successful recovery response = %d %q, want %d %q",
			success.Code, success.Header().Get("Location"), http.StatusFound, wantLocation)
	}

	assertCanonicalRecoveryCompleted(t, runtime, browserCookie, stepUpHandle)

	replay := postCanonicalRecovery(t, router, browserCookie, csrfCookie, stepUpHandle, retryToken, "recovery-good")
	if replay.Code != http.StatusConflict || verificationCalls != 2 {
		t.Fatalf("recovery replay = status %d verifier calls %d, want %d/2",
			replay.Code, verificationCalls, http.StatusConflict)
	}
}

func TestCanonicalLoginRecoveryViewDoesNotExpose2FAHomeMenuBeforeCompletion(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, flowID := seedCanonicalIDPFlow(t, canonicalDecisionOIDCState(""))
	authenticateCanonicalFixture(t, runtime, browserCookie)
	stepUpHandle := seedCanonicalRecoveryStepUp(t, runtime, browserCookie, flowID)

	handler := newLoginMFAViewHandler()
	handler.canonicalMFAAvailabilityResolver = canonicalRecoveryAvailability
	router := gin.New()
	router.SetHTMLTemplate(loginMFATestTemplate())
	router.Use(loginMFAViewLocalizationMiddleware())
	router.GET(
		"/login/recovery/:languageTag",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.LoginRecovery,
	)

	request := httptest.NewRequest(http.MethodGet, "/login/recovery/de?flow="+string(stepUpHandle), nil)
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	if writer.Code != http.StatusOK || strings.Contains(writer.Body.String(), "2FA Verwaltung") {
		t.Fatalf("canonical recovery view = status %d body %q, want 200 without self-service menu",
			writer.Code, writer.Body.String())
	}
}

func seedCanonicalRecoveryStepUp(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	flowID string,
) sessionstate.Handle {
	t.Helper()

	session := openCanonicalFixture(t, runtime, browserCookie)

	handle := sessionstate.Handle("YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY")
	if err := mfastate.NewAggregate(session.Stores, session.Handle, 10*time.Minute).BeginStepUp(
		context.Background(),
		&sessionstate.StepUpRecord{
			Record: sessionstate.Record{Handle: handle}, Session: session.Handle,
			Flow: sessionstate.Handle(flowID), RequestedLevel: 1,
			SupportedMethods: []string{definitions.MFAMethodRecoveryCodes}, Scope: "oidc:client-a",
		},
	); err != nil {
		t.Fatalf("seed typed recovery step-up: %v", err)
	}

	return handle
}

func canonicalRecoveryAvailability(
	_ *gin.Context,
	_ *cookie.CanonicalSession,
	_ cookie.SessionIdentity,
	_ *flowdomain.State,
	_ []string,
) (mfaAvailability, error) {
	return mfaAvailability{haveRecoveryCodes: true, count: 1}, nil
}

func canonicalRecoveryTestRouter(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	handler *FrontendHandler,
) *gin.Engine {
	t.Helper()

	csrfHandler := csrf.NewHandler()
	router := gin.New()
	router.SetHTMLTemplate(template.Must(template.New("canonical-recovery").Parse(
		`{{ define "idp_recovery_login.html" }}ticket={{ .FlowTicket }};csrf={{ .CSRFToken }};error={{ .HaveError }}{{ end }}`,
	)))
	router.Use(csrfHandler.Middleware())
	router.GET("/login/recovery", cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation), handler.LoginRecovery)
	router.POST("/login/recovery", cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation), handler.PostLoginRecovery)

	return router
}

func loadCanonicalRecoveryForm(
	t *testing.T,
	router http.Handler,
	browserCookie *http.Cookie,
	stepUpHandle sessionstate.Handle,
) (*http.Cookie, string) {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "https://idp.example.test/login/recovery?flow="+string(stepUpHandle), nil)
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	if writer.Code != http.StatusOK {
		t.Fatalf("load canonical recovery form status = %d, want %d", writer.Code, http.StatusOK)
	}

	for _, responseCookie := range writer.Result().Cookies() {
		if responseCookie.Name == csrf.CookieName {
			return responseCookie, canonicalTOTPTemplateValue(t, writer.Body.String(), "csrf")
		}
	}

	t.Fatal("canonical recovery form did not issue CSRF cookie")

	return nil, ""
}

func postCanonicalRecovery(
	t *testing.T,
	router http.Handler,
	browserCookie *http.Cookie,
	csrfCookie *http.Cookie,
	stepUpHandle sessionstate.Handle,
	csrfToken string,
	code string,
) *httptest.ResponseRecorder {
	t.Helper()

	form := url.Values{
		csrf.FormFieldName: {csrfToken},
		"flow":             {string(stepUpHandle)},
		"code":             {code},
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"https://idp.example.test/login/recovery",
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://idp.example.test")
	request.AddCookie(browserCookie)
	request.AddCookie(csrfCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	return writer
}

func assertCanonicalRecoveryCompleted(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	stepUpHandle sessionstate.Handle,
) {
	t.Helper()

	session := openCanonicalFixture(t, runtime, browserCookie)

	loaded, err := mfastate.NewAggregate(session.Stores, session.Handle, 0).
		LoadStepUp(context.Background(), stepUpHandle)
	if err != nil || !loaded.Value.Completed || loaded.Value.ProofMethod != definitions.MFAMethodRecoveryCodes {
		t.Fatalf("successful recovery StepUp = %#v, err = %v", loaded.Value, err)
	}

	assurance, ok := session.Assurance(session.EvaluationTime())
	if !ok || assurance.Level != 1 || assurance.Method != definitions.MFAMethodRecoveryCodes ||
		assurance.Scope != "oidc:client-a" {
		t.Fatalf("successful recovery assurance = %#v, ok = %t", assurance, ok)
	}
}
