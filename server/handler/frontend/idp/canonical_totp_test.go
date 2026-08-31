// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//nolint:dupl,gocyclo // TOTP tests mirror other MFA methods while proving distinct verifier semantics.
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

	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	flowdomain "github.com/croessner/nauthilus/v4/server/idp/flow"
	"github.com/croessner/nauthilus/v4/server/idp/mfastate"
	"github.com/croessner/nauthilus/v4/server/middleware/csrf"
	"github.com/croessner/nauthilus/v4/server/sessionstate"
	"github.com/gin-gonic/gin"
	"github.com/nicksnyder/go-i18n/v2/i18n"
)

func TestCanonicalTOTPWrongCodePreservesTicketAndCSRFThenCompletesOnce(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, flowID := seedCanonicalIDPFlow(t, canonicalDecisionOIDCState(""))
	authenticateCanonicalFixture(t, runtime, browserCookie)
	stepUpHandle := seedCanonicalTOTPStepUp(t, runtime, browserCookie, flowID)

	verificationCalls := 0
	handler := newLoginMFAViewHandler()
	handler.canonicalMFAAvailabilityResolver = canonicalTOTPAvailability
	handler.canonicalTOTPVerifier = func(
		_ *gin.Context,
		selection canonicalMFASelectionState,
		code string,
	) (bool, error) {
		verificationCalls++

		if selection.identity.Reference != "identity-42" || selection.identity.Account != "alice" ||
			selection.parent.FlowID != flowID || selection.stepUp.Value.Flow != sessionstate.Handle(flowID) {
			t.Fatalf("typed TOTP binding = identity %#v parent %#v step-up %#v",
				selection.identity, selection.parent, selection.stepUp.Value)
		}

		return code == "123456", nil
	}

	router, csrfHandler := canonicalTOTPTestRouter(t, runtime, handler)
	csrfCookie, firstToken := loadCanonicalTOTPForm(t, router, browserCookie, stepUpHandle)

	retry := postCanonicalTOTP(t, router, browserCookie, csrfCookie, stepUpHandle, firstToken, "000000")
	if retry.Code != http.StatusOK || !strings.Contains(retry.Body.String(), "error=true") {
		t.Fatalf("wrong-code response = %d %q, want retry form", retry.Code, retry.Body.String())
	}

	retryToken := canonicalTOTPTemplateValue(t, retry.Body.String(), "csrf")
	if retryToken == "" || canonicalTOTPTemplateValue(t, retry.Body.String(), "ticket") != string(stepUpHandle) {
		t.Fatalf("wrong-code retry lost bound state: %q", retry.Body.String())
	}

	assertCanonicalTOTPPending(t, runtime, browserCookie, stepUpHandle)

	success := postCanonicalTOTP(t, router, browserCookie, csrfCookie, stepUpHandle, retryToken, "123456")

	wantLocation := "/oidc/authorize?client_id=client-a&flow=" + flowID
	if success.Code != http.StatusFound || success.Header().Get("Location") != wantLocation {
		t.Fatalf("successful TOTP response = %d %q, want %d %q",
			success.Code, success.Header().Get("Location"), http.StatusFound, wantLocation)
	}

	assertCanonicalTOTPCompleted(t, runtime, browserCookie, stepUpHandle)

	replay := postCanonicalTOTP(t, router, browserCookie, csrfCookie, stepUpHandle, retryToken, "123456")
	if replay.Code != http.StatusConflict || verificationCalls != 2 {
		t.Fatalf("TOTP replay = status %d verifier calls %d, want %d/2",
			replay.Code, verificationCalls, http.StatusConflict)
	}

	_ = csrfHandler
}

func TestCanonicalLoginTOTPViewDoesNotExpose2FAHomeMenuBeforeCompletion(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, flowID := seedCanonicalIDPFlow(t, canonicalDecisionOIDCState(""))
	authenticateCanonicalFixture(t, runtime, browserCookie)
	stepUpHandle := seedCanonicalTOTPStepUp(t, runtime, browserCookie, flowID)

	handler := newLoginMFAViewHandler()
	handler.canonicalMFAAvailabilityResolver = canonicalTOTPAvailability
	router := gin.New()
	router.SetHTMLTemplate(loginMFATestTemplate())
	router.Use(loginMFAViewLocalizationMiddleware())
	router.GET(
		"/login/totp/:languageTag",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.LoginTOTP,
	)

	request := httptest.NewRequest(http.MethodGet, "/login/totp/de?flow="+string(stepUpHandle), nil)
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	if writer.Code != http.StatusOK || strings.Contains(writer.Body.String(), "2FA Verwaltung") {
		t.Fatalf("canonical TOTP view = status %d body %q, want 200 without self-service menu",
			writer.Code, writer.Body.String())
	}
}

func loginMFAViewLocalizationMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		localizer := i18n.NewLocalizer((&mockLangManager{}).GetBundle(), "de")
		ctx.Set(definitions.CtxLocalizedKey, localizer)
		ctx.Next()
	}
}

func seedCanonicalTOTPStepUp(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	flowID string,
) sessionstate.Handle {
	t.Helper()

	session := openCanonicalFixture(t, runtime, browserCookie)

	handle := sessionstate.Handle("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
	if err := mfastate.NewAggregate(session.Stores, session.Handle, 10*time.Minute).BeginStepUp(
		context.Background(),
		&sessionstate.StepUpRecord{
			Record: sessionstate.Record{Handle: handle}, Session: session.Handle,
			Flow: sessionstate.Handle(flowID), RequestedLevel: 2,
			SupportedMethods: []string{definitions.MFAMethodTOTP}, Scope: "oidc:client-a",
		},
	); err != nil {
		t.Fatalf("seed typed TOTP step-up: %v", err)
	}

	return handle
}

func canonicalTOTPAvailability(
	_ *gin.Context,
	_ *cookie.CanonicalSession,
	_ cookie.SessionIdentity,
	_ *flowdomain.State,
	_ []string,
) (mfaAvailability, error) {
	return mfaAvailability{haveTOTP: true, count: 1}, nil
}

func canonicalTOTPTestRouter(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	handler *FrontendHandler,
) (*gin.Engine, *csrf.DefaultHandler) {
	t.Helper()

	csrfHandler := csrf.NewHandler()
	router := gin.New()
	router.SetHTMLTemplate(template.Must(template.New("canonical-totp").Parse(
		`{{ define "idp_totp_verify.html" }}ticket={{ .FlowTicket }};csrf={{ .CSRFToken }};error={{ .HaveError }}{{ end }}`,
	)))
	router.Use(csrfHandler.Middleware())
	router.GET("/login/totp", cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation), handler.LoginTOTP)
	router.POST("/login/totp", cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation), handler.PostLoginTOTP)

	return router, csrfHandler
}

func loadCanonicalTOTPForm(
	t *testing.T,
	router http.Handler,
	browserCookie *http.Cookie,
	stepUpHandle sessionstate.Handle,
) (*http.Cookie, string) {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "https://idp.example.test/login/totp?flow="+string(stepUpHandle), nil)
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	if writer.Code != http.StatusOK {
		t.Fatalf("load canonical TOTP form status = %d, want %d", writer.Code, http.StatusOK)
	}

	var csrfCookie *http.Cookie

	for _, responseCookie := range writer.Result().Cookies() {
		if responseCookie.Name == csrf.CookieName {
			csrfCookie = responseCookie

			break
		}
	}

	if csrfCookie == nil {
		t.Fatal("canonical TOTP form did not issue CSRF cookie")
	}

	return csrfCookie, canonicalTOTPTemplateValue(t, writer.Body.String(), "csrf")
}

func postCanonicalTOTP(
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
	request := httptest.NewRequest(http.MethodPost, "https://idp.example.test/login/totp", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://idp.example.test")
	request.AddCookie(browserCookie)
	request.AddCookie(csrfCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	return writer
}

func canonicalTOTPTemplateValue(t *testing.T, body string, key string) string {
	t.Helper()

	prefix := key + "="

	start := strings.Index(body, prefix)
	if start < 0 {
		t.Fatalf("template output %q lacks %q", body, prefix)
	}

	value := body[start+len(prefix):]
	if end := strings.IndexByte(value, ';'); end >= 0 {
		value = value[:end]
	}

	return value
}

func assertCanonicalTOTPPending(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	stepUpHandle sessionstate.Handle,
) {
	t.Helper()

	session := openCanonicalFixture(t, runtime, browserCookie)

	loaded, err := mfastate.NewAggregate(session.Stores, session.Handle, 0).
		LoadStepUp(context.Background(), stepUpHandle)
	if err != nil || loaded.Value.Completed {
		t.Fatalf("wrong-code StepUp = %#v, err = %v, want pending", loaded.Value, err)
	}

	if _, ok := session.Assurance(session.EvaluationTime()); ok {
		t.Fatal("wrong-code request committed assurance")
	}
}

func assertCanonicalTOTPCompleted(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	stepUpHandle sessionstate.Handle,
) {
	t.Helper()

	session := openCanonicalFixture(t, runtime, browserCookie)

	loaded, err := mfastate.NewAggregate(session.Stores, session.Handle, 0).
		LoadStepUp(context.Background(), stepUpHandle)
	if err != nil || !loaded.Value.Completed || loaded.Value.ProofMethod != definitions.MFAMethodTOTP {
		t.Fatalf("successful TOTP StepUp = %#v, err = %v", loaded.Value, err)
	}

	assurance, ok := session.Assurance(session.EvaluationTime())
	if !ok || assurance.Level != 2 || assurance.Method != definitions.MFAMethodTOTP || assurance.Scope != "oidc:client-a" {
		t.Fatalf("successful TOTP assurance = %#v, ok = %t", assurance, ok)
	}
}
