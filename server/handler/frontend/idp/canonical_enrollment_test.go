// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//nolint:gocyclo,funlen // Enrollment tests keep each single-use browser lifecycle in one security contract.
package idp

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	flowdomain "github.com/croessner/nauthilus/v4/server/idp/flow"
	"github.com/croessner/nauthilus/v4/server/idp/mfastate"
	"github.com/croessner/nauthilus/v4/server/sessionstate"
	"github.com/gin-gonic/gin"
)

func TestCanonicalRecoveryEnrollmentGeneratesSavesAndAdvancesOnce(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, flowID := seedCanonicalIDPFlow(t, canonicalDecisionOIDCState(""))
	authenticateCanonicalFixture(t, runtime, browserCookie)
	enrollment := seedCanonicalEnrollmentForMethods(t, runtime, browserCookie, flowID,
		[]string{definitions.MFAMethodRecoveryCodes, definitions.MFAMethodWebAuthn})

	generatedCodes := []string{"recovery-one", "recovery-two"}
	generateCalls := 0
	saveCalls := 0
	operation := sessionstate.Handle("")
	handler := newLoginMFAViewHandler()
	handler.canonicalRecoveryEnrollmentGenerator = func(
		_ *gin.Context,
		selection canonicalEnrollmentSelectionState,
		pending sessionstate.Handle,
	) ([]string, error) {
		generateCalls++
		operation = pending

		assertCanonicalEnrollmentBinding(t, selection, flowID, enrollment, definitions.MFAMethodRecoveryCodes)

		return generatedCodes, nil
	}
	handler.canonicalRecoveryEnrollmentSaver = func(
		_ *gin.Context,
		selection canonicalEnrollmentSelectionState,
		pending sessionstate.Handle,
		codes []string,
	) error {
		saveCalls++

		assertCanonicalEnrollmentBinding(t, selection, flowID, enrollment, definitions.MFAMethodRecoveryCodes)

		if pending != operation || !slices.Equal(codes, generatedCodes) {
			t.Fatalf("canonical recovery save = operation %q codes %#v", pending, codes)
		}

		return nil
	}

	router := canonicalRecoveryEnrollmentRouter(runtime, handler)
	get := httptest.NewRequest(http.MethodGet, "/mfa/recovery/register?flow="+string(enrollment), nil)
	get.AddCookie(browserCookie)

	getWriter := httptest.NewRecorder()
	router.ServeHTTP(getWriter, get)

	if getWriter.Code != http.StatusOK || generateCalls != 1 ||
		!strings.Contains(getWriter.Body.String(), "operation="+string(operation)) ||
		!strings.Contains(getWriter.Body.String(), "recovery-one") {
		t.Fatalf("canonical recovery enrollment begin = status %d calls %d body %q",
			getWriter.Code, generateCalls, getWriter.Body.String())
	}

	assertCanonicalRecoveryPendingOperation(t, runtime, browserCookie, operation, enrollment, false)

	tampered := postCanonicalRecoverySave(router, browserCookie, enrollment, operation, []string{"attacker-value"})
	if tampered.Code != http.StatusConflict || saveCalls != 0 {
		t.Fatalf("canonical recovery tampered save = status %d calls %d", tampered.Code, saveCalls)
	}

	assertCanonicalRecoveryPendingOperation(t, runtime, browserCookie, operation, enrollment, false)

	saved := postCanonicalRecoverySave(router, browserCookie, enrollment, operation, generatedCodes)
	if saved.Code != http.StatusOK || saveCalls != 1 {
		t.Fatalf("canonical recovery save = status %d calls %d body %q", saved.Code, saveCalls, saved.Body.String())
	}

	assertCanonicalRecoveryPendingOperation(t, runtime, browserCookie, operation, enrollment, true)
	assertCanonicalEnrollmentStep(t, runtime, browserCookie, enrollment, definitions.MFAMethodRecoveryCodes, nil)

	repeatedSave := postCanonicalRecoverySave(router, browserCookie, enrollment, operation, generatedCodes)
	if repeatedSave.Code != http.StatusOK || saveCalls != 1 {
		t.Fatalf("canonical recovery repeated save = status %d calls %d", repeatedSave.Code, saveCalls)
	}

	continued := postCanonicalRecoveryContinue(router, browserCookie, enrollment, operation)

	wantNext := flowdomain.AppendTicket(definitions.MFARoot+"/webauthn/register", string(enrollment))
	if continued.Code != http.StatusSeeOther || continued.Header().Get("Location") != wantNext {
		t.Fatalf("canonical recovery continue = status %d redirect %q body %q",
			continued.Code, continued.Header().Get("Location"), continued.Body.String())
	}

	assertCanonicalEnrollmentStep(t, runtime, browserCookie, enrollment, definitions.MFAMethodWebAuthn,
		[]string{definitions.MFAMethodRecoveryCodes})
	assertCanonicalRecoveryOperationDeleted(t, runtime, browserCookie, operation)

	replay := postCanonicalRecoveryContinue(router, browserCookie, enrollment, operation)

	if replay.Code != http.StatusConflict || saveCalls != 1 {
		t.Fatalf("canonical recovery replay = status %d save calls %d", replay.Code, saveCalls)
	}
}

func TestCanonicalRecoveryEnrollmentAuthoritySaveDoesNotMutateTwice(t *testing.T) {
	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, canonicalDecisionOIDCState(""))

	session := openCanonicalFixture(t, runtime, browserCookie)
	if err := session.CommitIdentity(context.Background(), cookie.IdentityUpdate{
		Reference: "identity-42", Account: "alice", Subject: "identity-42", Protocol: "oidc",
		BackendAffinity: &cookie.SessionBackendAffinity{
			Type: "ldap", Name: "target", Protocol: "idp", Authority: "authority-a", OpaqueToken: "opaque-ref",
		},
	}); err != nil {
		t.Fatalf("commit authority identity: %v", err)
	}

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodPost, "/mfa/recovery/register/save", nil)
	handler := &FrontendHandler{}

	err := handler.persistCanonicalRecoveryEnrollment(ctx, canonicalEnrollmentSelectionState{
		session: session,
		identity: cookie.SessionIdentity{
			Reference: "identity-42", Account: "alice", Subject: "identity-42", Protocol: "oidc",
		},
	}, "operation", []string{"recovery-code"})
	if err != nil {
		t.Fatalf("persist authority recovery enrollment: %v", err)
	}
}

func TestCanonicalWebAuthnEnrollmentBindsCeremonyAndResumesOnce(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, flowID := seedCanonicalIDPFlow(t, canonicalDecisionOIDCState(""))
	authenticateCanonicalFixture(t, runtime, browserCookie)
	enrollment := seedCanonicalEnrollmentForMethods(t, runtime, browserCookie, flowID,
		[]string{definitions.MFAMethodWebAuthn})
	ceremony := sessionstate.Handle("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")

	beginCalls := 0
	finishCalls := 0
	handler := newLoginMFAViewHandler()
	handler.canonicalWebAuthnEnrollmentBegin = func(
		_ *gin.Context,
		selection canonicalEnrollmentSelectionState,
	) (any, sessionstate.Handle, error) {
		beginCalls++

		assertCanonicalEnrollmentBinding(t, selection, flowID, enrollment, definitions.MFAMethodWebAuthn)

		return map[string]any{"publicKey": map[string]any{"challenge": "opaque"}}, ceremony, nil
	}
	handler.canonicalWebAuthnEnrollmentFinish = func(
		_ *gin.Context,
		selection canonicalEnrollmentSelectionState,
		got sessionstate.Handle,
	) error {
		finishCalls++

		assertCanonicalEnrollmentBinding(t, selection, flowID, enrollment, definitions.MFAMethodWebAuthn)

		if got != ceremony {
			t.Fatalf("canonical WebAuthn enrollment ceremony = %q", got)
		}

		return nil
	}

	router := canonicalWebAuthnEnrollmentRouter(runtime, handler)

	page := getCanonicalEnrollmentRequest(router, browserCookie,
		"/mfa/webauthn/register?flow="+string(enrollment))
	if page.Code != http.StatusOK ||
		!strings.Contains(page.Body.String(), "flow="+string(enrollment)) {
		t.Fatalf("canonical WebAuthn enrollment page = status %d body %q", page.Code, page.Body.String())
	}

	begin := getCanonicalEnrollmentRequest(router, browserCookie,
		"/mfa/webauthn/register/begin?flow="+string(enrollment))

	var beginResponse canonicalWebAuthnBeginResponse
	if err := json.Unmarshal(begin.Body.Bytes(), &beginResponse); err != nil ||
		begin.Code != http.StatusOK || beginCalls != 1 || beginResponse.Ceremony != string(ceremony) {
		t.Fatalf("canonical WebAuthn enrollment begin = status %d calls %d response %#v err %v",
			begin.Code, beginCalls, beginResponse, err)
	}

	finish := postCanonicalWebAuthnEnrollment(router, browserCookie, enrollment, ceremony)

	var finishResponse webAuthnFinishResponse

	wantContinue := flowdomain.AppendTicket(definitions.MFARoot+"/register/continue", string(enrollment))
	if err := json.Unmarshal(finish.Body.Bytes(), &finishResponse); err != nil ||
		finish.Code != http.StatusOK || finishCalls != 1 ||
		finishResponse.Redirect != wantContinue {
		t.Fatalf("canonical WebAuthn enrollment finish = status %d calls %d response %#v err %v",
			finish.Code, finishCalls, finishResponse, err)
	}

	assertCanonicalEnrollmentCompleted(t, runtime, browserCookie, enrollment, definitions.MFAMethodWebAuthn)

	continued := getCanonicalEnrollmentRequest(router, browserCookie, finishResponse.Redirect)

	wantResume := "/oidc/authorize?client_id=client-a&flow=" + flowID
	if continued.Code != http.StatusSeeOther || continued.Header().Get("Location") != wantResume {
		t.Fatalf("canonical WebAuthn enrollment continuation = status %d location %q",
			continued.Code, continued.Header().Get("Location"))
	}

	replay := postCanonicalWebAuthnEnrollment(router, browserCookie, enrollment, ceremony)
	if replay.Code != http.StatusConflict || finishCalls != 1 {
		t.Fatalf("canonical WebAuthn enrollment replay = status %d calls %d", replay.Code, finishCalls)
	}
}

func TestCanonicalTOTPEnrollmentPersistsPendingMaterialAndAdvancesOnce(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, flowID := seedCanonicalIDPFlow(t, canonicalDecisionOIDCState(""))
	authenticateCanonicalFixture(t, runtime, browserCookie)
	enrollment := seedCanonicalEnrollment(t, runtime, browserCookie, flowID)

	beginCalls := 0
	finishCalls := 0
	operation := sessionstate.Handle("")
	handler := newLoginMFAViewHandler()
	handler.canonicalTOTPEnrollmentStarter = func(
		_ *gin.Context,
		selection canonicalEnrollmentSelectionState,
		pending sessionstate.Handle,
	) (canonicalTOTPEnrollmentPending, error) {
		beginCalls++
		operation = pending

		assertCanonicalEnrollmentBinding(t, selection, flowID, enrollment, definitions.MFAMethodTOTP)

		return canonicalTOTPEnrollmentPending{
			Secret: "opaque-totp-secret", QRCodeURL: "otpauth://opaque",
		}, nil
	}
	handler.canonicalTOTPEnrollmentFinisher = func(
		_ *gin.Context,
		selection canonicalEnrollmentSelectionState,
		pending canonicalTOTPEnrollmentPending,
		operationHandle sessionstate.Handle,
		code string,
	) (bool, error) {
		finishCalls++

		assertCanonicalEnrollmentBinding(t, selection, flowID, enrollment, definitions.MFAMethodTOTP)

		if operationHandle != operation || pending.Secret != "opaque-totp-secret" {
			t.Fatalf("canonical TOTP finish = operation %q pending %#v", operationHandle, pending)
		}

		return code == "123456", nil
	}

	router := canonicalTOTPEnrollmentRouter(runtime, handler)
	get := httptest.NewRequest(http.MethodGet, "/mfa/totp/register?flow="+string(enrollment), nil)
	get.AddCookie(browserCookie)

	getWriter := httptest.NewRecorder()
	router.ServeHTTP(getWriter, get)

	if getWriter.Code != http.StatusOK || beginCalls != 1 ||
		!strings.Contains(getWriter.Body.String(), "operation="+string(operation)) ||
		!strings.Contains(getWriter.Body.String(), "flow="+string(enrollment)) {
		t.Fatalf("canonical TOTP enrollment begin = status %d calls %d body %q",
			getWriter.Code, beginCalls, getWriter.Body.String())
	}

	assertCanonicalTOTPPendingOperation(t, runtime, browserCookie, operation, enrollment, false)

	wrong := postCanonicalTOTPEnrollment(router, browserCookie, enrollment, operation, "000000")
	if wrong.Code != http.StatusOK || finishCalls != 1 ||
		!strings.Contains(wrong.Body.String(), "Failed to register TOTP") {
		t.Fatalf("canonical TOTP enrollment wrong code = status %d calls %d body %q",
			wrong.Code, finishCalls, wrong.Body.String())
	}

	assertCanonicalEnrollmentStep(t, runtime, browserCookie, enrollment, definitions.MFAMethodTOTP, nil)
	assertCanonicalTOTPPendingOperation(t, runtime, browserCookie, operation, enrollment, false)

	post := postCanonicalTOTPEnrollment(router, browserCookie, enrollment, operation, "123456")

	wantNext := flowdomain.AppendTicket(definitions.MFARoot+"/webauthn/register", string(enrollment))
	if post.Code != http.StatusOK || post.Header().Get("HX-Redirect") != wantNext || finishCalls != 2 {
		t.Fatalf("canonical TOTP enrollment finish = status %d redirect %q calls %d",
			post.Code, post.Header().Get("HX-Redirect"), finishCalls)
	}

	assertCanonicalEnrollmentStep(t, runtime, browserCookie, enrollment, definitions.MFAMethodWebAuthn,
		[]string{definitions.MFAMethodTOTP})

	replay := postCanonicalTOTPEnrollment(router, browserCookie, enrollment, operation, "123456")
	if replay.Code != http.StatusConflict || finishCalls != 2 {
		t.Fatalf("canonical TOTP enrollment replay = status %d calls %d", replay.Code, finishCalls)
	}
}

func TestCanonicalRequiredMFAContinueConsumesCompletedEnrollmentOnce(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, flowID := seedCanonicalIDPFlow(t, canonicalDecisionOIDCState(""))
	authenticateCanonicalFixture(t, runtime, browserCookie)
	enrollment := seedCanonicalEnrollmentForMethods(t, runtime, browserCookie, flowID,
		[]string{definitions.MFAMethodWebAuthn})

	session := openCanonicalFixture(t, runtime, browserCookie)
	if _, err := mfastate.NewAggregate(session.Stores, session.Handle, canonicalEnrollmentTTL).
		CompleteEnrollmentMethod(context.Background(), enrollment, definitions.MFAMethodWebAuthn); err != nil {
		t.Fatalf("complete enrollment fixture: %v", err)
	}

	handler := &FrontendHandler{}
	router := gin.New()
	router.GET(
		definitions.MFARoot+"/register/continue",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.CanonicalAuthMiddleware(),
		handler.ContinueRequiredMFARegistration,
	)
	target := flowdomain.AppendTicket(definitions.MFARoot+"/register/continue", string(enrollment))

	continued := getCanonicalEnrollmentRequest(router, browserCookie, target)

	want := "/oidc/authorize?client_id=client-a&flow=" + flowID
	if continued.Code != http.StatusSeeOther || continued.Header().Get("Location") != want {
		t.Fatalf("canonical enrollment continue = status %d location %q, want %d %q",
			continued.Code, continued.Header().Get("Location"), http.StatusSeeOther, want)
	}

	if _, err := mfastate.NewAggregate(session.Stores, session.Handle, 0).
		LoadEnrollment(context.Background(), enrollment); !errors.Is(err, sessionstate.ErrNotFound) {
		t.Fatalf("completed enrollment still reachable after continue: %v", err)
	}

	replay := getCanonicalEnrollmentRequest(router, browserCookie, target)
	if replay.Code != http.StatusConflict {
		t.Fatalf("canonical enrollment continue replay = %d, want %d", replay.Code, http.StatusConflict)
	}
}

func TestCanonicalRequiredMFACancelDeletesOnlyBoundEnrollmentAndParentFlow(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, flowID := seedCanonicalIDPFlow(t, canonicalDecisionOIDCState(""))
	authenticateCanonicalFixture(t, runtime, browserCookie)
	enrollment := seedCanonicalEnrollmentForMethods(t, runtime, browserCookie, flowID,
		[]string{definitions.MFAMethodWebAuthn})
	session := openCanonicalFixture(t, runtime, browserCookie)

	handler := &FrontendHandler{}
	router := gin.New()
	router.GET(
		definitions.MFARoot+"/register/cancel",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.CanonicalAuthMiddleware(),
		handler.CancelRequiredMFARegistration,
	)
	target := flowdomain.AppendTicket(definitions.MFARoot+"/register/cancel", string(enrollment))

	canceled := getCanonicalEnrollmentRequest(router, browserCookie, target)
	if canceled.Code != http.StatusSeeOther || canceled.Header().Get("Location") != "/logged_out" {
		t.Fatalf("canonical enrollment cancel = status %d location %q",
			canceled.Code, canceled.Header().Get("Location"))
	}

	assertCanonicalBrowserEnvelopePurged(t, canceled)

	if _, err := mfastate.NewAggregate(session.Stores, session.Handle, 0).
		LoadEnrollment(context.Background(), enrollment); !errors.Is(err, sessionstate.ErrNotFound) {
		t.Fatalf("canceled enrollment still reachable: %v", err)
	}

	if _, err := flowdomain.NewProtocolAggregate(session.Stores, session.Handle, 0).
		Load(context.Background(), flowID); !errors.Is(err, flowdomain.ErrFlowNotFound) {
		t.Fatalf("canceled parent flow still reachable: %v", err)
	}

	replay := getCanonicalEnrollmentRequest(router, browserCookie, target)
	if replay.Code != http.StatusConflict {
		t.Fatalf("canonical enrollment cancel replay = %d, want %d", replay.Code, http.StatusConflict)
	}
}

func canonicalTOTPEnrollmentRouter(
	runtime *cookie.CanonicalRuntime,
	handler *FrontendHandler,
) *gin.Engine {
	router := gin.New()
	router.SetHTMLTemplate(template.Must(template.New("canonical-totp-enrollment").Parse(
		`{{ define "idp_totp_register.html" }}post={{ .PostTOTPRegisterPath }};secret={{ .Secret }}{{ end }}
{{ define "idp_error_modal.html" }}{{ .Message }}{{ end }}`,
	)))
	router.GET(
		"/mfa/totp/register",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.RegisterTOTP,
	)
	router.POST(
		"/mfa/totp/register",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.PostRegisterTOTP,
	)

	return router
}

func canonicalRecoveryEnrollmentRouter(
	runtime *cookie.CanonicalRuntime,
	handler *FrontendHandler,
) *gin.Engine {
	router := gin.New()
	router.SetHTMLTemplate(template.Must(template.New("canonical-recovery-enrollment").Parse(
		`{{ define "idp_recovery_codes_register.html" }}save={{ .SaveRecoveryCodesEndpoint }};continue={{ .PostRecoveryRegisterEndpoint }};{{ range .Codes }}code={{ . }};{{ end }}{{ end }}`,
	)))
	router.GET(
		"/mfa/recovery/register",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.RegisterRecoveryCodes,
	)
	router.POST(
		"/mfa/recovery/register/save",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.SaveRecoveryCodes,
	)
	router.POST(
		"/mfa/recovery/register",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.PostRegisterRecoveryCodes,
	)

	return router
}

func canonicalWebAuthnEnrollmentRouter(
	runtime *cookie.CanonicalRuntime,
	handler *FrontendHandler,
) *gin.Engine {
	router := gin.New()
	router.SetHTMLTemplate(template.Must(template.New("canonical-webauthn-enrollment").Parse(
		`{{ define "idp_webauthn_register.html" }}begin={{ .WebAuthnBeginEndpoint }};finish={{ .WebAuthnFinishEndpoint }}{{ end }}`,
	)))

	middleware := cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation)
	router.GET("/mfa/webauthn/register", middleware, handler.RegisterWebAuthn)
	router.GET("/mfa/webauthn/register/begin", middleware, handler.BeginWebAuthnRegistration)
	router.POST("/mfa/webauthn/register/finish", middleware, handler.FinishWebAuthnRegistration)
	router.GET("/mfa/register/continue", middleware, handler.ContinueRequiredMFARegistration)

	return router
}

func assertCanonicalBrowserEnvelopePurged(t *testing.T, writer *httptest.ResponseRecorder) {
	t.Helper()

	for _, responseCookie := range writer.Result().Cookies() {
		if responseCookie.Name == definitions.SecureDataCookieName && responseCookie.MaxAge < 0 {
			return
		}
	}

	t.Fatal("canonical browser envelope was not purged")
}

func getCanonicalEnrollmentRequest(
	router http.Handler,
	browserCookie *http.Cookie,
	target string,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	return writer
}

func postCanonicalWebAuthnEnrollment(
	router http.Handler,
	browserCookie *http.Cookie,
	enrollment sessionstate.Handle,
	ceremony sessionstate.Handle,
) *httptest.ResponseRecorder {
	target := "/mfa/webauthn/register/finish?flow=" + string(enrollment) + "&ceremony=" + string(ceremony)
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(`{"name":"security key","credential":{}}`))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	return writer
}

func postCanonicalRecoverySave(
	router http.Handler,
	browserCookie *http.Cookie,
	enrollment sessionstate.Handle,
	operation sessionstate.Handle,
	codes []string,
) *httptest.ResponseRecorder {
	body, err := json.Marshal(recoveryCodesPayload{Codes: codes})
	if err != nil {
		panic(err)
	}

	target := "/mfa/recovery/register/save?flow=" + string(enrollment) + "&operation=" + string(operation)
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	return writer
}

func postCanonicalRecoveryContinue(
	router http.Handler,
	browserCookie *http.Cookie,
	enrollment sessionstate.Handle,
	operation sessionstate.Handle,
) *httptest.ResponseRecorder {
	target := "/mfa/recovery/register?flow=" + string(enrollment) + "&operation=" + string(operation)
	request := httptest.NewRequest(http.MethodPost, target, nil)
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	return writer
}

func postCanonicalTOTPEnrollment(
	router http.Handler,
	browserCookie *http.Cookie,
	enrollment sessionstate.Handle,
	operation sessionstate.Handle,
	code string,
) *httptest.ResponseRecorder {
	form := url.Values{"code": {code}}
	target := "/mfa/totp/register?flow=" + string(enrollment) + "&operation=" + string(operation)
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("HX-Request", "true")
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	return writer
}

func seedCanonicalEnrollment(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	flowID string,
) sessionstate.Handle {
	t.Helper()

	return seedCanonicalEnrollmentForMethods(t, runtime, browserCookie, flowID,
		[]string{definitions.MFAMethodTOTP, definitions.MFAMethodWebAuthn})
}

func seedCanonicalEnrollmentForMethods(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	flowID string,
	methods []string,
) sessionstate.Handle {
	t.Helper()

	session := openCanonicalFixture(t, runtime, browserCookie)
	handle := sessionstate.Handle("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")

	record := &sessionstate.EnrollmentRecord{
		Record: sessionstate.Record{Handle: handle}, Session: session.Handle,
		Flow: sessionstate.Handle(flowID), AccountReference: "alice", IdentityReference: "identity-42",
		RequiredMethods: methods, CurrentStep: methods[0],
		Continuation: "/oidc/authorize?client_id=client-a&flow=" + flowID,
	}
	if err := mfastate.NewAggregate(session.Stores, session.Handle, 15*time.Minute).
		BeginEnrollment(context.Background(), record); err != nil {
		t.Fatalf("seed canonical enrollment: %v", err)
	}

	return handle
}

func assertCanonicalRecoveryPendingOperation(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	operation sessionstate.Handle,
	enrollment sessionstate.Handle,
	wantSaved bool,
) {
	t.Helper()

	session := openCanonicalFixture(t, runtime, browserCookie)

	loaded, err := mfastate.NewAggregate(session.Stores, session.Handle, 0).
		LoadTOTPRecovery(context.Background(), operation)
	if err != nil || loaded.Value.Flow != enrollment || loaded.Value.IdentityReference != "identity-42" ||
		loaded.Value.AccountReference != "alice" || !loaded.Value.Generated || loaded.Value.Saved != wantSaved ||
		!slices.Equal(loaded.Value.RecoveryCodes, []string{"recovery-one", "recovery-two"}) {
		t.Fatalf("canonical recovery pending operation = %#v, err = %v", loaded.Value, err)
	}
}

func assertCanonicalRecoveryOperationDeleted(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	operation sessionstate.Handle,
) {
	t.Helper()

	session := openCanonicalFixture(t, runtime, browserCookie)

	_, err := mfastate.NewAggregate(session.Stores, session.Handle, 0).
		LoadTOTPRecovery(context.Background(), operation)
	if !errors.Is(err, sessionstate.ErrNotFound) {
		t.Fatalf("canonical recovery operation after completion err = %v", err)
	}
}

func assertCanonicalEnrollmentCompleted(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	enrollment sessionstate.Handle,
	method string,
) {
	t.Helper()

	session := openCanonicalFixture(t, runtime, browserCookie)

	loaded, err := mfastate.NewAggregate(session.Stores, session.Handle, 0).
		LoadEnrollment(context.Background(), enrollment)
	if err != nil || !loaded.Value.Completed || loaded.Value.CurrentStep != "complete" ||
		!slices.Equal(loaded.Value.CompletedMethods, []string{method}) {
		t.Fatalf("canonical enrollment completion = %#v, err = %v", loaded.Value, err)
	}
}

func assertCanonicalEnrollmentBinding(
	t *testing.T,
	selection canonicalEnrollmentSelectionState,
	flowID string,
	enrollment sessionstate.Handle,
	method string,
) {
	t.Helper()

	if selection.identity.Reference != "identity-42" || selection.identity.Account != "alice" ||
		selection.parent.FlowID != flowID || selection.enrollment.Value.Handle != enrollment ||
		selection.enrollment.Value.CurrentStep != method {
		t.Fatalf("canonical enrollment binding = identity %#v parent %#v enrollment %#v",
			selection.identity, selection.parent, selection.enrollment.Value)
	}
}

func assertCanonicalEnrollmentStep(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	enrollment sessionstate.Handle,
	want string,
	wantCompleted []string,
) {
	t.Helper()

	session := openCanonicalFixture(t, runtime, browserCookie)

	loaded, err := mfastate.NewAggregate(session.Stores, session.Handle, 0).
		LoadEnrollment(context.Background(), enrollment)
	if err != nil || loaded.Value.CurrentStep != want ||
		!slices.Equal(loaded.Value.CompletedMethods, wantCompleted) {
		t.Fatalf("canonical enrollment after TOTP = %#v, err = %v", loaded.Value, err)
	}
}

func assertCanonicalTOTPPendingOperation(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	operation sessionstate.Handle,
	enrollment sessionstate.Handle,
	wantSaved bool,
) {
	t.Helper()

	session := openCanonicalFixture(t, runtime, browserCookie)

	loaded, err := mfastate.NewAggregate(session.Stores, session.Handle, 0).
		LoadTOTPRecovery(context.Background(), operation)
	if err != nil || loaded.Value.Flow != enrollment || loaded.Value.IdentityReference != "identity-42" ||
		loaded.Value.AccountReference != "alice" || !loaded.Value.Generated || loaded.Value.Saved != wantSaved ||
		len(loaded.Value.PendingMaterial) == 0 {
		t.Fatalf("canonical TOTP pending operation = %#v, err = %v", loaded.Value, err)
	}
}
