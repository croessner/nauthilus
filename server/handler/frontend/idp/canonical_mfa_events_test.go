// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	flowdomain "github.com/croessner/nauthilus/v4/server/idp/flow"
	"github.com/croessner/nauthilus/v4/server/sessionstate"
	"github.com/gin-gonic/gin"
)

// recordingAuthEventEmitter captures emitted step events.
type recordingAuthEventEmitter struct {
	events []pluginapi.AuthEvent
	mu     sync.Mutex
}

// EmitAuthEvent records one event.
func (e *recordingAuthEventEmitter) EmitAuthEvent(_ context.Context, event pluginapi.AuthEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.events = append(e.events, event)
}

// snapshot returns the recorded events.
func (e *recordingAuthEventEmitter) snapshot() []pluginapi.AuthEvent {
	e.mu.Lock()
	defer e.mu.Unlock()

	return append([]pluginapi.AuthEvent(nil), e.events...)
}

// TestCanonicalFailLatchedRecoveryEmitsPrimaryFailureKeptEvent pins that a correct factor on a fail-latched flow is
// recorded as a verified factor that keeps the primary failure, and that replays without a selectable step-up emit
// nothing.
func TestCanonicalFailLatchedRecoveryEmitsPrimaryFailureKeptEvent(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, flowID, stepUp := seedCanonicalFailLatchedMFA(t, definitions.MFAMethodRecoveryCodes, 1)
	handler, emitter := newRecoveryEventHandler(t, "recovery-good")
	router := newRecoveryEventRouter(runtime, handler)

	if code := postRecoveryCode(router, browserCookie, stepUp, "recovery-good"); code != http.StatusUnauthorized {
		t.Fatalf("fail-latched recovery status = %d, want %d", code, http.StatusUnauthorized)
	}

	if code := postRecoveryCode(router, browserCookie, stepUp, "recovery-good"); code != http.StatusConflict {
		t.Fatalf("fail-latched recovery replay status = %d, want %d", code, http.StatusConflict)
	}

	events := emitter.snapshot()
	if len(events) != 1 {
		t.Fatalf("events = %#v, want exactly one verification event", events)
	}

	assertMFAEvent(t, events[0], pluginapi.AuthEventSuccess, "verified", pluginapi.AuthEventFlowPrimaryFailureKept)

	if !events[0].FailLatched || events[0].FlowRef != flowdomain.DiagnosticFlowRef(flowID) ||
		events[0].Method != definitions.MFAMethodRecoveryCodes || events[0].Protocol != string(flowdomain.FlowProtocolOIDC) {
		t.Fatalf("event correlation = %+v, want fail-latched OIDC recovery with derived flow_ref", events[0])
	}

	assertMFAEventHasNoHandles(t, events[0], flowID, string(stepUp))
}

// TestCanonicalFailLatchedRecoveryInvalidCodeEmitsInvalidEvent pins that a wrong code is a separate invalid attempt.
func TestCanonicalFailLatchedRecoveryInvalidCodeEmitsInvalidEvent(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, _, stepUp := seedCanonicalFailLatchedMFA(t, definitions.MFAMethodRecoveryCodes, 1)
	handler, emitter := newRecoveryEventHandler(t, "recovery-good")
	router := newRecoveryEventRouter(runtime, handler)

	postRecoveryCode(router, browserCookie, stepUp, "recovery-wrong")
	postRecoveryCode(router, browserCookie, stepUp, "recovery-good")

	events := emitter.snapshot()
	if len(events) != 2 {
		t.Fatalf("events = %#v, want invalid then verified", events)
	}

	assertMFAEvent(t, events[0], pluginapi.AuthEventInvalid, "invalid_code", pluginapi.AuthEventFlowNone)
	assertMFAEvent(t, events[1], pluginapi.AuthEventSuccess, "verified", pluginapi.AuthEventFlowPrimaryFailureKept)

	if events[0].EventID == "" || events[0].EventID == events[1].EventID {
		t.Fatalf("event IDs = %q/%q, want distinct non-empty IDs per attempt", events[0].EventID, events[1].EventID)
	}
}

// TestCanonicalWebAuthnFinishFailuresEmitTypedEvents pins the typed classification of WebAuthn finish failures.
func TestCanonicalWebAuthnFinishFailuresEmitTypedEvents(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		err        error
		name       string
		wantResult pluginapi.AuthEventResult
		wantReason string
	}{
		{name: "assertion rejected", err: core.ErrWebAuthnAssertionRejected,
			wantResult: pluginapi.AuthEventInvalid, wantReason: "assertion_rejected"},
		{name: "ceremony unavailable", err: core.ErrWebAuthnCeremonyUnavailable,
			wantResult: pluginapi.AuthEventInvalid, wantReason: "ceremony_unavailable"},
		{name: "state error", err: fmt.Errorf("%w: store down", core.ErrWebAuthnStateUnavailable),
			wantResult: pluginapi.AuthEventError, wantReason: "verifier_error"},
		{name: "backend lookup error", err: errors.New("backend unavailable"),
			wantResult: pluginapi.AuthEventError, wantReason: "verifier_error"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			runtime, browserCookie, _, stepUp := seedCanonicalFailLatchedMFA(t, definitions.MFAMethodWebAuthn, 2)
			handler := newLoginMFAViewHandler(t)
			emitter := &recordingAuthEventEmitter{}
			handler.canonicalAuthEventEmitter = emitter
			handler.canonicalWebAuthnFinish = func(
				*gin.Context, canonicalMFASelectionState, sessionstate.Handle,
			) (*backend.User, error) {
				return nil, testCase.err
			}

			router := gin.New()
			router.POST("/login/webauthn/finish",
				cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation), handler.PostLoginWebAuthnFinish)

			request := httptest.NewRequest(http.MethodPost, "/login/webauthn/finish?flow="+string(stepUp)+
				"&ceremony=WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW", strings.NewReader(`{"id":"opaque"}`))
			request.Header.Set("Content-Type", "application/json")
			request.AddCookie(browserCookie)
			router.ServeHTTP(httptest.NewRecorder(), request)

			events := emitter.snapshot()
			if len(events) != 1 {
				t.Fatalf("events = %#v, want one", events)
			}

			assertMFAEvent(t, events[0], testCase.wantResult, testCase.wantReason, pluginapi.AuthEventFlowNone)
		})
	}
}

// newRecoveryEventHandler returns a handler whose recovery verifier accepts one code and records events.
func newRecoveryEventHandler(t *testing.T, accepted string) (*FrontendHandler, *recordingAuthEventEmitter) {
	t.Helper()

	handler := newLoginMFAViewHandler(t)
	emitter := &recordingAuthEventEmitter{}
	handler.canonicalAuthEventEmitter = emitter
	handler.canonicalRecoveryVerifier = func(_ *gin.Context, _ canonicalMFASelectionState, code string) (bool, error) {
		return code == accepted, nil
	}

	return handler, emitter
}

// newRecoveryEventRouter mounts the recovery endpoint behind the canonical session middleware.
func newRecoveryEventRouter(runtime *cookie.CanonicalRuntime, handler *FrontendHandler) *gin.Engine {
	router := gin.New()
	router.SetHTMLTemplate(template.Must(template.New("idp_recovery_login.html").Parse("recovery")))
	router.POST("/login/recovery", cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation), handler.PostLoginRecovery)

	return router
}

// postRecoveryCode submits one recovery code and returns the response status.
func postRecoveryCode(router *gin.Engine, browserCookie *http.Cookie, stepUp sessionstate.Handle, code string) int {
	form := url.Values{"flow": {string(stepUp)}, "code": {code}}
	request := httptest.NewRequest(http.MethodPost, "/login/recovery", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	return writer.Code
}

// assertMFAEvent compares the stable classification of one event.
func assertMFAEvent(
	t *testing.T,
	event pluginapi.AuthEvent,
	result pluginapi.AuthEventResult,
	reason string,
	flowEffect pluginapi.AuthEventFlowEffect,
) {
	t.Helper()

	if event.Type != pluginapi.AuthEventMFAVerification || event.Version != pluginapi.AuthEventVersion ||
		event.Result != result || event.Reason != reason || event.FlowEffect != flowEffect ||
		event.FactorRole != pluginapi.AuthEventFactorRoleSecond || event.ObservedAt.IsZero() {
		t.Fatalf("event = %+v, want %s/%s/%s", event, result, reason, flowEffect)
	}
}

// assertMFAEventHasNoHandles proves that no authorizing handle leaks into the event.
func assertMFAEventHasNoHandles(t *testing.T, event pluginapi.AuthEvent, handles ...string) {
	t.Helper()

	serialized := fmt.Sprintf("%#v", event)
	for _, handle := range handles {
		if handle != "" && strings.Contains(serialized, handle) {
			t.Fatalf("event %s contains an authorizing handle", serialized)
		}
	}
}

// TestCanonicalStepUpFailuresKeepStatusAndEmitTypedEvents pins the shared step-up failure mapping: the HTTP answer of
// every path is unchanged and each path emits its stable event outcome.
func TestCanonicalStepUpFailuresKeepStatusAndEmitTypedEvents(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		answer     func(*FrontendHandler, *gin.Context, canonicalMFASelectionState)
		name       string
		wantResult pluginapi.AuthEventResult
		wantReason string
		wantEffect pluginapi.AuthEventFlowEffect
		wantStatus int
	}{
		{name: "binding mismatch", answer: stepUpErrorAnswer(sessionstate.ErrBindingMismatch),
			wantStatus: http.StatusConflict, wantResult: pluginapi.AuthEventRejected, wantReason: "step_up_conflict"},
		{name: "revision conflict", answer: stepUpErrorAnswer(sessionstate.ErrRevisionConflict),
			wantStatus: http.StatusConflict, wantResult: pluginapi.AuthEventRejected, wantReason: "step_up_conflict"},
		{name: "expired", answer: stepUpErrorAnswer(sessionstate.ErrExpired),
			wantStatus: http.StatusConflict, wantResult: pluginapi.AuthEventRejected, wantReason: "step_up_expired"},
		{name: "not found outside fail-latched", answer: stepUpErrorAnswer(sessionstate.ErrNotFound),
			wantStatus: http.StatusServiceUnavailable, wantResult: pluginapi.AuthEventError, wantReason: "state_error"},
		{name: "store error", answer: stepUpErrorAnswer(errors.New("store down")),
			wantStatus: http.StatusServiceUnavailable, wantResult: pluginapi.AuthEventError, wantReason: "state_error"},
		{name: "resume conflict", wantStatus: http.StatusConflict, wantResult: pluginapi.AuthEventRejected,
			wantReason: "resume_conflict", wantEffect: pluginapi.AuthEventFlowStepUpCompleted,
			answer: func(h *FrontendHandler, ctx *gin.Context, selection canonicalMFASelectionState) {
				h.answerCanonicalResumeConflict(ctx, selection, definitions.MFAMethodTOTP)
			}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			emitter := &recordingAuthEventEmitter{}
			handler := &FrontendHandler{canonicalAuthEventEmitter: emitter}
			writer := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(writer)
			ctx.Request = httptest.NewRequest(http.MethodPost, "/login/totp", nil)

			testCase.answer(handler, ctx, canonicalMFASelectionState{})

			wantEffect := testCase.wantEffect
			if wantEffect == "" {
				wantEffect = pluginapi.AuthEventFlowNone
			}

			events := emitter.snapshot()
			if ctx.Writer.Status() != testCase.wantStatus || len(events) != 1 {
				t.Fatalf("status/events = %d/%d, want %d/1", ctx.Writer.Status(), len(events), testCase.wantStatus)
			}

			assertMFAEvent(t, events[0], testCase.wantResult, testCase.wantReason, wantEffect)

			if events[0].FlowRef != "" || events[0].Protocol != canonicalSelfServiceProtocol {
				t.Fatalf("event without parent flow = %+v, want empty flow_ref and account protocol", events[0])
			}
		})
	}
}

// stepUpErrorAnswer returns a test step that answers one step-up state error.
func stepUpErrorAnswer(err error) func(*FrontendHandler, *gin.Context, canonicalMFASelectionState) {
	return func(h *FrontendHandler, ctx *gin.Context, selection canonicalMFASelectionState) {
		h.answerCanonicalStepUpError(ctx, selection, definitions.MFAMethodTOTP, err)
	}
}
