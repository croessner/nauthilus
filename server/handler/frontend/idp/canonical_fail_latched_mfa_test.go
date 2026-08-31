// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

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

	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	flowdomain "github.com/croessner/nauthilus/v4/server/idp/flow"
	"github.com/croessner/nauthilus/v4/server/idp/mfastate"
	"github.com/croessner/nauthilus/v4/server/sessionstate"
	"github.com/gin-gonic/gin"
)

func TestCanonicalFailLatchedWebAuthnProofTerminatesWithoutAuthentication(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, flowID, stepUp := seedCanonicalFailLatchedMFA(
		t, definitions.MFAMethodWebAuthn,
	)
	handler := newLoginMFAViewHandler()
	finishCalls := 0
	handler.canonicalWebAuthnFinish = func(
		_ *gin.Context,
		selection canonicalMFASelectionState,
		_ sessionstate.Handle,
	) (*backend.User, error) {
		finishCalls++

		assertFailLatchedMFASelection(t, selection, flowID)

		return nil, nil
	}
	router := gin.New()
	router.POST(
		"/login/webauthn/finish",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.PostLoginWebAuthnFinish,
	)

	endpoint := "/login/webauthn/finish?flow=" + string(stepUp) +
		"&ceremony=WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW"
	request := httptest.NewRequest(http.MethodPost, endpoint, strings.NewReader(`{"id":"opaque"}`))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	if writer.Code != http.StatusUnauthorized {
		t.Fatalf("fail-latched WebAuthn status = %d, want %d", writer.Code, http.StatusUnauthorized)
	}

	assertCanonicalFailLatchedMFAConsumed(t, runtime, browserCookie, flowID, stepUp)

	replay := httptest.NewRequest(http.MethodPost, endpoint, strings.NewReader(`{"id":"opaque"}`))
	replay.Header.Set("Content-Type", "application/json")
	replay.AddCookie(browserCookie)

	replayWriter := httptest.NewRecorder()
	router.ServeHTTP(replayWriter, replay)

	if replayWriter.Code != http.StatusConflict || finishCalls != 1 {
		t.Fatalf("fail-latched WebAuthn replay = status %d calls %d, want %d/1",
			replayWriter.Code, finishCalls, http.StatusConflict)
	}
}

func TestCanonicalFailLatchedRecoveryProofTerminatesWithoutAuthentication(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, flowID, stepUp := seedCanonicalFailLatchedMFA(
		t, definitions.MFAMethodRecoveryCodes,
	)
	handler := newLoginMFAViewHandler()
	verifyCalls := 0
	handler.canonicalRecoveryVerifier = func(
		_ *gin.Context,
		selection canonicalMFASelectionState,
		code string,
	) (bool, error) {
		verifyCalls++

		assertFailLatchedMFASelection(t, selection, flowID)

		return code == "recovery-good", nil
	}
	router := gin.New()
	router.POST(
		"/login/recovery",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.PostLoginRecovery,
	)

	form := url.Values{"flow": {string(stepUp)}, "code": {"recovery-good"}}
	request := httptest.NewRequest(http.MethodPost, "/login/recovery", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	if writer.Code != http.StatusUnauthorized {
		t.Fatalf("fail-latched recovery status = %d, want %d", writer.Code, http.StatusUnauthorized)
	}

	assertCanonicalFailLatchedMFAConsumed(t, runtime, browserCookie, flowID, stepUp)

	replay := httptest.NewRequest(http.MethodPost, "/login/recovery", strings.NewReader(form.Encode()))
	replay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replay.AddCookie(browserCookie)

	replayWriter := httptest.NewRecorder()
	router.ServeHTTP(replayWriter, replay)

	if replayWriter.Code != http.StatusConflict || verifyCalls != 1 {
		t.Fatalf("fail-latched recovery replay = status %d calls %d, want %d/1",
			replayWriter.Code, verifyCalls, http.StatusConflict)
	}
}

// seedCanonicalFailLatchedMFA creates one unauthenticated delayed-response challenge.
func seedCanonicalFailLatchedMFA(
	t *testing.T,
	method string,
) (*cookie.CanonicalRuntime, *http.Cookie, string, sessionstate.Handle) {
	t.Helper()

	state := canonicalDecisionOIDCState("")
	state.AuthOutcome = flowdomain.AuthOutcomeFailLatched
	runtime, browserCookie, flowID := seedCanonicalIDPFlow(t, state)
	session := openCanonicalFixture(t, runtime, browserCookie)

	handle, err := sessionstate.NewRandomHandleGenerator(nil).NewHandle()
	if err != nil {
		t.Fatalf("create fail-latched step-up handle: %v", err)
	}

	record := &sessionstate.StepUpRecord{
		Record: sessionstate.Record{Handle: handle}, Session: session.Handle,
		Flow: sessionstate.Handle(flowID), AuthOutcome: string(flowdomain.AuthOutcomeFailLatched),
		PendingIdentityReference: "identity-42",
		PendingIdentity: sessionstate.IdentitySummary{
			Account: "alice", Subject: "identity-42", DisplayName: "Alice", Protocol: "oidc",
		},
		RequestedLevel: 2, SupportedMethods: []string{method}, Scope: "oidc:client-a",
	}
	if err = mfastate.NewAggregate(session.Stores, session.Handle, 10*time.Minute).
		BeginStepUp(context.Background(), record); err != nil {
		t.Fatalf("begin fail-latched step-up: %v", err)
	}

	return runtime, browserCookie, flowID, handle
}

// assertFailLatchedMFASelection verifies the pending identity never became an authenticated anchor.
func assertFailLatchedMFASelection(
	t *testing.T,
	selection canonicalMFASelectionState,
	flowID string,
) {
	t.Helper()

	if !selection.failLatched || selection.identity.Reference != "identity-42" ||
		selection.identity.Account != "alice" || selection.parent.FlowID != flowID {
		t.Fatalf("fail-latched selection = %#v", selection)
	}

	if _, authenticated := selection.session.Identity(); authenticated {
		t.Fatal("fail-latched selection authenticated the canonical anchor")
	}
}

// assertCanonicalFailLatchedMFAConsumed verifies terminal proof consumption without identity or assurance.
func assertCanonicalFailLatchedMFAConsumed(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	flowID string,
	stepUp sessionstate.Handle,
) {
	t.Helper()

	session := openCanonicalFixture(t, runtime, browserCookie)
	if _, authenticated := session.Identity(); authenticated || session.Anchor.Value.Assurance.Level != 0 {
		t.Fatalf("fail-latched anchor authenticated=%t assurance=%#v",
			authenticated, session.Anchor.Value.Assurance)
	}

	if _, err := mfastate.NewAggregate(session.Stores, session.Handle, 0).
		LoadStepUp(context.Background(), stepUp); !errors.Is(err, sessionstate.ErrNotFound) {
		t.Fatalf("fail-latched step-up replay state error = %v, want not found", err)
	}

	parent, err := flowdomain.NewProtocolAggregate(session.Stores, session.Handle, 0).
		Load(context.Background(), flowID)
	if err != nil || parent.AuthOutcome != flowdomain.AuthOutcomeFailLatched {
		t.Fatalf("fail-latched parent = %#v, err = %v", parent, err)
	}
}
