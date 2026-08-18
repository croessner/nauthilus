// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//nolint:dupl,funlen // WebAuthn tests keep ceremony binding, persistence, and replay in one contract.
package idp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/croessner/nauthilus/v3/server/idp/mfastate"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/gin-gonic/gin"
)

func TestCanonicalWebAuthnCeremonyCompletesBoundStepUpAndResumesOnce(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, flowID := seedCanonicalIDPFlow(t, canonicalDecisionOIDCState(""))
	authenticateCanonicalFixture(t, runtime, browserCookie)
	stepUpHandle := seedCanonicalWebAuthnStepUp(t, runtime, browserCookie, flowID)
	ceremonyHandle := sessionstate.Handle("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")

	beginCalls := 0
	finishCalls := 0
	handler := newLoginMFAViewHandler()
	handler.canonicalMFAAvailabilityResolver = canonicalWebAuthnAvailability
	handler.canonicalWebAuthnBegin = func(
		_ *gin.Context,
		selection canonicalMFASelectionState,
	) (any, sessionstate.Handle, error) {
		beginCalls++

		assertCanonicalWebAuthnBinding(t, selection, flowID)

		return gin.H{"publicKey": gin.H{"challenge": "opaque-challenge"}}, ceremonyHandle, nil
	}
	handler.canonicalWebAuthnFinish = func(
		_ *gin.Context,
		selection canonicalMFASelectionState,
		ceremony sessionstate.Handle,
	) (*backend.User, error) {
		finishCalls++

		assertCanonicalWebAuthnBinding(t, selection, flowID)

		if ceremony != ceremonyHandle {
			t.Fatalf("canonical ceremony handle = %q, want %q", ceremony, ceremonyHandle)
		}

		return nil, nil
	}

	router := gin.New()
	router.GET(
		"/login/webauthn/begin",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.LoginWebAuthnBegin,
	)
	router.POST(
		"/login/webauthn/finish",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.PostLoginWebAuthnFinish,
	)

	beginRequest := httptest.NewRequest(
		http.MethodGet,
		"/login/webauthn/begin?flow="+string(stepUpHandle),
		nil,
	)
	beginRequest.AddCookie(browserCookie)

	beginWriter := httptest.NewRecorder()
	router.ServeHTTP(beginWriter, beginRequest)

	if beginWriter.Code != http.StatusOK || beginCalls != 1 {
		t.Fatalf("canonical WebAuthn begin = status %d calls %d body %q",
			beginWriter.Code, beginCalls, beginWriter.Body.String())
	}

	var beginResponse struct {
		Ceremony string `json:"ceremony"`
	}
	if err := json.Unmarshal(beginWriter.Body.Bytes(), &beginResponse); err != nil || beginResponse.Ceremony != string(ceremonyHandle) {
		t.Fatalf("canonical WebAuthn begin response = %#v, err = %v", beginResponse, err)
	}

	finishURL := "/login/webauthn/finish?flow=" + string(stepUpHandle) + "&ceremony=" + beginResponse.Ceremony
	finishRequest := httptest.NewRequest(http.MethodPost, finishURL, strings.NewReader(`{"id":"opaque-credential"}`))
	finishRequest.Header.Set("Content-Type", "application/json")
	finishRequest.AddCookie(browserCookie)

	finishWriter := httptest.NewRecorder()
	router.ServeHTTP(finishWriter, finishRequest)

	if finishWriter.Code != http.StatusOK || finishCalls != 1 {
		t.Fatalf("canonical WebAuthn finish = status %d calls %d body %q",
			finishWriter.Code, finishCalls, finishWriter.Body.String())
	}

	var finishResponse webAuthnFinishResponse
	if err := json.Unmarshal(finishWriter.Body.Bytes(), &finishResponse); err != nil ||
		finishResponse.Redirect != "/oidc/authorize?client_id=client-a&flow="+flowID {
		t.Fatalf("canonical WebAuthn finish response = %#v, err = %v", finishResponse, err)
	}

	assertCanonicalWebAuthnCompleted(t, runtime, browserCookie, stepUpHandle)

	replayRequest := httptest.NewRequest(http.MethodPost, finishURL, strings.NewReader(`{"id":"opaque-credential"}`))
	replayRequest.Header.Set("Content-Type", "application/json")
	replayRequest.AddCookie(browserCookie)

	replayWriter := httptest.NewRecorder()
	router.ServeHTTP(replayWriter, replayRequest)

	if replayWriter.Code != http.StatusConflict || finishCalls != 1 {
		t.Fatalf("canonical WebAuthn replay = status %d calls %d, want %d/1",
			replayWriter.Code, finishCalls, http.StatusConflict)
	}
}

func TestCanonicalWebAuthnCompletionRefreshesAnchorAfterCeremonyConsume(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, flowID := seedCanonicalIDPFlow(t, canonicalDecisionOIDCState(""))
	authenticateCanonicalFixture(t, runtime, browserCookie)
	stepUpHandle := seedCanonicalWebAuthnStepUp(t, runtime, browserCookie, flowID)
	ceremonyHandle := sessionstate.Handle("YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY")

	handler := newLoginMFAViewHandler()
	handler.canonicalMFAAvailabilityResolver = canonicalWebAuthnAvailability
	handler.canonicalWebAuthnFinish = func(
		ctx *gin.Context,
		selection canonicalMFASelectionState,
		_ sessionstate.Handle,
	) (*backend.User, error) {
		reference := sessionstate.Reference{
			Session: selection.session.Handle,
			Record:  ceremonyHandle,
		}
		if _, err := selection.session.Stores.CommitCeremony(
			ctx.Request.Context(),
			sessionstate.CommitRequest[sessionstate.CeremonyRecord]{
				Reference: reference,
				Value: sessionstate.CeremonyRecord{
					Record:  sessionstate.Record{Handle: ceremonyHandle},
					Session: selection.session.Handle,
					Flow:    selection.stepUp.Value.Flow,
				},
				TTL: 5 * time.Minute,
			},
		); err != nil {
			return nil, err
		}

		if _, err := selection.session.Stores.ConsumeCeremony(
			ctx.Request.Context(),
			sessionstate.DeleteRequest{Reference: reference, ExpectedRevision: 1},
		); err != nil {
			return nil, err
		}

		return nil, nil
	}

	router := gin.New()
	router.POST(
		"/login/webauthn/finish",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.PostLoginWebAuthnFinish,
	)

	finishURL := "/login/webauthn/finish?flow=" + string(stepUpHandle) + "&ceremony=" + string(ceremonyHandle)
	request := httptest.NewRequest(http.MethodPost, finishURL, strings.NewReader(`{"id":"opaque-credential"}`))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	if writer.Code != http.StatusOK {
		t.Fatalf("canonical WebAuthn completion after ceremony consume = status %d body %q, want 200",
			writer.Code, writer.Body.String())
	}

	assertCanonicalWebAuthnCompleted(t, runtime, browserCookie, stepUpHandle)
}

func TestCanonicalWebAuthnSelfServiceUsesStepUpAsCeremonyBinding(t *testing.T) {
	t.Parallel()

	selection := canonicalMFASelectionState{
		identity: cookie.SessionIdentity{Protocol: definitions.ProtoOIDC},
		stepUp: sessionstate.Versioned[sessionstate.StepUpRecord]{
			Value: sessionstate.StepUpRecord{
				Record: sessionstate.Record{Handle: "step-up-handle"},
			},
		},
	}

	if got := canonicalMFABoundFlow(selection); got != "step-up-handle" {
		t.Fatalf("self-service ceremony binding = %q", got)
	}

	if got := canonicalMFAProtocol(selection); got != definitions.ProtoOIDC {
		t.Fatalf("self-service ceremony protocol = %q", got)
	}
}

func TestCanonicalLoginWebAuthnViewDoesNotExpose2FAHomeMenuBeforeCompletion(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, flowID := seedCanonicalIDPFlow(t, canonicalDecisionOIDCState(""))
	authenticateCanonicalFixture(t, runtime, browserCookie)
	stepUpHandle := seedCanonicalWebAuthnStepUp(t, runtime, browserCookie, flowID)

	handler := newLoginMFAViewHandler()
	handler.canonicalMFAAvailabilityResolver = canonicalWebAuthnAvailability
	router := gin.New()
	router.SetHTMLTemplate(loginMFATestTemplate())
	router.Use(loginMFAViewLocalizationMiddleware())
	router.GET(
		"/login/webauthn/:languageTag",
		cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation),
		handler.LoginWebAuthn,
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"/login/webauthn/de?flow="+string(stepUpHandle),
		nil,
	)
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	if writer.Code != http.StatusOK || strings.Contains(writer.Body.String(), "2FA Verwaltung") {
		t.Fatalf("canonical WebAuthn view = status %d body %q, want 200 without self-service menu",
			writer.Code, writer.Body.String())
	}
}

func seedCanonicalWebAuthnStepUp(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	flowID string,
) sessionstate.Handle {
	t.Helper()

	session := openCanonicalFixture(t, runtime, browserCookie)

	handle := sessionstate.Handle("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err := mfastate.NewAggregate(session.Stores, session.Handle, 10*time.Minute).BeginStepUp(
		context.Background(),
		&sessionstate.StepUpRecord{
			Record: sessionstate.Record{Handle: handle}, Session: session.Handle,
			Flow: sessionstate.Handle(flowID), RequestedLevel: 3,
			SupportedMethods: []string{definitions.MFAMethodWebAuthn}, Scope: "oidc:client-a",
		},
	); err != nil {
		t.Fatalf("seed typed WebAuthn step-up: %v", err)
	}

	return handle
}

func canonicalWebAuthnAvailability(
	_ *gin.Context,
	_ *cookie.CanonicalSession,
	_ cookie.SessionIdentity,
	_ *flowdomain.State,
	_ []string,
) (mfaAvailability, error) {
	return mfaAvailability{haveWebAuthn: true, count: 1}, nil
}

func assertCanonicalWebAuthnBinding(t *testing.T, selection canonicalMFASelectionState, flowID string) {
	t.Helper()

	if selection.identity.Reference != "identity-42" || selection.identity.Account != "alice" ||
		selection.parent.FlowID != flowID || selection.stepUp.Value.Flow != sessionstate.Handle(flowID) {
		t.Fatalf("typed WebAuthn binding = identity %#v parent %#v step-up %#v",
			selection.identity, selection.parent, selection.stepUp.Value)
	}
}

func assertCanonicalWebAuthnCompleted(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	stepUpHandle sessionstate.Handle,
) {
	t.Helper()

	session := openCanonicalFixture(t, runtime, browserCookie)

	loaded, err := mfastate.NewAggregate(session.Stores, session.Handle, 0).
		LoadStepUp(context.Background(), stepUpHandle)
	if err != nil || !loaded.Value.Completed || loaded.Value.ProofMethod != definitions.MFAMethodWebAuthn {
		t.Fatalf("successful WebAuthn StepUp = %#v, err = %v", loaded.Value, err)
	}

	assurance, ok := session.Assurance(session.EvaluationTime())
	if !ok || assurance.Level != 3 || assurance.Method != definitions.MFAMethodWebAuthn ||
		assurance.Scope != "oidc:client-a" {
		t.Fatalf("successful WebAuthn assurance = %#v, ok = %t", assurance, ok)
	}
}
