// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//nolint:dupl // Selection fixtures intentionally repeat complete binding records for independent cases.
package idp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
	"github.com/croessner/nauthilus/v3/server/idp/mfastate"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/gin-gonic/gin"
)

func TestCanonicalMFASelectionRejectsMissingCanonicalSession(t *testing.T) {
	t.Parallel()

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/login/mfa?flow=TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT", nil)

	selection, err := (&FrontendHandler{}).canonicalMFASelection(ctx)
	if !errors.Is(err, sessionstate.ErrBindingMismatch) || selection.session != nil {
		t.Fatalf("missing canonical session selection = %#v, err = %v", selection, err)
	}
}

func TestCanonicalMFASelectionLoadsBoundStepUpAndAvailability(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, flowID := seedCanonicalIDPFlow(t, canonicalDecisionOIDCState(""))
	authenticateCanonicalFixture(t, runtime, browserCookie)
	session := openCanonicalFixture(t, runtime, browserCookie)

	stepUpHandle := sessionstate.Handle("TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT")
	if err := mfastate.NewAggregate(session.Stores, session.Handle, 10*time.Minute).BeginStepUp(
		context.Background(),
		&sessionstate.StepUpRecord{
			Record: sessionstate.Record{Handle: stepUpHandle}, Session: session.Handle,
			Flow: sessionstate.Handle(flowID), RequestedLevel: 2,
			SupportedMethods: []string{definitions.MFAMethodTOTP}, Scope: "oidc:client-a",
		},
	); err != nil {
		t.Fatalf("seed typed step-up: %v", err)
	}

	handler := &FrontendHandler{canonicalMFAAvailabilityResolver: func(
		_ *gin.Context,
		_ *cookie.CanonicalSession,
		identity cookie.SessionIdentity,
		_ *flowdomain.State,
		methods []string,
	) (mfaAvailability, error) {
		if identity.Reference != "identity-42" || len(methods) != 1 || methods[0] != definitions.MFAMethodTOTP {
			t.Fatalf("selection resolver binding = %#v, methods = %v", identity, methods)
		}

		return mfaAvailability{haveTOTP: true, count: 1}, nil
	}}

	router := gin.New()
	router.GET("/login/mfa", cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation), func(ctx *gin.Context) {
		selection, err := handler.canonicalMFASelection(ctx)
		if err != nil || selection.stepUp.Value.Flow != sessionstate.Handle(flowID) ||
			selection.parent.FlowID != flowID || selection.identity.Reference != "identity-42" ||
			!selection.availability.haveTOTP || selection.availability.count != 1 {
			t.Fatalf("canonical MFA selection = %#v, err = %v", selection, err)
		}

		ctx.Status(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "/login/mfa?flow="+string(stepUpHandle), nil)
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	if writer.Code != http.StatusNoContent {
		t.Fatalf("canonical MFA selection status = %d, want %d", writer.Code, http.StatusNoContent)
	}
}

func TestLoginMFASelectUsesCanonicalStepUpTicket(t *testing.T) {
	t.Parallel()

	runtime, browserCookie, flowID := seedCanonicalIDPFlow(t, canonicalDecisionOIDCState(""))
	authenticateCanonicalFixture(t, runtime, browserCookie)
	session := openCanonicalFixture(t, runtime, browserCookie)

	stepUpHandle := sessionstate.Handle("UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU")
	if err := mfastate.NewAggregate(session.Stores, session.Handle, 10*time.Minute).BeginStepUp(
		context.Background(),
		&sessionstate.StepUpRecord{
			Record: sessionstate.Record{Handle: stepUpHandle}, Session: session.Handle,
			Flow: sessionstate.Handle(flowID), RequestedLevel: 2,
			SupportedMethods: []string{definitions.MFAMethodTOTP}, Scope: "oidc:client-a",
		},
	); err != nil {
		t.Fatalf("seed typed step-up: %v", err)
	}

	handler := &FrontendHandler{canonicalMFAAvailabilityResolver: func(
		_ *gin.Context,
		_ *cookie.CanonicalSession,
		_ cookie.SessionIdentity,
		_ *flowdomain.State,
		_ []string,
	) (mfaAvailability, error) {
		return mfaAvailability{haveTOTP: true}, nil
	}}
	router := gin.New()
	router.GET("/login/mfa", cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation), handler.LoginMFASelect)

	request := httptest.NewRequest(http.MethodGet, "/login/mfa?flow="+string(stepUpHandle), nil)
	request.AddCookie(browserCookie)

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	want := "/login/totp?flow=" + string(stepUpHandle)
	if writer.Code != http.StatusFound || writer.Header().Get("Location") != want {
		t.Fatalf("canonical MFA select redirect = %d %q, want %d %q",
			writer.Code, writer.Header().Get("Location"), http.StatusFound, want)
	}
}

func TestCanonicalMFASelectionRejectsMissingCrossSessionAndCompletedStepUp(t *testing.T) {
	t.Parallel()

	for _, variant := range []string{"missing", "cross-session", "completed"} {
		t.Run(variant, func(t *testing.T) {
			runtime, browserCookie, stepUpHandle := seedCanonicalMFASelectionFixture(t)
			ticket := stepUpHandle

			switch variant {
			case "missing":
				ticket = "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV"
			case "cross-session":
				browserCookie = createAuthenticatedCanonicalCookie(t, runtime)
			case "completed":
				completeCanonicalStepUpFixture(t, runtime, browserCookie, stepUpHandle)
			}

			resolverCalls := 0
			handler := &FrontendHandler{canonicalMFAAvailabilityResolver: func(
				_ *gin.Context,
				_ *cookie.CanonicalSession,
				_ cookie.SessionIdentity,
				_ *flowdomain.State,
				_ []string,
			) (mfaAvailability, error) {
				resolverCalls++

				return mfaAvailability{haveTOTP: true}, nil
			}}
			router := gin.New()
			router.GET("/login/mfa", cookie.CanonicalMiddleware(runtime, cookie.CanonicalContinuation), handler.LoginMFASelect)

			request := httptest.NewRequest(http.MethodGet, "/login/mfa?flow="+string(ticket), nil)
			request.AddCookie(browserCookie)

			writer := httptest.NewRecorder()
			router.ServeHTTP(writer, request)

			if writer.Code != http.StatusConflict || resolverCalls != 0 {
				t.Fatalf("%s selection = status %d resolver calls %d, want %d/0",
					variant, writer.Code, resolverCalls, http.StatusConflict)
			}
		})
	}
}

func seedCanonicalMFASelectionFixture(
	t *testing.T,
) (*cookie.CanonicalRuntime, *http.Cookie, sessionstate.Handle) {
	t.Helper()

	runtime, browserCookie, flowID := seedCanonicalIDPFlow(t, canonicalDecisionOIDCState(""))
	authenticateCanonicalFixture(t, runtime, browserCookie)
	session := openCanonicalFixture(t, runtime, browserCookie)

	stepUpHandle := sessionstate.Handle("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW")
	if err := mfastate.NewAggregate(session.Stores, session.Handle, 10*time.Minute).BeginStepUp(
		context.Background(),
		&sessionstate.StepUpRecord{
			Record: sessionstate.Record{Handle: stepUpHandle}, Session: session.Handle,
			Flow: sessionstate.Handle(flowID), RequestedLevel: 2,
			SupportedMethods: []string{definitions.MFAMethodTOTP}, Scope: "oidc:client-a",
		},
	); err != nil {
		t.Fatalf("seed typed step-up: %v", err)
	}

	return runtime, browserCookie, stepUpHandle
}

func createAuthenticatedCanonicalCookie(t *testing.T, runtime *cookie.CanonicalRuntime) *http.Cookie {
	t.Helper()

	writer := httptest.NewRecorder()

	session, err := runtime.Create(context.Background(), writer, false)
	if err != nil {
		t.Fatalf("create second canonical session: %v", err)
	}

	if err = session.CommitIdentity(context.Background(), cookie.IdentityUpdate{
		Reference: "identity-42", Account: "alice", Subject: "identity-42", Protocol: "oidc",
	}); err != nil {
		t.Fatalf("authenticate second canonical session: %v", err)
	}

	return writer.Result().Cookies()[0]
}

func completeCanonicalStepUpFixture(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	stepUpHandle sessionstate.Handle,
) {
	t.Helper()

	session := openCanonicalFixture(t, runtime, browserCookie)
	aggregate := mfastate.NewAggregate(session.Stores, session.Handle, 10*time.Minute)

	loaded, err := aggregate.LoadStepUp(context.Background(), stepUpHandle)
	if err != nil {
		t.Fatalf("load typed step-up: %v", err)
	}

	record := loaded.Value
	record.Revision = loaded.Revision
	record.Completed = true
	record.ProofMethod = definitions.MFAMethodTOTP
	record.CompletedAt = session.EvaluationTime()

	record.FreshUntil = record.CompletedAt.Add(5 * time.Minute)
	if err = aggregate.SaveStepUp(context.Background(), &record); err != nil {
		t.Fatalf("complete typed step-up fixture: %v", err)
	}
}
