// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package cookie

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/redis/go-redis/v9"
)

type loginCompletionGenerator struct {
	handles []sessionstate.Handle
	next    int
}

func (g *loginCompletionGenerator) NewHandle() (sessionstate.Handle, error) {
	if g.next >= len(g.handles) {
		return "", errors.New("no test handle available")
	}

	handle := g.handles[g.next]
	g.next++

	return handle, nil
}

type loginCompletionFixture struct {
	runtime    *CanonicalRuntime
	session    *CanonicalSession
	oldCookie  *http.Cookie
	oldHandle  sessionstate.Handle
	newHandle  sessionstate.Handle
	flowHandle sessionstate.Handle
}

func TestLoginCompletionRotatesAllCurrentV1ChildFamilies(t *testing.T) {
	t.Parallel()

	fixture := newLoginCompletionFixture(t)
	seedLoginCompletionFamilies(t, fixture)
	fixture.refreshSession(t)

	writer := httptest.NewRecorder()

	rotated, err := fixture.session.CompleteLogin(context.Background(), writer, fixture.input(0))
	if err != nil {
		t.Fatalf("complete login: %v", err)
	}

	if rotated.Handle != fixture.newHandle || len(rotated.Anchor.Value.OIDCFlows) != 1 ||
		len(rotated.Anchor.Value.SAMLFlows) != 1 || len(rotated.Anchor.Value.Enrollments) != 1 ||
		len(rotated.Anchor.Value.StepUps) != 1 || len(rotated.Anchor.Value.Ceremonies) != 1 ||
		len(rotated.Anchor.Value.TOTPRecovery) != 1 {
		t.Fatalf("rotated session = %#v", rotated)
	}

	assertOldEnvelopeRejected(t, fixture)
}

func TestLoginCompletionAdvancesOnlySelectedProtocolFlow(t *testing.T) {
	t.Parallel()

	fixture := newLoginCompletionFixture(t)
	seedLoginCompletionProtocolFlows(t, fixture)
	fixture.refreshSession(t)

	rotated, err := fixture.session.CompleteLogin(context.Background(), httptest.NewRecorder(), fixture.input(0))
	if err != nil {
		t.Fatalf("complete login: %v", err)
	}

	selected, err := rotated.Stores.OIDC.Load(context.Background(), sessionstate.Reference{
		Session: rotated.Handle, Record: fixture.flowHandle,
	})
	if err != nil || selected.Value.AuthOutcome != "ok" || selected.Value.CurrentStep != "login" {
		t.Fatalf("selected flow = %#v, err = %v", selected, err)
	}

	samlHandle := sessionstate.Handle(strings.Repeat("S", 43))

	untouched, err := rotated.Stores.SAML.Load(context.Background(), sessionstate.Reference{
		Session: rotated.Handle, Record: samlHandle,
	})
	if err != nil || untouched.Value.AuthOutcome != "unknown" || untouched.Value.CurrentStep != "start" {
		t.Fatalf("untouched flow = %#v, err = %v", untouched, err)
	}
}

func TestLoginCompletionAppliesRememberEnvelopeAndAnchorLifetime(t *testing.T) {
	t.Parallel()

	fixture := newLoginCompletionFixture(t)
	seedLoginCompletionProtocolFlows(t, fixture)
	fixture.refreshSession(t)

	writer := httptest.NewRecorder()

	rotated, err := fixture.session.CompleteLogin(context.Background(), writer, fixture.input(14*24*time.Hour))
	if err != nil {
		t.Fatalf("complete remembered login: %v", err)
	}

	cookies := writer.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge != int((14*24*time.Hour).Seconds()) {
		t.Fatalf("remember cookies = %#v", cookies)
	}

	if got := rotated.Anchor.Value.AbsoluteExpiresAt.Sub(rotated.Anchor.Value.CreatedAt); got != 14*24*time.Hour {
		t.Fatalf("remember absolute lifetime = %s", got)
	}
}

func TestLoginCompletionNewWriteFailureLeavesOldSessionLiveAndEmitsNoCookie(t *testing.T) {
	t.Parallel()

	fixture := newLoginCompletionFixture(t)
	seedLoginCompletionProtocolFlows(t, fixture)
	fixture.refreshSession(t)
	fixture.session.Anchor.Value.Ceremonies = append(
		fixture.session.Anchor.Value.Ceremonies, sessionstate.Handle(strings.Repeat("M", 43)),
	)

	writer := httptest.NewRecorder()
	if _, err := fixture.session.CompleteLogin(context.Background(), writer, fixture.input(0)); err == nil {
		t.Fatal("completion with missing current-v1 child succeeded")
	}

	if len(writer.Result().Cookies()) != 0 {
		t.Fatalf("failure emitted cookies: %#v", writer.Result().Cookies())
	}

	assertOldEnvelopeLoads(t, fixture)
}

func TestLoginCompletionOldRevokeConflictRollsBackNewSessionAndEmitsNoCookie(t *testing.T) {
	t.Parallel()

	fixture := newLoginCompletionFixture(t)
	seedLoginCompletionProtocolFlows(t, fixture)
	fixture.refreshSession(t)

	stale := *fixture.session
	if err := fixture.session.CommitIdentity(context.Background(), IdentityUpdate{
		Reference: "identity-42", Account: "alice", Subject: "identity-42", Protocol: "oidc",
	}); err != nil {
		t.Fatalf("advance old anchor revision: %v", err)
	}

	writer := httptest.NewRecorder()
	if _, err := stale.CompleteLogin(context.Background(), writer, fixture.input(0)); !errors.Is(err, sessionstate.ErrRevisionConflict) {
		t.Fatalf("stale completion error = %v", err)
	}

	if len(writer.Result().Cookies()) != 0 {
		t.Fatalf("revoke conflict emitted cookies: %#v", writer.Result().Cookies())
	}

	_, err := fixture.session.Stores.Session.Load(context.Background(), sessionstate.Reference{
		Session: fixture.newHandle, Record: fixture.newHandle,
	})
	if !errors.Is(err, sessionstate.ErrRevoked) {
		t.Fatalf("rolled-back new anchor error = %v", err)
	}
}

func TestLoginCompletionPermitsSuccessLoggingOnlyAfterEnvelopeCommit(t *testing.T) {
	t.Parallel()

	fixture := newLoginCompletionFixture(t)
	seedLoginCompletionProtocolFlows(t, fixture)
	fixture.refreshSession(t)

	writer := httptest.NewRecorder()

	logged := false
	if _, err := fixture.session.CompleteLogin(context.Background(), writer, fixture.input(0)); err == nil &&
		len(writer.Result().Cookies()) == 1 {
		logged = true
	}

	if !logged {
		t.Fatal("success logging was not permitted after durable envelope commit")
	}
}

func TestLoginCompletionPublishesSeparateMasterUserMFAIdentity(t *testing.T) {
	t.Parallel()

	fixture := newLoginCompletionFixture(t)
	seedLoginCompletionProtocolFlows(t, fixture)
	fixture.refreshSession(t)
	input := fixture.input(0)
	input.Identity.MFAIdentity = &SessionIdentity{
		Reference: "master-identity", Account: "admin@example.test", Subject: "master-identity",
		DisplayName: "Admin", Protocol: "oidc",
	}
	input.Identity.MFABackendAffinity = &SessionBackendAffinity{
		Type: "remote", Name: "authority", Protocol: "oidc",
		Authority: "authority-a", OpaqueToken: "master-capability",
	}

	rotated, err := fixture.session.CompleteLogin(context.Background(), httptest.NewRecorder(), input)
	if err != nil {
		t.Fatalf("complete master-user login: %v", err)
	}

	identity, authenticated := rotated.Identity()
	if !authenticated || identity.Reference != "identity-42" || identity.Account != "alice" {
		t.Fatalf("target identity = %#v authenticated=%t", identity, authenticated)
	}

	factor, ok := rotated.MFAIdentity()
	if !ok || factor.Reference != "master-identity" || factor.Account != "admin@example.test" {
		t.Fatalf("MFA identity = %#v ok=%t", factor, ok)
	}

	affinity, ok := rotated.MFABackendAffinity()
	if !ok || affinity.OpaqueToken != "master-capability" {
		t.Fatalf("MFA backend affinity = %#v ok=%t", affinity, ok)
	}
}

func newLoginCompletionFixture(t *testing.T) *loginCompletionFixture {
	t.Helper()

	oldHandle := sessionstate.Handle(strings.Repeat("A", 43))
	newHandle := sessionstate.Handle(strings.Repeat("B", 43))
	mini := miniredis.RunT(t)

	runtime, err := NewCanonicalRuntime(
		[]byte("login-completion-test-secret-32-bytes"), 1,
		redis.NewClient(&redis.Options{Addr: mini.Addr()}), "login-completion",
		canonicalRuntimeClock{now: time.Date(2026, time.August, 17, 18, 0, 0, 0, time.UTC)},
		&loginCompletionGenerator{handles: []sessionstate.Handle{oldHandle, newHandle}}, false,
	)
	if err != nil {
		t.Fatalf("create runtime: %v", err)
	}

	writer := httptest.NewRecorder()

	session, err := runtime.Create(context.Background(), writer, false)
	if err != nil {
		t.Fatalf("create old session: %v", err)
	}

	return &loginCompletionFixture{
		runtime: runtime, session: session, oldCookie: writer.Result().Cookies()[0],
		oldHandle: oldHandle, newHandle: newHandle, flowHandle: sessionstate.Handle(strings.Repeat("O", 43)),
	}
}

func (f *loginCompletionFixture) input(rememberTTL time.Duration) LoginCompletionInput {
	return LoginCompletionInput{
		Identity: IdentityUpdate{
			Reference: "identity-42", Account: "alice", Subject: "identity-42", DisplayName: "Alice", Protocol: "oidc",
		},
		Flow: f.flowHandle, Protocol: "oidc", NextStep: "login", RememberTTL: rememberTTL,
	}
}

func (f *loginCompletionFixture) refreshSession(t *testing.T) {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	request.AddCookie(f.oldCookie)

	loaded, err := f.runtime.Open(context.Background(), request)
	if err != nil {
		t.Fatalf("refresh old session: %v", err)
	}

	f.session = loaded
}

func seedLoginCompletionProtocolFlows(t *testing.T, fixture *loginCompletionFixture) {
	t.Helper()

	ctx := context.Background()
	if _, err := fixture.session.Stores.CommitOIDCFlow(ctx, sessionstate.CommitRequest[sessionstate.OIDCFlow]{
		Reference: sessionstate.Reference{Session: fixture.oldHandle, Record: fixture.flowHandle},
		Value: sessionstate.OIDCFlow{
			Record: sessionstate.Record{Handle: fixture.flowHandle}, Session: fixture.oldHandle,
			FlowType: "oidc_authorization_code", CurrentStep: "start", AuthOutcome: "unknown",
		}, TTL: 10 * time.Minute,
	}); err != nil {
		t.Fatalf("seed OIDC flow: %v", err)
	}

	samlHandle := sessionstate.Handle(strings.Repeat("S", 43))
	if _, err := fixture.session.Stores.CommitSAMLFlow(ctx, sessionstate.CommitRequest[sessionstate.SAMLFlow]{
		Reference: sessionstate.Reference{Session: fixture.oldHandle, Record: samlHandle},
		Value: sessionstate.SAMLFlow{
			Record: sessionstate.Record{Handle: samlHandle}, Session: fixture.oldHandle,
			FlowType: "saml", CurrentStep: "start", AuthOutcome: "unknown",
		}, TTL: 10 * time.Minute,
	}); err != nil {
		t.Fatalf("seed SAML flow: %v", err)
	}
}

func seedLoginCompletionFamilies(t *testing.T, fixture *loginCompletionFixture) {
	t.Helper()
	seedLoginCompletionProtocolFlows(t, fixture)

	ctx := context.Background()
	commit := func(owner string, err error) {
		t.Helper()

		if err != nil {
			t.Fatalf("seed %s: %v", owner, err)
		}
	}

	enrollment := sessionstate.Handle(strings.Repeat("E", 43))
	_, err := fixture.session.Stores.CommitEnrollment(ctx, sessionstate.CommitRequest[sessionstate.EnrollmentRecord]{
		Reference: sessionstate.Reference{Session: fixture.oldHandle, Record: enrollment},
		Value:     sessionstate.EnrollmentRecord{Record: sessionstate.Record{Handle: enrollment}, Session: fixture.oldHandle},
		TTL:       5 * time.Minute,
	})
	commit("enrollment", err)

	stepUp := sessionstate.Handle(strings.Repeat("U", 43))
	_, err = fixture.session.Stores.CommitStepUp(ctx, sessionstate.CommitRequest[sessionstate.StepUpRecord]{
		Reference: sessionstate.Reference{Session: fixture.oldHandle, Record: stepUp},
		Value:     sessionstate.StepUpRecord{Record: sessionstate.Record{Handle: stepUp}, Session: fixture.oldHandle},
		TTL:       5 * time.Minute,
	})
	commit("step-up", err)

	ceremony := sessionstate.Handle(strings.Repeat("C", 43))
	_, err = fixture.session.Stores.CommitCeremony(ctx, sessionstate.CommitRequest[sessionstate.CeremonyRecord]{
		Reference: sessionstate.Reference{Session: fixture.oldHandle, Record: ceremony},
		Value:     sessionstate.CeremonyRecord{Record: sessionstate.Record{Handle: ceremony}, Session: fixture.oldHandle},
		TTL:       5 * time.Minute,
	})
	commit("ceremony", err)

	totp := sessionstate.Handle(strings.Repeat("T", 43))
	_, err = fixture.session.Stores.CommitTOTPRecovery(ctx, sessionstate.CommitRequest[sessionstate.TOTPRecoveryRecord]{
		Reference: sessionstate.Reference{Session: fixture.oldHandle, Record: totp},
		Value:     sessionstate.TOTPRecoveryRecord{Record: sessionstate.Record{Handle: totp}, Session: fixture.oldHandle},
		TTL:       5 * time.Minute,
	})
	commit("TOTP/recovery", err)
}

func assertOldEnvelopeRejected(t *testing.T, fixture *loginCompletionFixture) {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	request.AddCookie(fixture.oldCookie)

	if _, err := fixture.runtime.Open(context.Background(), request); !errors.Is(err, ErrEnvelopeRejected) {
		t.Fatalf("old envelope error = %v", err)
	}
}

func assertOldEnvelopeLoads(t *testing.T, fixture *loginCompletionFixture) {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	request.AddCookie(fixture.oldCookie)

	if _, err := fixture.runtime.Open(context.Background(), request); err != nil {
		t.Fatalf("old envelope no longer loads: %v", err)
	}
}

var _ = definitions.SecureDataCookieName
