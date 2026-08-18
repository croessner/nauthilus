// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//nolint:funlen // Revocation fixtures seed the complete owned-child matrix in one place.
package cookie

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/redis/go-redis/v9"
)

type canonicalRuntimeClock struct {
	now time.Time
}

func (c canonicalRuntimeClock) Now() time.Time { return c.now }

func TestCanonicalRuntimeCreatesAndLoadsOnlyEnvelopeBackedSession(t *testing.T) {
	t.Parallel()

	mini := miniredis.RunT(t)

	runtime, err := NewCanonicalRuntime(
		[]byte("canonical-runtime-test-secret-32-bytes"),
		1,
		redis.NewClient(&redis.Options{Addr: mini.Addr()}),
		"canonical-runtime",
		canonicalRuntimeClock{now: time.Date(2026, time.August, 17, 12, 0, 0, 0, time.UTC)},
		sessionstate.NewRandomHandleGenerator(nil),
		false,
	)
	if err != nil {
		t.Fatalf("create runtime: %v", err)
	}

	createdWriter := httptest.NewRecorder()

	created, err := runtime.Create(context.Background(), createdWriter, false)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	cookies := createdWriter.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != definitions.SecureDataCookieName {
		t.Fatalf("canonical create cookies = %#v, want only secure-data envelope", cookies)
	}

	if len(cookies[0].Value) >= EnvelopeHardLimitBytes {
		t.Fatalf("canonical cookie value bytes = %d, want below %d", len(cookies[0].Value), EnvelopeHardLimitBytes)
	}

	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	request.AddCookie(cookies[0])

	loaded, err := runtime.Open(context.Background(), request)
	if err != nil {
		t.Fatalf("open canonical session: %v", err)
	}

	if loaded.Handle != created.Handle || loaded.Anchor.Value.Handle != created.Handle {
		t.Fatalf("loaded session mismatch: created=%#v loaded=%#v", created, loaded)
	}
}

func TestCanonicalRuntimeRejectsAndPurgesLegacyBrowserState(t *testing.T) {
	t.Parallel()

	secret := []byte("canonical-runtime-test-secret-32-bytes")
	mini := miniredis.RunT(t)

	runtime, err := NewCanonicalRuntime(
		secret,
		1,
		redis.NewClient(&redis.Options{Addr: mini.Addr()}),
		"canonical-runtime-reject",
		canonicalRuntimeClock{now: time.Date(2026, time.August, 17, 12, 0, 0, 0, time.UTC)},
		sessionstate.NewRandomHandleGenerator(nil),
		false,
	)
	if err != nil {
		t.Fatalf("create runtime: %v", err)
	}

	legacyCodec := NewSecureCodec(secret)

	legacyValue, err := legacyCodec.Encode(definitions.SecureDataCookieName, map[string]any{"idp_flow_id": "legacy"})
	if err != nil {
		t.Fatalf("encode legacy state: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	request.AddCookie(&http.Cookie{Name: definitions.SecureDataCookieName, Value: legacyValue})
	request.AddCookie(&http.Cookie{Name: definitions.WebAuthnCeremonyCookieName, Value: "legacy-reference"})

	if _, err = runtime.Open(context.Background(), request); !errors.Is(err, ErrEnvelopeRejected) {
		t.Fatalf("legacy open error = %v, want envelope rejected", err)
	}

	writer := httptest.NewRecorder()
	runtime.PurgeBrowser(writer)

	deleted := writer.Result().Cookies()
	if len(deleted) != 2 || deleted[0].MaxAge >= 0 || deleted[1].MaxAge >= 0 {
		t.Fatalf("purge cookies = %#v, want both browser representations deleted", deleted)
	}
}

func TestCanonicalSessionRevocationTombstonesAnchorAndDeletesOwnedChildren(t *testing.T) {
	t.Parallel()

	mini := miniredis.RunT(t)

	runtime, err := NewCanonicalRuntime(
		[]byte("canonical-revocation-test-secret-32bytes"), 1,
		redis.NewClient(&redis.Options{Addr: mini.Addr()}), "canonical-revocation",
		canonicalRuntimeClock{now: time.Date(2026, time.August, 17, 12, 0, 0, 0, time.UTC)},
		sessionstate.NewRandomHandleGenerator(nil), false,
	)
	if err != nil {
		t.Fatalf("create canonical revocation runtime: %v", err)
	}

	createWriter := httptest.NewRecorder()

	session, err := runtime.Create(context.Background(), createWriter, false)
	if err != nil {
		t.Fatalf("create canonical revocation session: %v", err)
	}

	commitCanonicalRevocationChildren(t, session)

	if got := len(mini.Keys()); got != 7 {
		t.Fatalf("canonical revocation fixture keys = %d, want anchor plus six children", got)
	}

	revokeWriter := httptest.NewRecorder()
	if err = session.Revoke(context.Background(), revokeWriter); err != nil {
		t.Fatalf("revoke canonical session: %v", err)
	}

	if got := len(mini.Keys()); got != 1 {
		t.Fatalf("canonical revocation keys = %d, want tombstone only", got)
	}

	if _, err = session.Stores.Session.Load(context.Background(), sessionstate.Reference{
		Session: session.Handle, Record: session.Handle,
	}); !errors.Is(err, sessionstate.ErrRevoked) {
		t.Fatalf("canonical revoked anchor load error = %v, want revoked", err)
	}

	assertCanonicalBrowserPurge(t, revokeWriter)
}

func TestCanonicalSessionRevocationPurgesBrowserOnRedisFailure(t *testing.T) {
	t.Parallel()

	mini := miniredis.RunT(t)

	runtime, err := NewCanonicalRuntime(
		[]byte("canonical-revoke-failure-secret-32bytes"), 1,
		redis.NewClient(&redis.Options{Addr: mini.Addr()}), "canonical-revoke-failure",
		canonicalRuntimeClock{now: time.Date(2026, time.August, 17, 12, 0, 0, 0, time.UTC)},
		sessionstate.NewRandomHandleGenerator(nil), false,
	)
	if err != nil {
		t.Fatalf("create canonical failure runtime: %v", err)
	}

	session, err := runtime.Create(context.Background(), httptest.NewRecorder(), false)
	if err != nil {
		t.Fatalf("create canonical failure session: %v", err)
	}

	mini.Close()

	revokeWriter := httptest.NewRecorder()
	if err = session.Revoke(context.Background(), revokeWriter); err == nil {
		t.Fatal("canonical revocation unexpectedly succeeded during Redis failure")
	}

	assertCanonicalBrowserPurge(t, revokeWriter)
}

func commitCanonicalRevocationChildren(t *testing.T, session *CanonicalSession) {
	t.Helper()

	ctx := context.Background()
	ttl := 10 * time.Minute
	newHandle := func() sessionstate.Handle {
		handle, err := sessionstate.NewRandomHandleGenerator(nil).NewHandle()
		if err != nil {
			t.Fatalf("generate canonical revocation child handle: %v", err)
		}

		return handle
	}
	commit := func(name string, err error) {
		if err != nil {
			t.Fatalf("commit canonical revocation %s child: %v", name, err)
		}
	}

	oidc := newHandle()
	_, err := session.Stores.CommitOIDCFlow(ctx, sessionstate.CommitRequest[sessionstate.OIDCFlow]{
		Reference: sessionstate.Reference{Session: session.Handle, Record: oidc},
		Value:     sessionstate.OIDCFlow{Record: sessionstate.Record{Handle: oidc}, Session: session.Handle}, TTL: ttl,
	})
	commit("OIDC", err)

	samlFlow := newHandle()
	_, err = session.Stores.CommitSAMLFlow(ctx, sessionstate.CommitRequest[sessionstate.SAMLFlow]{
		Reference: sessionstate.Reference{Session: session.Handle, Record: samlFlow},
		Value:     sessionstate.SAMLFlow{Record: sessionstate.Record{Handle: samlFlow}, Session: session.Handle}, TTL: ttl,
	})
	commit("SAML", err)

	enrollment := newHandle()
	_, err = session.Stores.CommitEnrollment(ctx, sessionstate.CommitRequest[sessionstate.EnrollmentRecord]{
		Reference: sessionstate.Reference{Session: session.Handle, Record: enrollment},
		Value:     sessionstate.EnrollmentRecord{Record: sessionstate.Record{Handle: enrollment}, Session: session.Handle}, TTL: ttl,
	})
	commit("enrollment", err)

	stepUp := newHandle()
	_, err = session.Stores.CommitStepUp(ctx, sessionstate.CommitRequest[sessionstate.StepUpRecord]{
		Reference: sessionstate.Reference{Session: session.Handle, Record: stepUp},
		Value:     sessionstate.StepUpRecord{Record: sessionstate.Record{Handle: stepUp}, Session: session.Handle}, TTL: ttl,
	})
	commit("step-up", err)

	ceremony := newHandle()
	_, err = session.Stores.CommitCeremony(ctx, sessionstate.CommitRequest[sessionstate.CeremonyRecord]{
		Reference: sessionstate.Reference{Session: session.Handle, Record: ceremony},
		Value:     sessionstate.CeremonyRecord{Record: sessionstate.Record{Handle: ceremony}, Session: session.Handle}, TTL: ttl,
	})
	commit("ceremony", err)

	totpRecovery := newHandle()
	_, err = session.Stores.CommitTOTPRecovery(ctx, sessionstate.CommitRequest[sessionstate.TOTPRecoveryRecord]{
		Reference: sessionstate.Reference{Session: session.Handle, Record: totpRecovery},
		Value: sessionstate.TOTPRecoveryRecord{
			Record: sessionstate.Record{Handle: totpRecovery}, Session: session.Handle,
		}, TTL: ttl,
	})
	commit("TOTP/recovery", err)

	session.Anchor, err = session.Stores.Session.Load(ctx, sessionstate.Reference{
		Session: session.Handle, Record: session.Handle,
	})
	if err != nil {
		t.Fatalf("reload canonical revocation anchor: %v", err)
	}
}

func assertCanonicalBrowserPurge(t *testing.T, writer *httptest.ResponseRecorder) {
	t.Helper()

	cookies := writer.Result().Cookies()
	if len(cookies) != 2 || cookies[0].MaxAge >= 0 || cookies[1].MaxAge >= 0 {
		t.Fatalf("canonical revocation browser purge = %#v", cookies)
	}
}
