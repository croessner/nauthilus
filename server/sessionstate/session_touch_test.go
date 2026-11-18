// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sessionstate

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestRedisStoresTouchSlidesAnchorAndLifetimeChildren proves that a touch extends the anchor and its listed
// lifetime children together, never beyond the absolute expiry, and fails closed for revoked anchors.
func TestRedisStoresTouchSlidesAnchorAndLifetimeChildren(t *testing.T) {
	t.Parallel()

	fixture := newRedisStoresFixture(t)
	ctx := context.Background()
	session := Handle(strings.Repeat("F", 43))
	logoutHandle := Handle(strings.Repeat("L", 43))
	anchorReference := Reference{Session: session, Record: session}
	logoutReference := Reference{Session: session, Record: logoutHandle}

	commitTouchTestAnchor(t, fixture, session, 30*time.Minute, 40*time.Minute)

	if _, err := fixture.stores.CommitLogoutIndex(ctx, CommitRequest[LogoutIndex]{
		Reference: logoutReference,
		Value: LogoutIndex{
			Record: Record{Handle: logoutHandle}, Session: session,
			IdentityReference: "identity-42", Account: "alice", OIDCClientIDs: []string{"client-a"},
		},
		TTL: 30 * time.Minute,
	}); err != nil {
		t.Fatalf("commit logout index: %v", err)
	}

	request := TouchRequest{
		Reference: anchorReference,
		Children:  []OwnedReference{{Owner: OwnerConsent, Reference: logoutReference}},
		IdleTTL:   30 * time.Minute,
	}

	advanceTouchTestTime(fixture, 20*time.Minute)

	receipt, err := fixture.stores.TouchSession(ctx, request)
	if err != nil || !receipt.Touched {
		t.Fatalf("touch: receipt=%#v err=%v", receipt, err)
	}

	// The idle window would reach 50 minutes, but the absolute expiry is 40 minutes after creation.
	absoluteExpiry := fixture.clock.Now().Add(20 * time.Minute)
	if !receipt.IdleExpiresAt.Equal(absoluteExpiry) {
		t.Fatalf("idle expiry = %s, want absolute expiry %s", receipt.IdleExpiresAt, absoluteExpiry)
	}

	advanceTouchTestTime(fixture, 15*time.Minute)

	if _, err = fixture.stores.Session.Load(ctx, anchorReference); err != nil {
		t.Fatalf("touched anchor expired with its original idle window: %v", err)
	}

	if _, err = fixture.stores.Logout.Load(ctx, logoutReference); err != nil {
		t.Fatalf("logout index expired before its anchor: %v", err)
	}

	assertTouchRejectedAfterRevocation(t, fixture, request)
}

// TestRedisStoresTouchRejectsForeignChildren proves that a touch cannot extend records of another session.
func TestRedisStoresTouchRejectsForeignChildren(t *testing.T) {
	t.Parallel()

	fixture := newRedisStoresFixture(t)
	session := Handle(strings.Repeat("G", 43))
	foreign := Reference{Session: Handle(strings.Repeat("H", 43)), Record: Handle(strings.Repeat("L", 43))}

	_, err := fixture.stores.TouchSession(context.Background(), TouchRequest{
		Reference: Reference{Session: session, Record: session},
		Children:  []OwnedReference{{Owner: OwnerConsent, Reference: foreign}},
		IdleTTL:   30 * time.Minute,
	})
	if !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("foreign child touch error = %v, want binding mismatch", err)
	}
}

// commitTouchTestAnchor creates one anchor with explicit idle and absolute lifetimes.
func commitTouchTestAnchor(t *testing.T, fixture redisStoresFixture, session Handle, idle, absolute time.Duration) {
	t.Helper()

	now := fixture.clock.Now()
	anchor := SessionAnchor{
		Record: Record{Handle: session}, CreatedAt: now, LastTouchedAt: now,
		IdleExpiresAt: now.Add(idle), AbsoluteExpiresAt: now.Add(absolute),
	}

	if _, err := fixture.stores.Session.Commit(context.Background(), CommitRequest[SessionAnchor]{
		Reference: Reference{Session: session, Record: session}, Value: anchor, TTL: idle,
	}); err != nil {
		t.Fatalf("commit anchor: %v", err)
	}
}

// advanceTouchTestTime moves the repository clock and the Redis TTLs together.
func advanceTouchTestTime(fixture redisStoresFixture, delta time.Duration) {
	fixture.clock.Advance(delta)
	fixture.redis.FastForward(delta)
}

// assertTouchRejectedAfterRevocation proves that a revoked anchor is never extended.
func assertTouchRejectedAfterRevocation(t *testing.T, fixture redisStoresFixture, request TouchRequest) {
	t.Helper()

	ctx := context.Background()

	loaded, err := fixture.stores.Session.Load(ctx, request.Reference)
	if err != nil {
		t.Fatalf("load anchor before revocation: %v", err)
	}

	if err = fixture.stores.RevokeSession(ctx, RevocationRequest{
		Reference: request.Reference, ExpectedRevision: loaded.Revision, TombstoneTTL: time.Minute,
	}); err != nil {
		t.Fatalf("revoke anchor: %v", err)
	}

	if _, err = fixture.stores.TouchSession(ctx, request); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked anchor touch error = %v, want revoked", err)
	}
}
