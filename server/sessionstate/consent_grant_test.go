// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//nolint:gocyclo,funlen // Consent-store tests keep revision, scope, expiry, and binding checks together.
package sessionstate

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestConsentGrantStoreIsIndependentBoundedAndRevisionChecked(t *testing.T) {
	t.Parallel()

	fixture := newRedisStoresFixture(t)
	ctx := context.Background()

	reference, err := ConsentGrantReference("identity-42", "client-a")
	if err != nil {
		t.Fatalf("derive consent grant reference: %v", err)
	}

	otherClient, err := ConsentGrantReference("identity-42", "client-b")
	if err != nil {
		t.Fatalf("derive other-client consent reference: %v", err)
	}

	otherIdentity, err := ConsentGrantReference("identity-99", "client-a")
	if err != nil {
		t.Fatalf("derive other-identity consent reference: %v", err)
	}

	if reference == otherClient || reference == otherIdentity {
		t.Fatalf("consent references are not identity/client isolated: %#v %#v %#v", reference, otherClient, otherIdentity)
	}

	grant := ConsentGrant{
		Record: Record{Handle: reference.Record}, IdentityReference: "identity-42", ClientID: "client-a",
		Scopes: []string{"profile", "openid", "profile"}, GrantedAt: fixture.clock.Now(),
		GrantExpiresAt: fixture.clock.Now().Add(30 * 24 * time.Hour),
	}

	revision, err := fixture.stores.Consent.Commit(ctx, CommitRequest[ConsentGrant]{
		Reference: reference, Value: grant, TTL: 30 * 24 * time.Hour,
	})
	if err != nil || revision != 1 {
		t.Fatalf("commit independent consent grant: revision=%d err=%v", revision, err)
	}

	loaded, err := fixture.stores.Consent.Load(ctx, reference)
	if err != nil || loaded.Revision != 1 || !loaded.Value.Covers([]string{"openid", "profile"}, fixture.clock.Now()) ||
		loaded.Value.Covers([]string{"openid", "email"}, fixture.clock.Now()) {
		t.Fatalf("loaded consent grant = %#v, err = %v", loaded, err)
	}

	key, err := fixture.stores.keyspace.Key(OwnerConsent, reference)
	if err != nil || strings.Contains(key, "identity-42") || strings.Contains(key, "client-a") {
		t.Fatalf("consent key discloses binding: key=%q err=%v", key, err)
	}

	grant.Scopes = []string{"openid", "profile", "email"}
	if _, err = fixture.stores.Consent.Commit(ctx, CommitRequest[ConsentGrant]{
		Reference: reference, ExpectedRevision: 0, Value: grant, TTL: 30 * 24 * time.Hour,
	}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale consent update error = %v, want %v", err, ErrRevisionConflict)
	}

	if _, err = fixture.stores.Consent.Load(ctx, otherClient); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-client consent load error = %v, want %v", err, ErrNotFound)
	}

	if _, err = fixture.stores.Consent.Load(ctx, otherIdentity); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-identity consent load error = %v, want %v", err, ErrNotFound)
	}

	fixture.clock.Advance(31 * 24 * time.Hour)
	fixture.redis.FastForward(31 * 24 * time.Hour)

	if _, err = fixture.stores.Consent.Load(ctx, reference); !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrExpired) {
		t.Fatalf("expired consent load error = %v", err)
	}
}

func TestConsentGrantRejectsPayloadReferenceMismatch(t *testing.T) {
	t.Parallel()

	fixture := newRedisStoresFixture(t)

	reference, err := ConsentGrantReference("identity-42", "client-a")
	if err != nil {
		t.Fatalf("derive consent grant reference: %v", err)
	}

	grant := ConsentGrant{
		Record: Record{Handle: reference.Record}, IdentityReference: "identity-42", ClientID: "client-b",
		Scopes: []string{"openid"}, GrantedAt: fixture.clock.Now(), GrantExpiresAt: fixture.clock.Now().Add(time.Hour),
	}
	if _, err = fixture.stores.Consent.Commit(context.Background(), CommitRequest[ConsentGrant]{
		Reference: reference, Value: grant, TTL: time.Hour,
	}); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("mismatched consent payload error = %v, want %v", err, ErrBindingMismatch)
	}
}
