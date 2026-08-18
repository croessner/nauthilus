// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//nolint:gocyclo,funlen // Logout-index tests keep bounded ownership and revocation in one contract.
package sessionstate

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestLogoutIndexIsSessionBoundBoundedAndRevokedWithAnchor(t *testing.T) {
	t.Parallel()

	fixture := newRedisStoresFixture(t)
	ctx := context.Background()
	session := Handle("LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL")
	indexHandle := Handle("MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM")

	commitTestAnchor(t, fixture, session)

	reference := Reference{Session: session, Record: indexHandle}
	index := LogoutIndex{
		Record: Record{Handle: indexHandle}, Session: session,
		IdentityReference: "identity-42", Account: "alice",
		OIDCClientIDs: []string{"client-a", "client-b"},
	}

	revision, err := fixture.stores.CommitLogoutIndex(ctx, CommitRequest[LogoutIndex]{
		Reference: reference, Value: index, TTL: 30 * time.Minute,
	})
	if err != nil || revision != 1 {
		t.Fatalf("commit typed logout index: revision=%d err=%v", revision, err)
	}

	loaded, err := fixture.stores.Logout.Load(ctx, reference)
	if err != nil || loaded.Value.IdentityReference != "identity-42" || loaded.Value.Account != "alice" ||
		len(loaded.Value.OIDCClientIDs) != 2 || loaded.Value.OIDCClientIDs[0] != "client-a" ||
		loaded.Value.OIDCClientIDs[1] != "client-b" {
		t.Fatalf("typed logout index = %#v, err = %v", loaded, err)
	}

	anchor, err := fixture.stores.Session.Load(ctx, Reference{Session: session, Record: session})
	if err != nil || len(anchor.Value.LogoutIndexes) != 1 || anchor.Value.LogoutIndexes[0] != indexHandle {
		t.Fatalf("typed logout anchor index = %#v, err = %v", anchor.Value.LogoutIndexes, err)
	}

	wrongSession := Handle("NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN")

	_, err = fixture.stores.CommitLogoutIndex(ctx, CommitRequest[LogoutIndex]{
		Reference: Reference{Session: session, Record: indexHandle},
		Value: LogoutIndex{
			Record: Record{Handle: indexHandle}, Session: wrongSession,
			IdentityReference: "identity-42", Account: "alice", OIDCClientIDs: []string{"client-a"},
		},
		TTL: time.Minute,
	})
	if !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("cross-session logout index error = %v, want binding mismatch", err)
	}

	tooManyClients := make([]string, maxActiveProtocolFlows+1)
	for index := range tooManyClients {
		tooManyClients[index] = fmt.Sprintf("client-%d", index)
	}

	_, err = fixture.stores.CommitLogoutIndex(ctx, CommitRequest[LogoutIndex]{
		Reference: reference, ExpectedRevision: revision,
		Value: LogoutIndex{
			Record: Record{Handle: indexHandle}, Session: session,
			IdentityReference: "identity-42", Account: "alice", OIDCClientIDs: tooManyClients,
		},
		TTL: time.Minute,
	})
	if !errors.Is(err, ErrActiveFlowLimit) {
		t.Fatalf("oversized logout index error = %v, want active-flow limit", err)
	}

	anchor, err = fixture.stores.Session.Load(ctx, Reference{Session: session, Record: session})
	if err != nil {
		t.Fatalf("reload logout anchor before revoke: %v", err)
	}

	if err = fixture.stores.RevokeSession(ctx, RevocationRequest{
		Reference: Reference{Session: session, Record: session}, ExpectedRevision: anchor.Revision,
		TombstoneTTL: 5 * time.Minute,
		Children:     []OwnedReference{{Owner: OwnerConsent, Reference: reference}},
	}); err != nil {
		t.Fatalf("revoke logout index with anchor: %v", err)
	}

	if got := len(fixture.redis.Keys()); got != 1 {
		t.Fatalf("logout revocation Redis keys = %d, want tombstone only", got)
	}
}
