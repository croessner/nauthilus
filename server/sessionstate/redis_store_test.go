// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sessionstate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

type mutableClock struct {
	now time.Time
}

// Now returns the controlled repository test time.
func (c *mutableClock) Now() time.Time { return c.now }

// Advance moves controlled repository test time forward.
func (c *mutableClock) Advance(delta time.Duration) { c.now = c.now.Add(delta) }

// TestRandomHandleAndRedisKeyContracts prove entropy encoding and non-disclosing cluster keys.
func TestRandomHandleAndRedisKeyContracts(t *testing.T) {
	t.Parallel()

	generator := NewRandomHandleGenerator(nil)
	first := generateTestHandle(t, generator, "first")
	second := generateTestHandle(t, generator, "second")

	if first == second || len(first) != EncodedHandleLength || len(second) != EncodedHandleLength {
		t.Fatalf("unexpected 256-bit handles: first=%d second=%d equal=%t", len(first), len(second), first == second)
	}

	keyspace, err := NewKeyspace("browser-session", []byte("key-derivation-secret-with-32-bytes"))
	if err != nil {
		t.Fatalf("create keyspace: %v", err)
	}

	anchorKey := deriveTestKey(t, keyspace, OwnerSessionAnchor, Reference{Session: first, Record: first})
	childKey := deriveTestKey(t, keyspace, OwnerOIDCFlow, Reference{Session: first, Record: second})

	if strings.Contains(anchorKey, string(first)) || strings.Contains(childKey, string(first)) || strings.Contains(childKey, string(second)) {
		t.Fatalf("redis key disclosed a raw handle: anchor=%q child=%q", anchorKey, childKey)
	}

	if RedisClusterHashTag(anchorKey) != RedisClusterHashTag(childKey) {
		t.Fatalf("coordinated keys use different hash tags: anchor=%q child=%q", anchorKey, childKey)
	}
}

// generateTestHandle creates one handle or fails the current test.
func generateTestHandle(t *testing.T, generator HandleGenerator, label string) Handle {
	t.Helper()

	handle, err := generator.NewHandle()
	if err != nil {
		t.Fatalf("generate %s handle: %v", label, err)
	}

	return handle
}

// deriveTestKey creates one Redis key or fails the current test.
func deriveTestKey(t *testing.T, keyspace Keyspace, owner Owner, reference Reference) string {
	t.Helper()

	key, err := keyspace.Key(owner, reference)
	if err != nil {
		t.Fatalf("derive %s key: %v", owner, err)
	}

	return key
}

// TestRedisStoresEnforceCASIsolationExpiryAndParentBinding exercises the typed store security contract.
func TestRedisStoresEnforceCASIsolationExpiryAndParentBinding(t *testing.T) {
	t.Parallel()

	fixture := newRedisStoresFixture(t)
	ctx := context.Background()
	session := Handle("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	oidcHandle := Handle("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
	anchorReference := Reference{Session: session, Record: session}
	oidcReference := Reference{Session: session, Record: oidcHandle}

	anchor := SessionAnchor{
		Record:            Record{Handle: session},
		CreatedAt:         fixture.clock.Now(),
		IdleExpiresAt:     fixture.clock.Now().Add(30 * time.Minute),
		AbsoluteExpiresAt: fixture.clock.Now().Add(time.Hour),
	}

	revision, err := fixture.stores.Session.Commit(ctx, CommitRequest[SessionAnchor]{
		Reference: anchorReference,
		Value:     anchor,
		TTL:       time.Hour,
	})
	if err != nil || revision != 1 {
		t.Fatalf("commit anchor: revision=%d err=%v", revision, err)
	}

	oidc := OIDCFlow{Record: Record{Handle: oidcHandle}, Session: session}

	revision, err = fixture.stores.OIDC.Commit(ctx, CommitRequest[OIDCFlow]{
		Reference: oidcReference,
		Value:     oidc,
		TTL:       2 * time.Hour,
	})
	if err != nil || revision != 1 {
		t.Fatalf("commit OIDC flow: revision=%d err=%v", revision, err)
	}

	if _, err = fixture.stores.SAML.Load(ctx, oidcReference); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SAML repository loaded OIDC record: %v", err)
	}

	_, err = fixture.stores.OIDC.Commit(ctx, CommitRequest[OIDCFlow]{
		Reference:        oidcReference,
		ExpectedRevision: 0,
		Value:            oidc,
		TTL:              time.Minute,
	})
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale OIDC commit error = %v, want revision conflict", err)
	}

	childKey, err := fixture.stores.keyspace.Key(OwnerOIDCFlow, oidcReference)
	if err != nil {
		t.Fatalf("derive OIDC key: %v", err)
	}

	if ttl := fixture.redis.TTL(childKey); ttl > time.Hour || ttl <= 0 {
		t.Fatalf("child TTL = %v, want positive and capped to parent absolute expiry", ttl)
	}
}

// TestRedisStoresBoundTouchesAndPurgeOrphans proves idle-write bounds and fail-closed cleanup.
func TestRedisStoresBoundTouchesAndPurgeOrphans(t *testing.T) {
	t.Parallel()

	fixture := newRedisStoresFixture(t)
	ctx := context.Background()
	session := Handle("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
	child := Handle("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD")
	anchorReference := Reference{Session: session, Record: session}
	childReference := Reference{Session: session, Record: child}

	anchor := SessionAnchor{
		Record:            Record{Handle: session},
		CreatedAt:         fixture.clock.Now(),
		IdleExpiresAt:     fixture.clock.Now().Add(20 * time.Minute),
		AbsoluteExpiresAt: fixture.clock.Now().Add(time.Hour),
	}
	if _, err := fixture.stores.Session.Commit(ctx, CommitRequest[SessionAnchor]{
		Reference: anchorReference,
		Value:     anchor,
		TTL:       time.Hour,
	}); err != nil {
		t.Fatalf("commit anchor: %v", err)
	}

	touched, err := fixture.stores.TouchSession(ctx, anchorReference, 20*time.Minute)
	if err != nil || touched {
		t.Fatalf("early touch: touched=%t err=%v", touched, err)
	}

	fixture.clock.Advance(6 * time.Minute)

	touched, err = fixture.stores.TouchSession(ctx, anchorReference, 20*time.Minute)
	if err != nil || !touched {
		t.Fatalf("bounded touch: touched=%t err=%v", touched, err)
	}

	stepUp := StepUpRecord{Record: Record{Handle: child}, Session: session}
	if _, err = fixture.stores.StepUp.Commit(ctx, CommitRequest[StepUpRecord]{
		Reference: childReference,
		Value:     stepUp,
		TTL:       10 * time.Minute,
	}); err != nil {
		t.Fatalf("commit step-up: %v", err)
	}

	if err = fixture.stores.Session.Delete(ctx, DeleteRequest{Reference: anchorReference, ExpectedRevision: 2}); err != nil {
		t.Fatalf("delete parent: %v", err)
	}

	if _, err = fixture.stores.StepUp.Load(ctx, childReference); !errors.Is(err, ErrParentMissing) {
		t.Fatalf("orphan load error = %v, want missing parent", err)
	}

	childKey, keyErr := fixture.stores.keyspace.Key(OwnerStepUp, childReference)
	if keyErr != nil {
		t.Fatalf("derive child key: %v", keyErr)
	}

	if fixture.redis.Exists(childKey) {
		t.Fatalf("orphan key %q was not purged", childKey)
	}
}

// TestRedisStoresCommitAtomicallyAndRevokeChildren proves rollback, tombstone ordering, and child cleanup.
func TestRedisStoresCommitAtomicallyAndRevokeChildren(t *testing.T) {
	t.Parallel()

	fixture := newRedisStoresFixture(t)
	state := seedTransactionFixture(t, fixture)

	_, err := fixture.stores.Commit(context.Background(), staleTransactionRequest(state))
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale transaction error = %v, want revision conflict", err)
	}

	assertTransactionRollback(t, fixture, state)
	revokeAndAssertCleanup(t, fixture, state)
}

type transactionFixture struct {
	anchor          SessionAnchor
	oidc            OIDCFlow
	anchorReference Reference
	childReference  Reference
	anchorRevision  Revision
	childRevision   Revision
}

// seedTransactionFixture commits one anchor and OIDC child for transaction tests.
func seedTransactionFixture(t *testing.T, fixture redisStoresFixture) transactionFixture {
	t.Helper()

	ctx := context.Background()
	session := Handle("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")
	child := Handle("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
	state := transactionFixture{
		anchorReference: Reference{Session: session, Record: session},
		childReference:  Reference{Session: session, Record: child},
		anchor: SessionAnchor{
			Record: Record{Handle: session}, CreatedAt: fixture.clock.Now(),
			IdleExpiresAt: fixture.clock.Now().Add(30 * time.Minute), AbsoluteExpiresAt: fixture.clock.Now().Add(time.Hour),
		},
		oidc: OIDCFlow{Record: Record{Handle: child}, Session: session},
	}

	var err error

	state.anchorRevision, err = fixture.stores.Session.Commit(ctx, CommitRequest[SessionAnchor]{
		Reference: state.anchorReference, Value: state.anchor, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("commit anchor: %v", err)
	}

	state.childRevision, err = fixture.stores.OIDC.Commit(ctx, CommitRequest[OIDCFlow]{
		Reference: state.childReference, Value: state.oidc, TTL: 20 * time.Minute,
	})
	if err != nil {
		t.Fatalf("commit OIDC child: %v", err)
	}

	return state
}

// staleTransactionRequest creates an intentionally stale child mutation.
func staleTransactionRequest(state transactionFixture) TransactionRequest {
	state.anchor.Authenticated = true

	return TransactionRequest{
		Session: &CommitRequest[SessionAnchor]{
			Reference: state.anchorReference, ExpectedRevision: state.anchorRevision, Value: state.anchor, TTL: time.Hour,
		},
		OIDC: []CommitRequest[OIDCFlow]{
			{
				Reference: state.childReference, ExpectedRevision: state.childRevision - 1, Value: state.oidc, TTL: 20 * time.Minute,
			},
		},
	}
}

// assertTransactionRollback verifies that a stale child prevented every write.
func assertTransactionRollback(t *testing.T, fixture redisStoresFixture, state transactionFixture) {
	t.Helper()

	loadedAnchor, err := fixture.stores.Session.Load(context.Background(), state.anchorReference)
	if err != nil {
		t.Fatalf("load anchor after rollback: %v", err)
	}

	if loadedAnchor.Revision != state.anchorRevision || loadedAnchor.Value.Authenticated {
		t.Fatalf("partial transaction became visible: %#v", loadedAnchor)
	}
}

// revokeAndAssertCleanup verifies tombstone visibility and child cleanup.
func revokeAndAssertCleanup(t *testing.T, fixture redisStoresFixture, state transactionFixture) {
	t.Helper()

	ctx := context.Background()

	err := fixture.stores.RevokeSession(ctx, RevocationRequest{
		Reference: state.anchorReference, ExpectedRevision: state.anchorRevision, TombstoneTTL: 5 * time.Minute,
		Children: []OwnedReference{{Owner: OwnerOIDCFlow, Reference: state.childReference}},
	})
	if err != nil {
		t.Fatalf("revoke session: %v", err)
	}

	if _, err = fixture.stores.Session.Load(ctx, state.anchorReference); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked anchor load error = %v, want revoked", err)
	}

	if _, err = fixture.stores.OIDC.Load(ctx, state.childReference); !errors.Is(err, ErrParentMissing) {
		t.Fatalf("revoked child load error = %v, want missing parent", err)
	}
}

// TestEveryTypedRepositoryRejectsCrossBindingAndMissingTTL covers all separate record families.
func TestEveryTypedRepositoryRejectsCrossBindingAndMissingTTL(t *testing.T) {
	t.Parallel()

	fixture := newRedisStoresFixture(t)
	session := Handle("GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG")
	commitTestAnchor(t, fixture, session)
	assertCrossBindingRejected(t, fixture, session)

	for index, item := range typedRepositoryCases(fixture, session) {
		assertMissingTTLRejected(t, fixture, session, index, item)
	}
}

type typedRepositoryCase struct {
	owner  Owner
	commit func(Reference) error
	load   func(Reference) error
}

// commitTestAnchor creates the live parent required by typed child repositories.
func commitTestAnchor(t *testing.T, fixture redisStoresFixture, session Handle) {
	t.Helper()

	anchor := SessionAnchor{
		Record: Record{Handle: session}, CreatedAt: fixture.clock.Now(),
		IdleExpiresAt: fixture.clock.Now().Add(30 * time.Minute), AbsoluteExpiresAt: fixture.clock.Now().Add(time.Hour),
	}

	_, err := fixture.stores.Session.Commit(context.Background(), CommitRequest[SessionAnchor]{
		Reference: Reference{Session: session, Record: session}, Value: anchor, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("commit anchor: %v", err)
	}
}

// assertCrossBindingRejected proves a typed child cannot claim another session.
func assertCrossBindingRejected(t *testing.T, fixture redisStoresFixture, session Handle) {
	t.Helper()

	wrongSession := Handle("HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH")
	reference := Reference{Session: session, Record: wrongSession}

	_, err := fixture.stores.Enrollment.Commit(context.Background(), CommitRequest[EnrollmentRecord]{
		Reference: reference,
		Value:     EnrollmentRecord{Record: Record{Handle: wrongSession}, Session: wrongSession},
		TTL:       time.Minute,
	})
	if !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("cross-session enrollment error = %v, want binding mismatch", err)
	}
}

// typedRepositoryCases creates commit adapters for every short-lived child family.
func typedRepositoryCases(fixture redisStoresFixture, session Handle) []typedRepositoryCase {
	return []typedRepositoryCase{
		newTypedRepositoryCase(OwnerEnrollment, fixture.stores.Enrollment, func(ref Reference) EnrollmentRecord {
			return EnrollmentRecord{Record: Record{Handle: ref.Record}, Session: session}
		}),
		newTypedRepositoryCase(OwnerStepUp, fixture.stores.StepUp, func(ref Reference) StepUpRecord {
			return StepUpRecord{Record: Record{Handle: ref.Record}, Session: session}
		}),
		newTypedRepositoryCase(OwnerWebAuthnCeremony, fixture.stores.Ceremony, func(ref Reference) CeremonyRecord {
			return CeremonyRecord{Record: Record{Handle: ref.Record}, Session: session}
		}),
		newTypedRepositoryCase(OwnerTOTPRecovery, fixture.stores.TOTPRecovery, func(ref Reference) TOTPRecoveryRecord {
			return TOTPRecoveryRecord{Record: Record{Handle: ref.Record}, Session: session}
		}),
	}
}

// newTypedRepositoryCase adapts one generic repository to the shared corruption test.
func newTypedRepositoryCase[T any](
	owner Owner,
	repository *RedisRepository[T],
	value func(Reference) T,
) typedRepositoryCase {
	return typedRepositoryCase{
		owner: owner,
		commit: func(reference Reference) error {
			_, err := repository.Commit(context.Background(), CommitRequest[T]{
				Reference: reference, Value: value(reference), TTL: time.Minute,
			})

			return err
		},
		load: func(reference Reference) error {
			_, err := repository.Load(context.Background(), reference)

			return err
		},
	}
}

// assertMissingTTLRejected corrupts one record and proves fail-closed metadata validation.
func assertMissingTTLRejected(
	t *testing.T,
	fixture redisStoresFixture,
	session Handle,
	index int,
	item typedRepositoryCase,
) {
	t.Helper()

	handle := Handle(strings.Repeat(string(rune('I'+index)), EncodedHandleLength))

	reference := Reference{Session: session, Record: handle}
	if err := item.commit(reference); err != nil {
		t.Fatalf("commit %s: %v", item.owner, err)
	}

	key := deriveTestKey(t, fixture.stores.keyspace, item.owner, reference)
	fixture.redis.HDel(key, "expires_at_ms")

	if err := item.load(reference); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("missing %s TTL error = %v, want binding mismatch", item.owner, err)
	}
}

type failingReader struct{}

// Read always fails to exercise entropy-source failure handling.
func (failingReader) Read([]byte) (int, error) { return 0, fmt.Errorf("entropy unavailable") }

// TestRedisStoresPropagateEntropyAndRedisFailures proves creation cannot continue after dependencies fail.
func TestRedisStoresPropagateEntropyAndRedisFailures(t *testing.T) {
	t.Parallel()

	if _, err := NewRandomHandleGenerator(failingReader{}).NewHandle(); err == nil {
		t.Fatal("handle generation succeeded without entropy")
	}

	fixture := newRedisStoresFixture(t)
	if err := fixture.client.Close(); err != nil {
		t.Fatalf("close Redis client: %v", err)
	}

	session := Handle("MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM")
	anchor := SessionAnchor{
		Record: Record{Handle: session}, CreatedAt: fixture.clock.Now(),
		IdleExpiresAt: fixture.clock.Now().Add(time.Minute), AbsoluteExpiresAt: fixture.clock.Now().Add(time.Hour),
	}

	_, err := fixture.stores.Session.Commit(context.Background(), CommitRequest[SessionAnchor]{
		Reference: Reference{Session: session, Record: session}, Value: anchor, TTL: time.Minute,
	})
	if err == nil {
		t.Fatal("anchor commit succeeded after Redis failure")
	}
}

type redisStoresFixture struct {
	redis  *miniredis.Miniredis
	client *redis.Client
	clock  *mutableClock
	stores *RedisStores
}

// newRedisStoresFixture creates an isolated real Redis-protocol store fixture.
func newRedisStoresFixture(t *testing.T) redisStoresFixture {
	t.Helper()

	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})

	t.Cleanup(func() { _ = client.Close() })

	clock := &mutableClock{now: time.Unix(1_800_000_000, 0).UTC()}

	stores, err := NewRedisStores(client, []byte("key-derivation-secret-with-32-bytes"), clock, RedisStoreConfig{
		Prefix:        "browser-session",
		TouchInterval: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("create Redis stores: %v", err)
	}

	return redisStoresFixture{redis: server, client: client, clock: clock, stores: stores}
}
