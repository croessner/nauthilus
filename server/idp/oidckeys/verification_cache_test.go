// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package oidckeys

import (
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/alicebob/miniredis/v2/server"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/idp/signing"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/redis/go-redis/v9"
)

const verificationTestPrefix = "vk-test:"

// keyStoreReads counts HGET reads of the signing-key hashes seen by one private miniredis server.
type keyStoreReads struct {
	count atomic.Int64
}

// newVerificationTestManager returns a Manager on a private miniredis and a counter of key-store reads.
func newVerificationTestManager(t *testing.T) (*Manager, *miniredis.Miniredis, *keyStoreReads) {
	t.Helper()

	store := miniredis.RunT(t)
	reads := &keyStoreReads{}

	store.Server().SetPreHook(func(_ *server.Peer, command string, args ...string) bool {
		if strings.EqualFold(command, "HGET") && len(args) > 0 && strings.HasSuffix(args[0], "keys") {
			reads.count.Add(1)
		}

		return false
	})

	handle := redis.NewClient(&redis.Options{Addr: store.Addr()})

	t.Cleanup(func() { _ = handle.Close() })

	cfg := &config.FileSettings{
		Server: &config.ServerSection{Redis: config.Redis{Prefix: verificationTestPrefix}},
		IDP:    &config.IDPSection{OIDC: config.OIDCConfig{KeyMaxAge: time.Hour}},
	}

	return NewManager(&deps.Deps{Cfg: cfg, Redis: rediscli.NewTestClient(handle)}), store, reads
}

// assertKeyStoreReads fails when the observed number of key-store reads differs from want.
func assertKeyStoreReads(t *testing.T, reads *keyStoreReads, want int64) {
	t.Helper()

	if got := reads.count.Load(); got != want {
		t.Fatalf("key-store reads = %d, want %d", got, want)
	}
}

// TestVerificationKeyByIDServesRepeatedLookupsFromCache pins one key-store read per key ID and TTL window.
func TestVerificationKeyByIDServesRepeatedLookupsFromCache(t *testing.T) {
	tests := []struct {
		generate  func(*Manager) (string, error)
		algorithm string
	}{
		{algorithm: signing.AlgorithmRS256, generate: func(m *Manager) (string, error) { return m.GenerateNewKey(t.Context()) }},
		{algorithm: signing.AlgorithmEdDSA, generate: func(m *Manager) (string, error) { return m.GenerateNewEdKey(t.Context()) }},
	}

	for _, test := range tests {
		t.Run(test.algorithm, func(t *testing.T) {
			manager, _, reads := newVerificationTestManager(t)

			kid, err := test.generate(manager)
			if err != nil {
				t.Fatalf("generate key: %v", err)
			}

			first, err := manager.VerificationKeyByID(t.Context(), test.algorithm, kid)
			if err != nil {
				t.Fatalf("first lookup: %v", err)
			}

			for range 5 {
				again, err := manager.VerificationKeyByID(t.Context(), test.algorithm, kid)
				if err != nil || !publicKeysEqual(first, again) {
					t.Fatalf("cached lookup = (%v, %v), want the first public key", again, err)
				}
			}

			assertKeyStoreReads(t, reads, 1)
		})
	}
}

// TestVerificationKeyCacheHoldsOnlyPublicKeys pins that no private or signing key material is retained.
func TestVerificationKeyCacheHoldsOnlyPublicKeys(t *testing.T) {
	manager, _, _ := newVerificationTestManager(t)

	rsaKID, err := manager.GenerateNewKey(t.Context())
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	edKID, err := manager.GenerateNewEdKey(t.Context())
	if err != nil {
		t.Fatalf("generate EdDSA key: %v", err)
	}

	for algorithm, kid := range map[string]string{signing.AlgorithmRS256: rsaKID, signing.AlgorithmEdDSA: edKID} {
		if _, err := manager.VerificationKeyByID(t.Context(), algorithm, kid); err != nil {
			t.Fatalf("lookup %s: %v", algorithm, err)
		}
	}

	manager.verificationKeys.mu.RLock()
	defer manager.verificationKeys.mu.RUnlock()

	if len(manager.verificationKeys.entries) != 2 {
		t.Fatalf("cache entries = %d, want 2", len(manager.verificationKeys.entries))
	}

	for _, entry := range manager.verificationKeys.entries {
		switch entry.publicKey.(type) {
		case *rsa.PublicKey, ed25519.PublicKey:
		default:
			t.Fatalf("cache retained %T, want public key material only", entry.publicKey)
		}
	}
}

// TestVerificationKeyByIDNeverCachesMissesOrFailures pins that unknown key IDs and store failures always reach Redis.
func TestVerificationKeyByIDNeverCachesMissesOrFailures(t *testing.T) {
	manager, store, reads := newVerificationTestManager(t)

	for range 3 {
		if _, err := manager.VerificationKeyByID(t.Context(), signing.AlgorithmRS256, "unknown-kid"); err == nil {
			t.Fatal("unknown key ID was accepted")
		}
	}

	assertKeyStoreReads(t, reads, 3)

	kid, err := manager.GenerateNewKey(t.Context())
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	store.SetError("simulated key store outage")

	_, err = manager.VerificationKeyByID(t.Context(), signing.AlgorithmRS256, kid)
	if !errors.Is(err, ErrKeyStoreUnavailable) {
		t.Fatalf("lookup during outage error = %v, want ErrKeyStoreUnavailable", err)
	}

	store.SetError("")

	if _, err := manager.VerificationKeyByID(t.Context(), signing.AlgorithmRS256, kid); err != nil {
		t.Fatalf("lookup after outage: %v", err)
	}
}

// TestVerificationKeyCacheIsInvalidatedByRotationInAnyManager pins process-wide invalidation on key-store changes.
func TestVerificationKeyCacheIsInvalidatedByRotationInAnyManager(t *testing.T) {
	manager, _, reads := newVerificationTestManager(t)
	rotator, _, _ := newVerificationTestManager(t)

	kid, err := manager.GenerateNewKey(t.Context())
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	if _, err := manager.VerificationKeyByID(t.Context(), signing.AlgorithmRS256, kid); err != nil {
		t.Fatalf("first lookup: %v", err)
	}

	if _, err := rotator.GenerateNewKey(t.Context()); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	if _, err := manager.VerificationKeyByID(t.Context(), signing.AlgorithmRS256, kid); err != nil {
		t.Fatalf("lookup after rotation: %v", err)
	}

	assertKeyStoreReads(t, reads, 2)
}

// TestVerificationKeyCacheBoundsEntriesByTTLAndKeyExpiry pins that an entry never outlives either bound.
func TestVerificationKeyCacheBoundsEntriesByTTLAndKeyExpiry(t *testing.T) {
	now := time.Now()
	cache := newVerificationKeyCache(10 * time.Second)
	cache.now = func() time.Time { return now }
	generation := verificationKeyGeneration.Load()
	longLived := verificationKeyCacheKey{hashKey: RedisKeyOIDCKeys, kid: "long-lived"}
	expiring := verificationKeyCacheKey{hashKey: RedisKeyOIDCKeys, kid: "expiring"}
	publicKey := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))

	cache.put(longLived, publicKey, now.Add(time.Hour), generation)
	cache.put(expiring, publicKey, now.Add(2*time.Second), generation)
	cache.put(verificationKeyCacheKey{kid: "expired"}, publicKey, now.Add(-time.Second), generation)

	now = now.Add(3 * time.Second)

	if _, ok := cache.get(expiring); ok {
		t.Fatal("entry outlived its key expiry")
	}

	if _, ok := cache.get(longLived); !ok {
		t.Fatal("entry expired before its TTL")
	}

	now = now.Add(8 * time.Second)

	if _, ok := cache.get(longLived); ok {
		t.Fatal("entry outlived its TTL")
	}

	if len(cache.entries) != 2 {
		t.Fatalf("cache stored %d entries, want 2 (already expired keys are rejected)", len(cache.entries))
	}
}

// TestVerificationKeyCacheRejectsLoadsRacingAnInvalidation pins that a lookup started before a rotation cannot repopulate the cache.
func TestVerificationKeyCacheRejectsLoadsRacingAnInvalidation(t *testing.T) {
	cache := newVerificationKeyCache(time.Minute)
	key := verificationKeyCacheKey{hashKey: RedisKeyOIDCKeys, kid: "racing"}
	generation := verificationKeyGeneration.Load()

	invalidateVerificationKeys()
	cache.put(key, ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)), time.Time{}, generation)

	if _, ok := cache.get(key); ok {
		t.Fatal("a load that raced an invalidation populated the cache")
	}
}

// TestVerificationKeyByIDIsSafeForConcurrentUse exercises lookups, rotation and invalidation under the race detector.
func TestVerificationKeyByIDIsSafeForConcurrentUse(t *testing.T) {
	manager, _, _ := newVerificationTestManager(t)

	kid, err := manager.GenerateNewKey(t.Context())
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var group sync.WaitGroup

	for worker := range 8 {
		group.Go(func() {
			for iteration := range 50 {
				if _, err := manager.VerificationKeyByID(t.Context(), signing.AlgorithmRS256, kid); err != nil {
					t.Errorf("concurrent lookup: %v", err)

					return
				}

				if worker == 0 && iteration%10 == 0 {
					invalidateVerificationKeys()
				}
			}
		})
	}

	group.Wait()
}

// publicKeysEqual compares the two supported public key types by value.
func publicKeysEqual(left, right any) bool {
	switch key := left.(type) {
	case *rsa.PublicKey:
		return key.Equal(right)
	case ed25519.PublicKey:
		return key.Equal(right)
	default:
		return false
	}
}
