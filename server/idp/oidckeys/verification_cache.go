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
	"crypto"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// VerificationKeyCacheTTL bounds how long a process reuses a public verification key it loaded from Redis.
	//
	// A key ID names immutable key material, and rotation only adds new key IDs, so a positive entry never
	// becomes wrong while its key is unexpired. The only change a process can miss is an out-of-band deletion
	// of a still-valid key in another process; this TTL bounds that window. Ten seconds removes almost every
	// key-store read on the validation path while staying far below access token lifetimes.
	VerificationKeyCacheTTL = 10 * time.Second

	// maximumVerificationKeyCacheEntries bounds memory; only existing, unexpired keys are ever cached.
	maximumVerificationKeyCacheEntries = 64
)

// verificationKeyGeneration changes on every key-store mutation in this process. Entries loaded under an
// older generation are ignored, so rotation or cleanup through any Manager invalidates every Manager cache.
var verificationKeyGeneration atomic.Uint64

// invalidateVerificationKeys drops every cached verification key in this process.
func invalidateVerificationKeys() {
	verificationKeyGeneration.Add(1)
}

// verificationKeyCacheKey identifies one key by its Redis hash and key ID.
type verificationKeyCacheKey struct {
	hashKey string
	kid     string
}

// verificationKeyEntry holds only public key material, never a private or signing key.
type verificationKeyEntry struct {
	publicKey  crypto.PublicKey
	validUntil time.Time
	generation uint64
}

// verificationKeyCache is a bounded, process-local positive cache for public verification keys.
type verificationKeyCache struct {
	entries map[verificationKeyCacheKey]verificationKeyEntry
	now     func() time.Time
	ttl     time.Duration
	mu      sync.RWMutex
}

// newVerificationKeyCache creates an empty cache with the given lifetime per entry.
func newVerificationKeyCache(ttl time.Duration) *verificationKeyCache {
	return &verificationKeyCache{entries: make(map[verificationKeyCacheKey]verificationKeyEntry), now: time.Now, ttl: ttl}
}

// get returns a cached public key only while it is within its TTL, its key expiry and the current generation.
func (c *verificationKeyCache) get(key verificationKeyCacheKey) (crypto.PublicKey, bool) {
	if c == nil {
		return nil, false
	}

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok || !c.usable(entry) {
		return nil, false
	}

	return entry.publicKey, true
}

// put stores a freshly loaded public key unless the key store changed since generation was observed.
func (c *verificationKeyCache) put(key verificationKeyCacheKey, publicKey crypto.PublicKey, expiresAt time.Time, generation uint64) {
	if c == nil || publicKey == nil || c.ttl <= 0 {
		return
	}

	validUntil := c.now().Add(c.ttl)
	if !expiresAt.IsZero() && expiresAt.Before(validUntil) {
		validUntil = expiresAt
	}

	entry := verificationKeyEntry{publicKey: publicKey, validUntil: validUntil, generation: generation}
	if !c.usable(entry) {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= maximumVerificationKeyCacheEntries {
		c.pruneLocked()
	}

	c.entries[key] = entry
}

// usable reports whether an entry is current and unexpired at the cache clock.
func (c *verificationKeyCache) usable(entry verificationKeyEntry) bool {
	return entry.generation == verificationKeyGeneration.Load() && c.now().Before(entry.validUntil)
}

// pruneLocked removes unusable entries and resets the cache if it is still full; the caller holds the lock.
func (c *verificationKeyCache) pruneLocked() {
	for key, entry := range c.entries {
		if !c.usable(entry) {
			delete(c.entries, key)
		}
	}

	if len(c.entries) >= maximumVerificationKeyCacheEntries {
		clear(c.entries)
	}
}
