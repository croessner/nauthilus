// Copyright (C) 2026 Christian Roessner
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

package grpcauthority

import (
	"context"
	"errors"
	"sync"
	"time"
)

const defaultMFAIdempotencyTTL = 15 * time.Minute

var (
	// ErrIdempotencyKeyMissing means a mutating authority request did not carry a key.
	ErrIdempotencyKeyMissing = errors.New("idempotency key is required")

	// ErrIdempotencyKeyReplay means a mutating authority request reused a live key.
	ErrIdempotencyKeyReplay = errors.New("idempotency key replay")
)

type idempotencyStore interface {
	Reserve(ctx context.Context, operation AuthorityOperation, principal string, key string) error
}

type memoryIdempotencyStore struct {
	ttl     time.Duration
	mu      sync.Mutex
	entries map[string]time.Time
}

func newMemoryIdempotencyStore(ttl time.Duration) *memoryIdempotencyStore {
	if ttl <= 0 {
		ttl = defaultMFAIdempotencyTTL
	}

	return &memoryIdempotencyStore{
		ttl:     ttl,
		entries: make(map[string]time.Time),
	}
}

func (s *memoryIdempotencyStore) Reserve(_ context.Context, operation AuthorityOperation, principal string, key string) error {
	if key == "" {
		return ErrIdempotencyKeyMissing
	}

	if s == nil {
		return nil
	}

	now := time.Now()
	entryKey := string(operation) + ":" + principal + ":" + key

	s.mu.Lock()
	defer s.mu.Unlock()

	s.pruneLocked(now)

	if expiresAt, ok := s.entries[entryKey]; ok && now.Before(expiresAt) {
		return ErrIdempotencyKeyReplay
	}

	s.entries[entryKey] = now.Add(s.ttl)

	return nil
}

func (s *memoryIdempotencyStore) pruneLocked(now time.Time) {
	for key, expiresAt := range s.entries {
		if !now.Before(expiresAt) {
			delete(s.entries, key)
		}
	}
}
