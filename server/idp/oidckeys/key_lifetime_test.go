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
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/redis/go-redis/v9"
)

// TestGeneratedKeyLifetimeFollowsKeyMaxAge pins generated signing-key expiry to the effective key_max_age, so an
// unset or invalid value uses the same default as the config getter and the config dump.
func TestGeneratedKeyLifetimeFollowsKeyMaxAge(t *testing.T) {
	defaultMaxAge := (&config.OIDCConfig{}).GetKeyMaxAge()

	for _, tc := range []struct {
		name       string
		keyMaxAge  time.Duration
		wantMaxAge time.Duration
	}{
		{name: "unset", keyMaxAge: 0, wantMaxAge: defaultMaxAge},
		{name: "negative", keyMaxAge: -time.Hour, wantMaxAge: defaultMaxAge},
		{name: "configured", keyMaxAge: 36 * time.Hour, wantMaxAge: 36 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager := newKeyLifetimeTestManager(t, tc.keyMaxAge)

			for _, generated := range []struct {
				hashKey  string
				generate func(context.Context) (string, error)
			}{
				{hashKey: RedisKeyOIDCKeys, generate: manager.GenerateNewKey},
				{hashKey: RedisKeyOIDCEdKeys, generate: manager.GenerateNewEdKey},
			} {
				kid, err := generated.generate(t.Context())
				if err != nil {
					t.Fatalf("generate %s key: %v", generated.hashKey, err)
				}

				meta, err := manager.getKeyMetadataFromRedisHash(t.Context(), kid, generated.hashKey)
				if err != nil {
					t.Fatalf("load %s key metadata: %v", generated.hashKey, err)
				}

				if got := meta.ExpiresAt.Sub(meta.CreatedAt); got != tc.wantMaxAge {
					t.Fatalf("%s key lifetime = %s, want %s", generated.hashKey, got, tc.wantMaxAge)
				}
			}
		})
	}
}

// newKeyLifetimeTestManager returns a Manager on a private miniredis with the given key_max_age.
func newKeyLifetimeTestManager(t *testing.T, keyMaxAge time.Duration) *Manager {
	t.Helper()

	store := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: store.Addr()})

	t.Cleanup(func() { _ = handle.Close() })

	cfg := &config.FileSettings{
		Server: &config.ServerSection{Redis: config.Redis{Prefix: "key-lifetime:"}},
		IDP:    &config.IDPSection{OIDC: config.OIDCConfig{KeyMaxAge: keyMaxAge}},
	}

	return NewManager(&deps.Deps{Cfg: cfg, Redis: rediscli.NewTestClient(handle)})
}

// TestCleanupRetiresKeysOlderThanKeyMaxAge proves that cleanup removes non-active keys older than key_max_age
// even when an earlier release stored them with a longer expiry, and keeps the active and younger keys.
func TestCleanupRetiresKeysOlderThanKeyMaxAge(t *testing.T) {
	manager := newKeyLifetimeTestManager(t, 0)
	now := time.Now()
	legacy := KeyMetadata{ID: "legacy", PEM: "unused", CreatedAt: now.Add(-8 * 24 * time.Hour), ExpiresAt: now.Add(300 * 24 * time.Hour)}
	recent := KeyMetadata{ID: "recent", PEM: "unused", CreatedAt: now.Add(-24 * time.Hour), ExpiresAt: now.Add(6 * 24 * time.Hour)}

	for _, meta := range []KeyMetadata{legacy, recent} {
		raw, err := json.Marshal(meta)
		if err != nil {
			t.Fatalf("encode %s: %v", meta.ID, err)
		}

		if err = manager.deps.Redis.GetWriteHandle().HSet(
			t.Context(), manager.redisPrefix()+RedisKeyOIDCKeys, meta.ID, string(raw),
		).Err(); err != nil {
			t.Fatalf("seed %s: %v", meta.ID, err)
		}
	}

	activeKID, err := manager.GenerateNewKey(t.Context())
	if err != nil {
		t.Fatalf("generate active key: %v", err)
	}

	manager.CleanupOldKeys(t.Context())

	remaining, err := manager.deps.Redis.GetReadHandle().HKeys(t.Context(), manager.redisPrefix()+RedisKeyOIDCKeys).Result()
	if err != nil {
		t.Fatalf("list keys: %v", err)
	}

	if !slices.Contains(remaining, activeKID) || !slices.Contains(remaining, recent.ID) || slices.Contains(remaining, legacy.ID) {
		t.Fatalf("remaining keys = %v, want active %s and %s without %s", remaining, activeKID, recent.ID, legacy.ID)
	}
}

// TestRotationIntervalKeepsActiveKeyBeforeKeyMaxAge proves that rotation never lets the active key reach
// key_max_age, while a consistent configuration keeps its configured interval.
func TestRotationIntervalKeepsActiveKeyBeforeKeyMaxAge(t *testing.T) {
	for _, tc := range []struct {
		name      string
		interval  time.Duration
		keyMaxAge time.Duration
		want      time.Duration
	}{
		{name: "defaults", want: 24 * time.Hour},
		{name: "consistent", interval: 12 * time.Hour, keyMaxAge: 48 * time.Hour, want: 12 * time.Hour},
		{name: "interval beyond default max age", interval: 30 * 24 * time.Hour, want: 84 * time.Hour},
		{name: "interval equals max age", interval: 48 * time.Hour, keyMaxAge: 48 * time.Hour, want: 24 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager := NewManager(&deps.Deps{Cfg: &config.FileSettings{
				IDP: &config.IDPSection{OIDC: config.OIDCConfig{KeyRotationInterval: tc.interval, KeyMaxAge: tc.keyMaxAge}},
			}})

			if got := manager.rotationInterval(); got != tc.want {
				t.Fatalf("rotation interval = %s, want %s", got, tc.want)
			}
		})
	}
}
