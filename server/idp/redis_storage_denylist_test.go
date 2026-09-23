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

package idp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/redis/go-redis/v9"
)

const denylistTestToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"

// newDenylistTestStorage returns token storage backed by a real RESP server.
func newDenylistTestStorage(t *testing.T) (*RedisTokenStorage, *miniredis.Miniredis) {
	t.Helper()

	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})

	t.Cleanup(func() {
		_ = handle.Close()
	})

	return NewRedisTokenStorage(rediscli.NewTestClient(handle), "test:"), server
}

// TestDenyJWTAccessTokenWritesDigestAndLegacyKeys pins the migration write set: the digest key never embeds
// the token, and for one release the legacy key is written alongside with the same TTL.
func TestDenyJWTAccessTokenWritesDigestAndLegacyKeys(t *testing.T) {
	storage, server := newDenylistTestStorage(t)

	if err := storage.DenyJWTAccessToken(context.Background(), denylistTestToken, time.Hour); err != nil {
		t.Fatalf("DenyJWTAccessToken() error = %v", err)
	}

	digestKey := storage.deniedAccessTokenKey(denylistTestToken)
	legacyKey := "test:oidc:denied_access_token:" + denylistTestToken

	if strings.Contains(digestKey, denylistTestToken) {
		t.Fatalf("digest denylist key %q contains the raw token", digestKey)
	}

	if !strings.HasPrefix(digestKey, "test:oidc:denied_access_token:"+oidcDeniedAccessTokenDigestMarker) {
		t.Fatalf("digest denylist key %q does not use the digest namespace", digestKey)
	}

	keys := server.Keys()
	if len(keys) != 2 {
		t.Fatalf("denylist keys = %v, want digest and legacy key", keys)
	}

	for _, key := range []string{digestKey, legacyKey} {
		if ttl := server.TTL(key); ttl != time.Hour {
			t.Fatalf("TTL(%q) = %s, want %s", key, ttl, time.Hour)
		}
	}
}

// TestDenyJWTAccessTokenSurvivesRollback pins that an instance rolled back to the legacy-only reader, which
// performs a single GET on the raw-token key, still sees a revocation written by this release.
func TestDenyJWTAccessTokenSurvivesRollback(t *testing.T) {
	storage, server := newDenylistTestStorage(t)

	if err := storage.DenyJWTAccessToken(context.Background(), denylistTestToken, time.Hour); err != nil {
		t.Fatalf("DenyJWTAccessToken() error = %v", err)
	}

	legacyReader := redis.NewClient(&redis.Options{Addr: server.Addr()})

	t.Cleanup(func() {
		_ = legacyReader.Close()
	})

	value, err := legacyReader.Get(context.Background(), "test:oidc:denied_access_token:"+denylistTestToken).Result()
	if err != nil || value != "1" {
		t.Fatalf("legacy reader GET = (%q, %v), want revocation marker", value, err)
	}
}

// TestIsJWTAccessTokenDeniedReadsDigestAndLegacyKeys pins that the digest migration never revives a token
// that was revoked under the legacy raw-token key.
func TestIsJWTAccessTokenDeniedReadsDigestAndLegacyKeys(t *testing.T) {
	tests := []struct {
		seed func(t *testing.T, storage *RedisTokenStorage, server *miniredis.Miniredis)
		name string
		want bool
	}{
		{
			name: "digest entry",
			seed: func(t *testing.T, storage *RedisTokenStorage, _ *miniredis.Miniredis) {
				t.Helper()

				if err := storage.DenyJWTAccessToken(context.Background(), denylistTestToken, time.Hour); err != nil {
					t.Fatalf("DenyJWTAccessToken() error = %v", err)
				}
			},
			want: true,
		},
		{
			name: "legacy raw-token entry",
			seed: func(t *testing.T, _ *RedisTokenStorage, server *miniredis.Miniredis) {
				t.Helper()

				if err := server.Set("test:oidc:denied_access_token:"+denylistTestToken, "1"); err != nil {
					t.Fatalf("seed legacy entry: %v", err)
				}
			},
			want: true,
		},
		{
			name: "no entry",
			seed: func(*testing.T, *RedisTokenStorage, *miniredis.Miniredis) {},
			want: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			storage, server := newDenylistTestStorage(t)
			test.seed(t, storage, server)

			denied, err := storage.IsJWTAccessTokenDenied(context.Background(), denylistTestToken)
			if err != nil {
				t.Fatalf("IsJWTAccessTokenDenied() error = %v", err)
			}

			if denied != test.want {
				t.Fatalf("IsJWTAccessTokenDenied() = %t, want %t", denied, test.want)
			}
		})
	}
}

// TestIsJWTAccessTokenDeniedReportsBackendFailure pins that an unreachable denylist is never read as absence.
func TestIsJWTAccessTokenDeniedReportsBackendFailure(t *testing.T) {
	storage, server := newDenylistTestStorage(t)
	server.Close()

	denied, err := storage.IsJWTAccessTokenDenied(context.Background(), denylistTestToken)
	if err == nil {
		t.Fatal("IsJWTAccessTokenDenied() error = nil, want backend failure")
	}

	if denied {
		t.Fatal("IsJWTAccessTokenDenied() must not report a verdict on backend failure")
	}
}

// TestDeniedAccessTokenKeyIsDeterministic pins that every instance derives the same key without shared secrets.
func TestDeniedAccessTokenKeyIsDeterministic(t *testing.T) {
	storage, _ := newDenylistTestStorage(t)
	other, _ := newDenylistTestStorage(t)

	if storage.deniedAccessTokenKey(denylistTestToken) != other.deniedAccessTokenKey(denylistTestToken) {
		t.Fatal("denylist digest keys differ between storage instances")
	}

	if storage.deniedAccessTokenKey(denylistTestToken) == storage.deniedAccessTokenKey(denylistTestToken+"x") {
		t.Fatal("different tokens must not share one denylist key")
	}
}
