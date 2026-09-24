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

package rediscli

import (
	"context"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRWPSlidingWindowUsesOnlyFullHash(t *testing.T) {
	checkScript := LuaScripts["RWPSlidingWindowCheck"]
	commitScript := LuaScripts["RWPSlidingWindowCommit"]

	for name, script := range map[string]string{"check": checkScript, "commit": commitScript} {
		if strings.Contains(script, "ARGV[5]") || strings.Contains(script, "legacy") {
			t.Fatalf("RWP %s script still accepts a short hash candidate", name)
		}
	}

	server := miniredis.RunT(t)

	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	closeRedisTestClient(t, client)

	const (
		key       = "rwp:{contract}:account"
		fullHash  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		shortHash = "01234567"
		now       = int64(1000)
	)

	ctx := context.Background()
	if err := client.ZAdd(ctx, key, redis.Z{Score: float64(now - 1), Member: shortHash}).Err(); err != nil {
		t.Fatalf("seed short RWP member: %v", err)
	}

	result, err := client.Eval(ctx, checkScript, []string{key}, fullHash, now, 300, 4).Int64()
	if err != nil {
		t.Fatalf("execute RWP check script: %v", err)
	}

	if result != 0 {
		t.Fatalf("short RWP member result = %d, want no repeat", result)
	}

	for attempt, want := range []int64{0, 1} {
		repeated, err := client.Eval(ctx, commitScript, []string{key}, fullHash, now, 300, 4).Int64()
		if err != nil {
			t.Fatalf("execute RWP commit script: %v", err)
		}

		if repeated != want {
			t.Fatalf("RWP commit %d repeated = %d, want %d", attempt, repeated, want)
		}
	}

	score, err := client.ZScore(ctx, key, fullHash).Result()
	if err != nil || int64(score) != now {
		t.Fatalf("full RWP member score = %v err=%v, want %d", score, err, now)
	}
}

func TestPasswordHistoryCommitStoresFullHashOnly(t *testing.T) {
	script := LuaScripts["AddToSetAndExpireLimit"]
	if strings.Contains(script, "ARGV[4]") || strings.Contains(script, "SREM") {
		t.Fatal("password-history commit script still removes a short hash candidate")
	}

	server := miniredis.RunT(t)

	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	closeRedisTestClient(t, client)

	const (
		key       = "password-history:{contract}:account"
		fullHash  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		shortHash = "01234567"
	)

	ctx := context.Background()
	if err := client.SAdd(ctx, key, shortHash).Err(); err != nil {
		t.Fatalf("seed stray short password-history member: %v", err)
	}

	if _, err := client.Eval(ctx, script, []string{key}, fullHash, 300, 4).Result(); err != nil {
		t.Fatalf("execute password-history commit script: %v", err)
	}

	isMember, err := client.SIsMember(ctx, key, fullHash).Result()
	if err != nil || !isMember {
		t.Fatalf("full password-history member present = %t err=%v, want true", isMember, err)
	}

	if ttl := server.TTL(key); ttl <= 0 {
		t.Fatalf("password-history TTL = %v, want positive", ttl)
	}
}

// closeRedisTestClient registers checked cleanup for a hermetic Redis client.
func closeRedisTestClient(t *testing.T, client *redis.Client) {
	t.Helper()
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close Redis test client: %v", err)
		}
	})
}
