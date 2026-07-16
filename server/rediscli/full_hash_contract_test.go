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

func TestRWPSlidingWindowReadsLegacyHashAndCommitsFullHash(t *testing.T) {
	checkScript := LuaScripts["RWPSlidingWindowCheck"]
	commitScript := LuaScripts["RWPSlidingWindowCommit"]

	if !strings.Contains(checkScript, "ARGV[5]") {
		t.Fatal("RWP check script has no bounded exact legacy-hash candidate")
	}

	if !strings.Contains(commitScript, "ARGV[5]") || !strings.Contains(commitScript, "ZREM") {
		t.Fatal("RWP commit script does not remove the exact legacy member before writing the full hash")
	}

	server := miniredis.RunT(t)

	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	closeRedisTestClient(t, client)

	const (
		key      = "rwp:{contract}:account"
		fullHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		legacy   = "01234567"
		now      = int64(1000)
	)

	ctx := context.Background()
	if err := client.ZAdd(ctx, key, redis.Z{Score: float64(now - 1), Member: legacy}).Err(); err != nil {
		t.Fatalf("seed legacy RWP member: %v", err)
	}

	result, err := client.Eval(ctx, checkScript, []string{key}, fullHash, now, 300, 4, legacy).Int64()
	if err != nil {
		t.Fatalf("execute RWP check script: %v", err)
	}

	if result != 1 {
		t.Fatalf("legacy RWP membership result = %d, want repeat", result)
	}

	if _, err := client.Eval(ctx, commitScript, []string{key}, fullHash, now, 300, 4, legacy).Result(); err != nil {
		t.Fatalf("execute RWP commit script: %v", err)
	}

	members, err := client.ZRange(ctx, key, 0, -1).Result()
	if err != nil {
		t.Fatalf("read canonical RWP members: %v", err)
	}

	if len(members) != 1 || members[0] != fullHash {
		t.Fatalf("canonical RWP members = %#v, want one full hash", members)
	}
}

func TestPasswordHistoryCommitCanonicalizesLegacyWithoutCardinalityGrowth(t *testing.T) {
	server := miniredis.RunT(t)

	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	closeRedisTestClient(t, client)

	const (
		key      = "password-history:{contract}:account"
		fullHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		legacy   = "01234567"
	)

	ctx := context.Background()
	if err := client.SAdd(ctx, key, legacy).Err(); err != nil {
		t.Fatalf("seed legacy password-history member: %v", err)
	}

	if _, err := client.Eval(ctx, LuaScripts["AddToSetAndExpireLimit"], []string{key}, fullHash, 300, 4, legacy).Result(); err != nil {
		t.Fatalf("execute password-history commit script: %v", err)
	}

	members, err := client.SMembers(ctx, key).Result()
	if err != nil {
		t.Fatalf("read canonical password-history members: %v", err)
	}

	if len(members) != 1 || members[0] != fullHash {
		t.Fatalf("canonical password-history members = %#v, want one full hash", members)
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
