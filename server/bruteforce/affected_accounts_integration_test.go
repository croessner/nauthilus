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

package bruteforce

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/log"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/redis/go-redis/v9"
)

// affectedAccountsIntegrationEnv selects an isolated real Redis: "single:<addr>" or "cluster:<addr>,<addr>,...".
// The test flushes that instance; never point it at shared or production data.
const affectedAccountsIntegrationEnv = "NAUTHILUS_AFFECTED_ACCOUNTS_REDIS"

// integrationClient connects to the isolated Redis named by the environment and empties it.
func integrationClient(t *testing.T) redis.UniversalClient {
	t.Helper()

	target := os.Getenv(affectedAccountsIntegrationEnv)
	if target == "" {
		t.Skipf("set %s to run against an isolated real Redis", affectedAccountsIntegrationEnv)
	}

	mode, addrs, _ := strings.Cut(target, ":")

	var client redis.UniversalClient

	switch mode {
	case "cluster":
		cluster := redis.NewClusterClient(&redis.ClusterOptions{Addrs: strings.Split(addrs, ",")})
		if err := cluster.ForEachMaster(t.Context(), func(ctx context.Context, node *redis.Client) error {
			return node.FlushDB(ctx).Err()
		}); err != nil {
			t.Fatalf("flush cluster: %v", err)
		}

		client = cluster
	default:
		single := redis.NewClient(&redis.Options{Addr: addrs})
		if err := single.FlushDB(t.Context()).Err(); err != nil {
			t.Fatalf("flush redis: %v", err)
		}

		client = single
	}

	t.Cleanup(func() { _ = client.Close() })

	return client
}

// TestAffectedAccountLifecycleAgainstRealRedis runs re-arm and bounded cleanup of 12,000 legacy members with real Lua.
func TestAffectedAccountLifecycleAgainstRealRedis(t *testing.T) {
	handle := integrationClient(t)
	cfg := passwordHistoryCommandConfig(0)
	cfg.(*config.FileSettings).Server.Redis.NegCacheTTL = time.Hour
	client := rediscli.NewTestClientForHandle(handle)
	ctx := t.Context()

	keys, err := NewAffectedAccountKeys(cfg.GetServer().GetRedis().GetPrefix())
	if err != nil {
		t.Fatal(err)
	}

	const legacy = 12000

	seedIntegrationLegacyMembers(t, handle, cfg, keys, legacy)

	now := time.Now().Truncate(time.Second)
	maintainer := NewAffectedAccountsMaintainer(client, log.GetLogger())
	maintainer.now = func() time.Time { return now }

	ticks := 0
	tick := func() {
		ticks++

		handle.Del(ctx, keys.Lease)

		if err := maintainer.RunOnce(ctx, cfg); err != nil {
			t.Fatalf("tick %d: %v", ticks, err)
		}
	}

	started := time.Now()

	for handle.HGet(ctx, keys.State, stateFieldRearmDone).Val() != "1" {
		tick()
	}

	rearmTicks := ticks

	now = now.Add(AffectedAccountRetention(cfg) + time.Minute)

	for handle.SCard(ctx, keys.Set).Val() > int64(legacy/17+1) && ticks < 500 {
		tick()
	}

	remaining := handle.SCard(ctx, keys.Set).Val()
	if remaining != int64(legacy/17+1) {
		t.Fatalf("set has %d members after %d ticks, want %d with history", remaining, ticks, legacy/17+1)
	}

	if index := handle.ZCard(ctx, keys.Index).Val(); index != remaining {
		t.Fatalf("index has %d members, set %d", index, remaining)
	}

	t.Logf("redis=%s legacy=%d rearm_ticks=%d cleanup_ticks=%d elapsed=%s remaining=%d",
		strings.SplitN(os.Getenv(affectedAccountsIntegrationEnv), ":", 2)[0], legacy, rearmTicks, ticks-rearmTicks, time.Since(started), remaining)
}

// seedIntegrationLegacyMembers writes legacy members without deadlines; every 17th gets a long IP history.
func seedIntegrationLegacyMembers(t *testing.T, handle redis.UniversalClient, cfg config.File, keys AffectedAccountKeys, count int) {
	t.Helper()

	ctx := t.Context()
	pipe := handle.Pipeline()

	for index := range count {
		account := fmt.Sprintf("bench%d@example.test", index)
		pipe.SAdd(ctx, keys.Set, account)
		pipe.ZAdd(ctx, keys.Index, redis.Z{Score: float64(index), Member: account})

		if index%17 == 0 {
			pipe.SAdd(ctx, GetPWHistIPsRedisKey(account, cfg), "192.0.2.9")
			pipe.Expire(ctx, GetPWHistIPsRedisKey(account, cfg), 72*time.Hour)
		}
	}

	if _, err := pipe.Exec(ctx); err != nil {
		t.Fatalf("seed: %v", err)
	}
}
