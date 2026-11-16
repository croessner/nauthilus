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

package core

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/testing/redislatency"
	"github.com/croessner/nauthilus/v4/server/testing/redisroundtrip"
	"github.com/redis/go-redis/v9"
)

const (
	// accountHistoryMeasureEnv enables the latency measurement; it is skipped in normal test runs.
	accountHistoryMeasureEnv = "NAUTHILUS_ACCOUNT_HISTORY_MEASURE"
	// accountHistoryMeasureAddrEnv optionally points the measurement at an isolated real Redis instance.
	accountHistoryMeasureAddrEnv = "NAUTHILUS_ACCOUNT_HISTORY_MEASURE_ADDR"
	// accountHistoryMeasureDelayEnv optionally sets the one-way delay in microseconds; "direct" bypasses the proxy.
	accountHistoryMeasureDelayEnv = "NAUTHILUS_ACCOUNT_HISTORY_MEASURE_DELAY_US"
	// accountHistoryMeasureClusterEnv optionally lists comma-separated seed nodes of an isolated Redis Cluster.
	accountHistoryMeasureClusterEnv = "NAUTHILUS_ACCOUNT_HISTORY_MEASURE_CLUSTER"
	// accountHistoryMeasureDirect connects to the upstream without the latency proxy.
	accountHistoryMeasureDirect = "direct"
)

// accountHistoryMeasurement is one measured unpaged account listing.
type accountHistoryMeasurement struct {
	elapsed    time.Duration
	roundTrips int
	commands   int
	allocBytes uint64
	accounts   int
	ips        int
}

// TestMeasureUnpagedAccountListingWithLatency measures the unpaged account listing against synthetic data
// behind a simulated network delay. It runs only when NAUTHILUS_ACCOUNT_HISTORY_MEASURE=1 is set.
func TestMeasureUnpagedAccountListingWithLatency(t *testing.T) {
	if os.Getenv(accountHistoryMeasureEnv) != "1" {
		t.Skipf("set %s=1 to run the latency measurement", accountHistoryMeasureEnv)
	}

	cfg := setupBruteForceListTestConfig(t, "b_1m_ipv6_128_mail", time.Hour)
	prefix := cfg.GetServer().GetRedis().GetPrefix()
	upstream := os.Getenv(accountHistoryMeasureAddrEnv)

	if upstream == "" {
		upstream = miniredis.RunT(t).Addr()
	}

	seeder := redis.NewClient(&redis.Options{Addr: upstream, Protocol: 2})

	t.Cleanup(func() { _ = seeder.Close() })

	seedMeasurementData(t, seeder, prefix)

	addr, delayLabel := measurementClientAddr(t, upstream)
	client := redis.NewClient(&redis.Options{Addr: addr, Protocol: 2})

	t.Cleanup(func() { _ = client.Close() })

	recorder := redisroundtrip.Attach(client)
	deps := restAdminDeps{
		Cfg:    cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(client),
	}

	result := measureUnpagedAccountListing(t, deps, recorder)

	t.Logf("upstream=%s one_way_delay=%s accounts=%d ips=%d elapsed=%s round_trips=%d commands=%d alloc_bytes=%d",
		upstreamKind(), delayLabel, result.accounts, result.ips, result.elapsed, result.roundTrips, result.commands, result.allocBytes)
}

// TestMeasureUnpagedAccountListingOnCluster measures the same listing against an isolated Redis Cluster.
// It runs only when NAUTHILUS_ACCOUNT_HISTORY_MEASURE_CLUSTER lists the seed nodes; no latency is added.
func TestMeasureUnpagedAccountListingOnCluster(t *testing.T) {
	seeds := os.Getenv(accountHistoryMeasureClusterEnv)
	if seeds == "" {
		t.Skipf("set %s to run the cluster measurement", accountHistoryMeasureClusterEnv)
	}

	cfg := setupBruteForceListTestConfig(t, "b_1m_ipv6_128_mail", time.Hour)
	prefix := cfg.GetServer().GetRedis().GetPrefix()
	cluster := redis.NewClusterClient(&redis.ClusterOptions{Addrs: strings.Split(seeds, ","), Protocol: 2})

	t.Cleanup(func() { _ = cluster.Close() })

	seedMeasurementData(t, cluster, prefix)

	recorder := redisroundtrip.Attach(cluster)
	deps := restAdminDeps{
		Cfg:    cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClientForHandle(cluster),
	}

	result := measureUnpagedAccountListing(t, deps, recorder)

	t.Logf("upstream=redis-cluster accounts=%d ips=%d elapsed=%s pipeline_executions=%d commands=%d alloc_bytes=%d",
		result.accounts, result.ips, result.elapsed, result.roundTrips, result.commands, result.allocBytes)
}

// measurementClientAddr returns the address to dial, starting a latency proxy unless direct mode is requested.
func measurementClientAddr(t *testing.T, upstream string) (string, string) {
	t.Helper()

	raw := os.Getenv(accountHistoryMeasureDelayEnv)
	if raw == accountHistoryMeasureDirect {
		return upstream, accountHistoryMeasureDirect
	}

	delay := 500 * time.Microsecond

	if raw != "" {
		micros, err := strconv.Atoi(raw)
		if err != nil {
			t.Fatalf("parse %s: %v", accountHistoryMeasureDelayEnv, err)
		}

		delay = time.Duration(micros) * time.Microsecond
	}

	proxy, err := redislatency.Start(upstream, delay)
	if err != nil {
		t.Fatalf("start latency proxy: %v", err)
	}

	t.Cleanup(func() { _ = proxy.Close() })

	return proxy.Addr(), delay.String()
}

// measureUnpagedAccountListing runs one unpaged account listing and records time, trips, and allocations.
func measureUnpagedAccountListing(t *testing.T, deps restAdminDeps, recorder *redisroundtrip.Recorder) accountHistoryMeasurement {
	t.Helper()

	recorder.Reset()
	runtime.GC()

	var before, after runtime.MemStats

	runtime.ReadMemStats(&before)

	start := time.Now()
	accounts, err := listBlockedAccounts(t.Context(), deps, nil, bruteForceListPageQuery{}, "measure")
	elapsed := time.Since(start)

	runtime.ReadMemStats(&after)

	if err != nil {
		t.Fatalf("list accounts: %v", err)
	}

	result := accountHistoryMeasurement{
		elapsed:    elapsed,
		roundTrips: recorder.Count(),
		allocBytes: after.TotalAlloc - before.TotalAlloc,
		accounts:   len(accounts.Accounts),
	}

	for _, trip := range recorder.RoundTrips() {
		result.commands += len(trip)
	}

	for _, ips := range accounts.Accounts {
		result.ips += len(ips)
	}

	return result
}

// flushMeasurementDatabase empties the isolated measurement instance or every master of the cluster.
func flushMeasurementDatabase(ctx context.Context, client redis.UniversalClient) error {
	if cluster, ok := client.(*redis.ClusterClient); ok {
		return cluster.ForEachMaster(ctx, func(ctx context.Context, node *redis.Client) error {
			return node.FlushDB(ctx).Err()
		})
	}

	return client.FlushDB(ctx).Err()
}

// upstreamKind names the measured Redis implementation for the log line.
func upstreamKind() string {
	if os.Getenv(accountHistoryMeasureAddrEnv) != "" {
		return "redis-server"
	}

	return "miniredis"
}

// seedMeasurementData writes 12,000 affected accounts; 6% have histories and three have 5,000 IPs each.
func seedMeasurementData(t *testing.T, client redis.UniversalClient, prefix string) {
	t.Helper()

	ctx := t.Context()
	if err := flushMeasurementDatabase(ctx, client); err != nil {
		t.Fatalf("flush measurement database: %v", err)
	}

	pipe := client.Pipeline()

	for index := range 12000 {
		account := fmt.Sprintf("bench%d@example.test", index)
		pipe.SAdd(ctx, prefix+definitions.RedisAffectedAccountsKey, account)

		ips := 0

		switch {
		case index < 3:
			ips = 5000
		case index%17 == 0:
			ips = 4
		}

		for ipIndex := range ips {
			pipe.SAdd(ctx, prefix+definitions.RedisPWHistIPsKey+":"+account, fmt.Sprintf("2001:db8:%x::%x", index, ipIndex+1))
		}

		if pipe.Len() > 4096 {
			if _, err := pipe.Exec(ctx); err != nil {
				t.Fatalf("seed measurement data: %v", err)
			}
		}
	}

	if _, err := pipe.Exec(ctx); err != nil {
		t.Fatalf("seed measurement data: %v", err)
	}
}
