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
	"fmt"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/definitions"
	bf "github.com/croessner/nauthilus/v4/server/model/bruteforce"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/testing/rediscluster"
	"github.com/croessner/nauthilus/v4/server/testing/redisroundtrip"
	"github.com/redis/go-redis/v9"
)

// accountHistoryFixture wires the management list dependencies to miniredis with a round-trip recorder.
type accountHistoryFixture struct {
	server   *miniredis.Miniredis
	recorder *redisroundtrip.Recorder
	deps     restAdminDeps
	prefix   string
}

// newAccountHistoryFixture starts an isolated miniredis instance for account-history reads.
func newAccountHistoryFixture(t *testing.T) *accountHistoryFixture {
	t.Helper()

	cfg := setupBruteForceListTestConfig(t, "b_1m_ipv6_128_mail", time.Hour)
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr(), Protocol: 2})

	t.Cleanup(func() { _ = client.Close() })

	return &accountHistoryFixture{
		server:   server,
		recorder: redisroundtrip.Attach(client),
		deps: restAdminDeps{
			Cfg:    cfg,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			Redis:  rediscli.NewTestClient(client),
		},
		prefix: cfg.GetServer().GetRedis().GetPrefix(),
	}
}

// seedAccounts stores affected accounts and gives every historyEvery-th account an IP history.
func (f *accountHistoryFixture) seedAccounts(t *testing.T, count int, historyEvery int, ipsPerHistory int) []string {
	t.Helper()

	accounts := make([]string, 0, count)

	for index := range count {
		account := fmt.Sprintf("bench%d@example.test", index)
		accounts = append(accounts, account)

		if _, err := f.server.SetAdd(f.prefix+definitions.RedisAffectedAccountsKey, account); err != nil {
			t.Fatalf("seed affected account: %v", err)
		}

		if historyEvery <= 0 || index%historyEvery != 0 {
			continue
		}

		for ipIndex := range ipsPerHistory {
			ip := fmt.Sprintf("2001:db8:%x::%x", index, ipIndex+1)
			if _, err := f.server.SetAdd(f.prefix+definitions.RedisPWHistIPsKey+":"+account, ip); err != nil {
				t.Fatalf("seed account history: %v", err)
			}
		}
	}

	return accounts
}

// historyRoundTrips counts recorded round trips that read password-history IP sets.
func (f *accountHistoryFixture) historyRoundTrips() (int, int) {
	trips := 0
	commands := 0

	for _, trip := range f.recorder.RoundTrips() {
		if len(trip) == 0 || trip[0] != "smembers" {
			continue
		}

		trips++
		commands += len(trip)
	}

	return trips, commands
}

// TestPopulateBlockedAccountIPHistoryUsesBoundedPipelines proves that history reads are pipelined in
// bounded batches instead of one serial round trip per account.
func TestPopulateBlockedAccountIPHistoryUsesBoundedPipelines(t *testing.T) {
	const wantBatch = bruteForceAccountHistoryBatchSize

	for _, count := range []int{0, 1, wantBatch - 1, wantBatch, wantBatch + 1, 3*wantBatch + 7} {
		t.Run(fmt.Sprintf("accounts_%d", count), func(t *testing.T) {
			fixture := newAccountHistoryFixture(t)
			accounts := fixture.seedAccounts(t, count, 3, 2)
			result := &bf.BlockedAccounts{Accounts: make(map[string][]string)}

			fixture.recorder.Reset()

			if err := populateBlockedAccountIPHistory(t.Context(), fixture.deps, accounts, result, "guid"); err != nil {
				t.Fatalf("populate history: %v", err)
			}

			trips, commands := fixture.historyRoundTrips()
			wantTrips := (count + wantBatch - 1) / wantBatch

			if trips != wantTrips || commands != count {
				t.Fatalf("history reads used %d round trips with %d commands, want %d round trips with %d commands",
					trips, commands, wantTrips, count)
			}

			if len(result.Accounts) != count {
				t.Fatalf("result contains %d accounts, want %d", len(result.Accounts), count)
			}
		})
	}
}

// serialAccountHistoryReference reproduces the former one-SMEMBERS-per-account listing as the oracle.
func serialAccountHistoryReference(t *testing.T, deps restAdminDeps, prefix string, accounts []string) map[string][]string {
	t.Helper()

	reference := make(map[string][]string, len(accounts))

	for _, account := range accounts {
		ips, err := deps.Redis.GetReadHandle().SMembers(t.Context(), prefix+definitions.RedisPWHistIPsKey+":"+account).Result()
		if err != nil {
			t.Fatalf("reference read: %v", err)
		}

		reference[account] = ips
	}

	return reference
}

// assertSameAccountHistory compares two account listings independent of set member order.
func assertSameAccountHistory(t *testing.T, got map[string][]string, want map[string][]string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("listing has %d accounts, want %d", len(got), len(want))
	}

	for account, wantIPs := range want {
		gotIPs, ok := got[account]
		if !ok {
			t.Fatalf("account %q missing from listing", account)
		}

		if gotIPs == nil {
			t.Fatalf("account %q has a nil IP list, want an empty or complete list", account)
		}

		if !slices.Equal(slices.Sorted(slices.Values(gotIPs)), slices.Sorted(slices.Values(wantIPs))) {
			t.Fatalf("account %q has %d IPs, want %d", account, len(gotIPs), len(wantIPs))
		}
	}
}

// TestUnpagedAccountListingMatchesSerialReference covers 12,000 mostly history-less accounts and a few
// accounts with large histories; the pipelined listing must equal the former serial result.
func TestUnpagedAccountListingMatchesSerialReference(t *testing.T) {
	fixture := newAccountHistoryFixture(t)
	accounts := fixture.seedAccounts(t, 12000, 17, 4)

	for index := range 3 {
		for ipIndex := range 5000 {
			key := fixture.prefix + definitions.RedisPWHistIPsKey + ":" + accounts[index+1]
			if _, err := fixture.server.SetAdd(key, fmt.Sprintf("198.51.%d.%d", ipIndex/256, ipIndex%256)); err != nil {
				t.Fatalf("seed large history: %v", err)
			}
		}
	}

	reference := serialAccountHistoryReference(t, fixture.deps, fixture.prefix, accounts)

	fixture.recorder.Reset()

	listing, err := listBlockedAccounts(t.Context(), fixture.deps, nil, bruteForceListPageQuery{}, "guid")
	if err != nil {
		t.Fatalf("list accounts: %v", err)
	}

	if listing.Error != nil || listing.Page != nil {
		t.Fatalf("listing error = %v page = %v, want neither", listing.Error, listing.Page)
	}

	assertSameAccountHistory(t, listing.Accounts, reference)

	// One SMEMBERS for the affected-account set plus one pipeline per history batch.
	trips, commands := fixture.historyRoundTrips()
	if want := 1 + (12000+bruteForceAccountHistoryBatchSize-1)/bruteForceAccountHistoryBatchSize; trips != want || commands != 12001 {
		t.Fatalf("listing used %d SMEMBERS round trips with %d commands, want %d with 12001", trips, commands, want)
	}
}

// TestPagedAndFilteredAccountListingKeepsPageContract covers index pages, filters, has_more and next_offset.
func TestPagedAndFilteredAccountListingKeepsPageContract(t *testing.T) {
	fixture := newAccountHistoryFixture(t)
	accounts := fixture.seedAccounts(t, 600, 2, 1)
	indexKey := rediscli.GetAffectedAccountsIndexKey(fixture.prefix)

	for index, account := range accounts {
		if _, err := fixture.server.ZAdd(indexKey, float64(1000+index), account); err != nil {
			t.Fatalf("seed index: %v", err)
		}
	}

	reference := serialAccountHistoryReference(t, fixture.deps, fixture.prefix, accounts)

	cases := []struct {
		name        string
		filter      *bf.FilterCmd
		page        bruteForceListPageQuery
		wantFirst   int
		wantCount   int
		wantHasMore bool
	}{
		{name: "first_page", page: bruteForceListPageQuery{limit: 300, enabled: true}, wantFirst: 0, wantCount: 300, wantHasMore: true},
		{name: "last_full_page", page: bruteForceListPageQuery{limit: 300, offset: 300, enabled: true}, wantFirst: 300, wantCount: 300},
		{name: "past_end", page: bruteForceListPageQuery{limit: 10, offset: 600, enabled: true}, wantCount: 0},
		{
			name:        "filtered_page",
			filter:      &bf.FilterCmd{Accounts: []string{accounts[5], "unknown@example.test", accounts[7], accounts[9]}},
			page:        bruteForceListPageQuery{limit: 2, enabled: true},
			wantFirst:   -1,
			wantCount:   2,
			wantHasMore: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			listing, err := listBlockedAccounts(t.Context(), fixture.deps, tc.filter, tc.page, "guid")
			if err != nil {
				t.Fatalf("list accounts: %v", err)
			}

			want := make(map[string][]string, tc.wantCount)

			for index := range tc.wantCount {
				// Filtered pages keep request order and drop unknown accounts: accounts[5], then accounts[7].
				account := ""
				if tc.wantFirst < 0 {
					account = tc.filter.Accounts[[]int{0, 2}[index]]
				} else {
					account = accounts[tc.wantFirst+index]
				}

				want[account] = reference[account]
			}

			assertSameAccountHistory(t, listing.Accounts, want)

			if listing.Page == nil || listing.Page.HasMore != tc.wantHasMore || listing.Page.NextOffset != int(tc.page.offset+tc.page.limit) {
				t.Fatalf("page = %+v, want has_more=%t next_offset=%d", listing.Page, tc.wantHasMore, tc.page.offset+tc.page.limit)
			}
		})
	}
}

// TestAccountListingReportsFailedHistoryReadAsIncomplete keeps the error contract of the serial listing.
func TestAccountListingReportsFailedHistoryReadAsIncomplete(t *testing.T) {
	fixture := newAccountHistoryFixture(t)
	accounts := fixture.seedAccounts(t, 3*bruteForceAccountHistoryBatchSize, 0, 0)
	indexKey := rediscli.GetAffectedAccountsIndexKey(fixture.prefix)

	for index, account := range accounts {
		if _, err := fixture.server.ZAdd(indexKey, float64(index), account); err != nil {
			t.Fatalf("seed index: %v", err)
		}
	}

	failedIndex := bruteForceAccountHistoryBatchSize + 3
	if err := fixture.server.Set(fixture.prefix+definitions.RedisPWHistIPsKey+":"+accounts[failedIndex], "wrong type"); err != nil {
		t.Fatalf("seed wrong type: %v", err)
	}

	fixture.recorder.Reset()

	page := bruteForceListPageQuery{limit: int64(len(accounts)), enabled: true}

	listing, err := listBlockedAccounts(t.Context(), fixture.deps, nil, page, "guid")
	if err == nil || listing.Error == nil {
		t.Fatalf("error = %v listing error = %v, want both set", err, listing.Error)
	}

	if listing.Page != nil {
		t.Fatalf("page = %+v, want no page metadata for an incomplete listing", listing.Page)
	}

	if len(listing.Accounts) != failedIndex {
		t.Fatalf("listing kept %d accounts, want the %d read before the failure", len(listing.Accounts), failedIndex)
	}

	if trips, _ := fixture.historyRoundTrips(); trips != 2 {
		t.Fatalf("history round trips = %d, want 2 (no batch after the failure)", trips)
	}
}

// TestAccountListingReadsHistoriesAcrossClusterSlots lists accounts whose history keys live on two nodes.
func TestAccountListingReadsHistoriesAcrossClusterSlots(t *testing.T) {
	cfg := setupBruteForceListTestConfig(t, "b_1m_ipv6_128_mail", time.Hour)
	prefix := cfg.GetServer().GetRedis().GetPrefix()
	nodes := rediscluster.NewTwoNode(t)
	deps := restAdminDeps{
		Cfg:    cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClientForHandle(nodes.Cluster),
	}

	setKey := prefix + definitions.RedisAffectedAccountsKey
	want := make(map[string][]string)
	onHigh := 0

	for index := range 2*bruteForceAccountHistoryBatchSize + 1 {
		account := fmt.Sprintf("bench%d@example.test", index)
		historyKey := prefix + definitions.RedisPWHistIPsKey + ":" + account

		if _, err := nodes.Node(setKey).SetAdd(setKey, account); err != nil {
			t.Fatalf("seed set: %v", err)
		}

		want[account] = []string{}

		if rediscluster.IsHigh(historyKey) {
			onHigh++
		}

		if index%4 == 0 {
			ip := fmt.Sprintf("192.0.2.%d", index%250)
			if _, err := nodes.Node(historyKey).SetAdd(historyKey, ip); err != nil {
				t.Fatalf("seed history: %v", err)
			}

			want[account] = []string{ip}
		}
	}

	if onHigh == 0 || onHigh == len(want) {
		t.Fatalf("history keys do not span both nodes (%d of %d on high node)", onHigh, len(want))
	}

	listing, err := listBlockedAccounts(t.Context(), deps, nil, bruteForceListPageQuery{}, "guid")
	if err != nil {
		t.Fatalf("list accounts: %v", err)
	}

	assertSameAccountHistory(t, listing.Accounts, want)
}
