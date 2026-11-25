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

package supporthistory_test

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/supporthistory"
	"github.com/croessner/nauthilus/v4/server/supporthistory/historytest"
)

const (
	banNetwork = "198.51.100.0/24"
	banBucket  = "bucket-a"
	banWindow  = int64(100)
)

// banNow is the frozen query time of the ban tests.
var banNow = time.Now().UTC().Truncate(time.Second)

// int64p returns a pointer to v.
func int64p(v int64) *int64 { return &v }

// boolp returns a pointer to v.
func boolp(v bool) *bool { return &v }

// activation builds one ban activation of the shared bucket.
func activation(id string, at time.Time, current, previous int64) supporthistory.LifecycleRecord {
	expires := at.Add(time.Hour)

	return supporthistory.LifecycleRecord{At: at, ExpiresAt: &expires, EventID: id, Kind: "ban_activated",
		Network: banNetwork, Rule: "nat-network", StoredRule: "nat-network", BucketID: banBucket, PeriodSeconds: 3600,
		BanTimeSeconds: 3600, FailedRequests: 3, WindowIndex: int64p(banWindow), WindowCurrent: int64p(current),
		WindowPrevious: int64p(previous)}
}

// counted builds one counted increment.
func counted(id string, at time.Time, window, current int64, name string, crossed bool) supporthistory.CountedRecord {
	return supporthistory.CountedRecord{At: at, EventID: id, WindowIndex: int64p(window), WindowCurrent: int64p(current),
		ClaimedUsername: name, Account: name, Crossed: boolp(crossed), CountSource: "backend_failure", Protocol: "imap",
		ClientIP: "198.51.100.17"}
}

// banService builds a service over a ban store.
func banService(t *testing.T, store *historytest.BanStore) *supporthistory.Service {
	t.Helper()

	service, err := supporthistory.NewService(supporthistory.Options{Attempts: store, Bans: store,
		Now:      func() time.Time { return banNow },
		Prefixes: func() []supporthistory.Prefix { return []supporthistory.Prefix{{Family: 4, Bits: 24}} }})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	return service
}

// sharedIPStore returns the shared-IP scenario: three counted increments of different claimed names, an activation
// by a later request, one hit, a release, and a counter reset followed by a new increment that restarts at 1.
func sharedIPStore(activatedAt time.Time) *historytest.BanStore {
	store := &historytest.BanStore{Store: &historytest.Store{DeployName: "it"}, Contribs: map[string][]supporthistory.CountedRecord{}}
	store.Store.Lifecycle = []supporthistory.LifecycleRecord{
		activation("ban-1", activatedAt, 3, 0),
		{At: activatedAt.Add(4 * time.Second), EventID: "rel-1", Kind: "ban_released", Network: banNetwork, Rule: "nat-network",
			ReleaseSource: "admin_flush", OperatorClientID: "ops-client"},
		{At: activatedAt.Add(5 * time.Second), EventID: "reset-1", Kind: "counters_reset", Network: banNetwork,
			BucketID: banBucket, Rule: "nat-network"},
	}
	store.Contribs[banBucket] = []supporthistory.CountedRecord{
		counted("c1", activatedAt.Add(-3*time.Second), banWindow, 1, "alice@example.test", false),
		counted("c2", activatedAt.Add(-2*time.Second), banWindow, 2, "ceo@foreign.test", false),
		counted("c3", activatedAt.Add(-time.Second), banWindow, 3, "bob@example.test", true),
		counted("late", activatedAt.Add(6*time.Second), banWindow, 1, "late@example.test", false),
	}
	store.Volume = []historytest.VolumeRow{
		{CountedRecord: supporthistory.CountedRecord{At: activatedAt.Add(2 * time.Second), ClaimedUsername: "dave@example.test"},
			Network: banNetwork, Kind: "ban_hit", HitSource: "redis"},
		{CountedRecord: supporthistory.CountedRecord{At: activatedAt.Add(-time.Minute), ClaimedUsername: "eve@example.test"},
			Network: banNetwork, Kind: "ban_hit", HitSource: "l1"},
	}

	return store
}

// searchBans runs one ban search by IP over the last three hours.
func searchBans(t *testing.T, store *historytest.BanStore, scope string) *supporthistory.BanSearchResult {
	t.Helper()

	result, err := banService(t, store).SearchBans(context.Background(), caller(scope), supporthistory.BanSearchRequest{
		SchemaVersion: "1", Target: supporthistory.BanTarget{IP: "198.51.100.17"},
		Filter: supporthistory.BanSearchFilter{From: banNow.Add(-3 * time.Hour), Until: banNow}})
	if err != nil {
		t.Fatalf("SearchBans() error = %v", err)
	}

	return result
}

// TestBanContributionsStopAtCounterReset mirrors TestClickHouseBruteForceContributionsStopAtCounterReset: an
// increment after the reset restarts at 1 and never joins the earlier ban.
func TestBanContributionsStopAtCounterReset(t *testing.T) {
	result := searchBans(t, sharedIPStore(banNow.Add(-2*time.Hour)), definitions.ScopeHistoryRead)
	if len(result.Bans) != 1 {
		t.Fatalf("bans = %+v, want one", result.Bans)
	}

	assertSharedIPBan(t, result.Bans[0])

	if result.OrphanHits.Count != 1 || stringValue(result.Releases[0].OperatorClientID) != "ops-client" ||
		len(result.CounterResets) != 1 {
		t.Fatalf("orphans = %+v lifecycle = %+v / %+v, want one orphan and the operator id",
			result.OrphanHits, result.Releases, result.CounterResets)
	}
}

// assertSharedIPBan checks contributions, the crossing heuristic, hits, and the released claims of one ban.
func assertSharedIPBan(t *testing.T, ban supporthistory.Ban) {
	t.Helper()

	summary := fmt.Sprintf("%s/%d/%s/%s/%d/%d", ban.Contributions.Status, len(ban.Contributions.Items), ban.End.Reason,
		ban.Activation.ActivatingRequest, ban.Hits.Count, *ban.Contributions.DistinctClaimedNames)
	if summary != "complete/3/released/NOT_A_CULPRIT/1/3" {
		t.Fatalf("ban = %s, want three complete contributions, one hit, ending in the release", summary)
	}

	if candidate := ban.Contributions.CrossingCandidate; candidate == nil || candidate.EventID != "c3" ||
		candidate.Basis != "heuristic_crossed_flag" {
		t.Fatalf("crossing candidate = %+v, want the heuristic c3", candidate)
	}

	claims := make([]string, 0, len(ban.Contributions.Items))
	for _, item := range ban.Contributions.Items {
		claims = append(claims, stringValue(item.ClaimedUsername)+"@"+stringValue(item.ClientIP))
	}

	if want := []string{"alice@example.test@198.51.100.17", "ceo@foreign.test@198.51.100.17",
		"bob@example.test@198.51.100.17"}; !slices.Equal(claims, want) {
		t.Fatalf("contribution claims = %v, want %v", claims, want)
	}
}

// TestBanCompletenessCoversBothWindows pins that a loss in the previous window is never reported complete.
func TestBanCompletenessCoversBothWindows(t *testing.T) {
	at := banNow.Add(-2 * time.Hour)

	lost := sharedIPStore(at)
	lost.Contribs[banBucket] = slices.Delete(lost.Contribs[banBucket], 1, 2)

	if status := searchBans(t, lost, definitions.ScopeHistoryRead).Bans[0].Contributions.Status; status != "loss_detected" {
		t.Fatalf("status = %s, want loss_detected for a missing current increment", status)
	}

	previous := sharedIPStore(at)
	previous.Store.Lifecycle[0] = activation("ban-1", at, 3, 2)
	previous.Contribs[banBucket] = append(previous.Contribs[banBucket],
		counted("p1", at.Add(-40*time.Minute), banWindow-1, 1, "old@example.test", false))

	ban := searchBans(t, previous, definitions.ScopeHistoryRead).Bans[0]
	if ban.Contributions.Status != "loss_detected" || ban.Contributions.Windows[0].Status != "complete" ||
		ban.Contributions.Windows[1].Status != "loss_detected" {
		t.Fatalf("windows = %+v, want a complete activation window and a lossy previous window", ban.Contributions.Windows)
	}
}

// TestBanEvidenceBeyondRawRetention pins aggregate_only and expired statuses outside the 14-day raw window.
func TestBanEvidenceBeyondRawRetention(t *testing.T) {
	old := banNow.Add(-20 * 24 * time.Hour)
	request := supporthistory.BanSearchRequest{SchemaVersion: "1", Target: supporthistory.BanTarget{Network: banNetwork},
		Filter: supporthistory.BanSearchFilter{From: old.Add(-time.Hour), Until: old.Add(time.Hour)}}

	gap := []supporthistory.WindowSummary{{WindowIndex: banWindow, Events: 2, MinCurrent: int64p(1), MaxCurrent: int64p(3)}}

	for name, tc := range map[string]struct {
		summaries  []supporthistory.WindowSummary
		status     string
		keepReset  bool
		unreliable bool
	}{
		"consistent summary": {[]supporthistory.WindowSummary{{WindowIndex: banWindow, Events: 3, MinCurrent: int64p(1), MaxCurrent: int64p(3)}}, "aggregate_only", false, false},
		"provable gap":       {gap, "loss_detected", false, false},
		"reset in window":    {gap, "aggregate_only", true, true},
		"no summary":         {nil, "expired", false, false},
	} {
		t.Run(name, func(t *testing.T) {
			store := sharedIPStore(old)
			store.Summaries = tc.summaries

			if !tc.keepReset {
				store.Store.Lifecycle = store.Store.Lifecycle[:2]
			}

			result, err := banService(t, store).SearchBans(context.Background(), caller(definitions.ScopeHistoryRead), request)
			if err != nil {
				t.Fatalf("SearchBans() error = %v", err)
			}

			window := result.Bans[0].Contributions.Windows[0]
			if window.Status != tc.status || window.Evidence == "raw" || window.SummaryCheckUnreliable != tc.unreliable ||
				len(result.Bans[0].Contributions.Items) != 0 {
				t.Fatalf("window = %+v, want %s without raw items", window, tc.status)
			}
		})
	}
}

// TestBanInstancesKeepUnknownsVisible pins supersession, unconfirmed creators, and bans that began before the window.
func TestBanInstancesKeepUnknownsVisible(t *testing.T) {
	at := banNow.Add(-2 * time.Hour)
	store := sharedIPStore(at)
	earlier := activation("ban-0", at.Add(-5*time.Hour), 3, 0)
	far := at.Add(30 * time.Hour)
	earlier.ExpiresAt = &far
	unconfirmed := supporthistory.LifecycleRecord{At: at.Add(10 * time.Minute), EventID: "ban-2", Kind: "ban_activation_unconfirmed",
		Network: banNetwork, Rule: "nat-network"}
	store.Store.Lifecycle = append([]supporthistory.LifecycleRecord{earlier}, append(store.Store.Lifecycle, unconfirmed)...)

	bans := searchBans(t, store, definitions.ScopeHistoryRead).Bans

	byRef := map[string]supporthistory.Ban{}
	for _, ban := range bans {
		byRef[ban.BanRef] = ban
	}

	if byRef["ban-0"].End.Reason != "superseded_by_new_activation" {
		t.Fatalf("earlier ban = %+v, want superseded and found although it began before the window", byRef["ban-0"])
	}

	if ban := byRef["ban-2"]; !slices.Contains(ban.Unknowns, "ACTIVATION_CREATOR_UNKNOWN") || ban.Contributions.Status != "not_applicable" ||
		ban.End.Reason != "unknown" {
		t.Fatalf("unconfirmed ban = %+v, want unknown creator and end", ban)
	}
}

// longRuleStore returns a 28-day rule activated two days ago: two increments of the activation window lie beyond the
// 14-day raw retention, three inside it, followed by a later increment, a hit, and a counter reset after the ban.
func longRuleStore() *historytest.BanStore {
	at := banNow.Add(-48 * time.Hour)
	long := activation("ban-long", at, 5, 2)
	long.PeriodSeconds = int64((28 * 24 * time.Hour).Seconds())

	store := sharedIPStore(at)
	store.Store.Lifecycle = []supporthistory.LifecycleRecord{long,
		{At: at.Add(time.Hour), EventID: "reset-long", Kind: "counters_reset", Network: banNetwork, BucketID: banBucket,
			Rule: "nat-network"}}
	store.Contribs[banBucket] = []supporthistory.CountedRecord{
		counted("p1", at.Add(-40*24*time.Hour), banWindow-1, 1, "old-a@example.test", false),
		counted("p2", at.Add(-35*24*time.Hour), banWindow-1, 2, "old-b@example.test", false),
		counted("c1", at.Add(-20*24*time.Hour), banWindow, 1, "expired-a@example.test", false),
		counted("c2", at.Add(-15*24*time.Hour), banWindow, 2, "expired-b@example.test", false),
		counted("c3", at.Add(-10*24*time.Hour), banWindow, 3, "alice@example.test", false),
		counted("c4", at.Add(-5*24*time.Hour), banWindow, 4, "bob@example.test", false),
		counted("c5", at.Add(-time.Second), banWindow, 5, "bob@example.test", true),
		counted("after", at.Add(30*time.Minute), banWindow, 6, "late@example.test", false),
		counted("restart", at.Add(2*time.Hour), banWindow, 1, "restart@example.test", false),
	}
	store.Summaries = []supporthistory.WindowSummary{
		{WindowIndex: banWindow, Events: 7, MinCurrent: int64p(1), MaxCurrent: int64p(6)},
		{WindowIndex: banWindow - 1, Events: 2, MinCurrent: int64p(1), MaxCurrent: int64p(2)},
	}

	return store
}

// TestLongRuleListsRetainedContributions reproduces the long-rule gap: a rule whose windows reach beyond the raw
// retention still lists the retained increments of the activation, assesses completeness from the summary only,
// and never turns later increments, increments after a reset, or hits into contributions.
func TestLongRuleListsRetainedContributions(t *testing.T) {
	result, err := banService(t, longRuleStore()).SearchBans(context.Background(), caller(definitions.ScopeHistoryDetail),
		supporthistory.BanSearchRequest{SchemaVersion: "1", Target: supporthistory.BanTarget{Network: banNetwork},
			Filter: supporthistory.BanSearchFilter{From: banNow.Add(-3 * 24 * time.Hour), Until: banNow}})
	if err != nil || len(result.Bans) != 1 {
		t.Fatalf("SearchBans() = %+v, %v, want the long ban", result, err)
	}

	contributions := result.Bans[0].Contributions

	var ids []string
	for _, item := range contributions.Items {
		ids = append(ids, item.EventID)
	}

	if !slices.Equal(ids, []string{"c3", "c4", "c5"}) {
		t.Fatalf("items = %v, want only the retained increments c3, c4, c5 of the activation", ids)
	}

	if contributions.Status != "aggregate_only" || !slices.Contains(contributions.Caveats, "RAW_CONTRIBUTIONS_PARTIALLY_RETAINED") {
		t.Fatalf("status = %s caveats = %v, want aggregate_only with the partial-retention caveat",
			contributions.Status, contributions.Caveats)
	}

	for _, window := range contributions.Windows {
		if window.Evidence == "raw" || window.Status == "complete" {
			t.Fatalf("window = %+v, want a summary assessment for a window beyond raw retention", window)
		}
	}

	if candidate := contributions.CrossingCandidate; candidate == nil || candidate.EventID != "c5" {
		t.Fatalf("crossing candidate = %+v, want c5", candidate)
	}
}

// TestBanClaimantsStateTheirLimit reproduces the silent claimant cap: a ban hit by more claimed names than
// MaxClaimants listed the first ones without saying that more exist.
func TestBanClaimantsStateTheirLimit(t *testing.T) {
	activatedAt := banNow.Add(-2 * time.Hour)
	store := sharedIPStore(activatedAt)

	for index := range supporthistory.MaxClaimants + 2 {
		store.Volume = append(store.Volume, historytest.VolumeRow{CountedRecord: supporthistory.CountedRecord{
			At: activatedAt.Add(2 * time.Second), ClaimedUsername: fmt.Sprintf("user%02d@example.test", index)},
			Network: banNetwork, Kind: "ban_hit", HitSource: "redis"})
	}

	hits := searchBans(t, store, definitions.ScopeHistoryRead).Bans[0].Hits
	if len(hits.Claimants) != supporthistory.MaxClaimants || !hits.ClaimantsTruncated {
		t.Fatalf("claimants = %d, truncated = %v, want %d and true", len(hits.Claimants), hits.ClaimantsTruncated,
			supporthistory.MaxClaimants)
	}

	if few := searchBans(t, sharedIPStore(activatedAt), definitions.ScopeHistoryRead).Bans[0].Hits; few.ClaimantsTruncated {
		t.Fatalf("a short claimant list is complete: %+v", few)
	}
}
