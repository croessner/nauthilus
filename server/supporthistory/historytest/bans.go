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

package historytest

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/supporthistory"
)

// Fixed values of the recorded-ban fixture.
const (
	kindBanHit    = "ban_hit"
	fixtureRule   = "example_failed_logins"
	fixtureBucket = "bucket-fixture"
)

// VolumeRow is one hit or tolerated row of the fake volume lane.
type VolumeRow struct {
	supporthistory.CountedRecord

	Network   string
	Kind      string
	HitSource string
	Rule      string
	BucketID  string
}

// BanStore extends Store with brute-force evidence.
type BanStore struct {
	*Store

	Summaries []supporthistory.WindowSummary
	Volume    []VolumeRow
	Recorded  []supporthistory.Prefix
	Contribs  map[string][]supporthistory.CountedRecord
}

// Prefixes returns the recorded prefixes.
func (b *BanStore) Prefixes(context.Context) ([]supporthistory.Prefix, error) {
	return b.Recorded, b.record("Prefixes")
}

// Lifecycle returns the rows of the networks in the range.
func (b *BanStore) Lifecycle(_ context.Context, query supporthistory.LifecycleQuery) ([]supporthistory.LifecycleRecord, error) {
	if err := b.record("Lifecycle"); err != nil {
		return nil, err
	}

	var rows []supporthistory.LifecycleRecord

	for _, row := range b.Store.Lifecycle {
		if slices.Contains(query.Networks, row.Network) && inRange(row.At, query.From, query.Until) {
			rows = append(rows, row)
		}
	}

	slices.SortStableFunc(rows, func(a, b supporthistory.LifecycleRecord) int { return b.At.Compare(a.At) })

	counts := map[string]int{}

	return slices.DeleteFunc(rows, func(row supporthistory.LifecycleRecord) bool {
		counts[row.Network]++

		return query.PerNetwork > 0 && counts[row.Network] > query.PerNetwork
	}), nil
}

// Contributions mirrors the §13.4 reference predicate over the configured counted rows of a bucket in the order
// window_index, window_current, ts, event_id, including the replay removal by event id (LIMIT 1 BY event_id), the
// continuation position, and the row limit.
func (b *BanStore) Contributions(_ context.Context, query supporthistory.ContributionQuery) ([]supporthistory.CountedRecord, error) {
	if err := b.record("Contributions"); err != nil {
		return nil, err
	}

	var rows []supporthistory.CountedRecord

	for _, row := range b.Contribs[query.BucketID] {
		if contributionMatch(query, row) && contributionFrom(row, query.Start) {
			rows = append(rows, row)
		}
	}

	slices.SortStableFunc(rows, compareContributions)

	seen := map[string]struct{}{}
	rows = slices.DeleteFunc(rows, func(row supporthistory.CountedRecord) bool {
		_, replay := seen[row.EventID]
		seen[row.EventID] = struct{}{}

		return replay && row.EventID != ""
	})

	if query.Limit > 0 && len(rows) > query.Limit {
		rows = rows[:query.Limit]
	}

	return rows, nil
}

// compareContributions orders counted rows by window_index, window_current, ts, and event_id; the predicate keeps
// only rows whose window values are set.
func compareContributions(a, b supporthistory.CountedRecord) int {
	return cmp.Or(cmp.Compare(*a.WindowIndex, *b.WindowIndex), cmp.Compare(*a.WindowCurrent, *b.WindowCurrent),
		a.At.Compare(b.At), cmp.Compare(a.EventID, b.EventID))
}

// contributionFrom mirrors the inclusive keyset condition of a contribution continuation.
func contributionFrom(row supporthistory.CountedRecord, position *supporthistory.ContributionPosition) bool {
	if position == nil {
		return true
	}

	key := supporthistory.CountedRecord{WindowIndex: &position.WindowIndex, WindowCurrent: &position.WindowCurrent,
		At: position.At, EventID: position.EventID}

	return compareContributions(row, key) >= 0
}

// contributionMatch mirrors the reference predicate for one counted row.
func contributionMatch(query supporthistory.ContributionQuery, row supporthistory.CountedRecord) bool {
	if row.WindowIndex == nil || row.WindowCurrent == nil || !inRange(row.At, query.From, query.Until) {
		return false
	}

	current := *row.WindowIndex == query.WindowIndex && *row.WindowCurrent <= query.Current
	previous := *row.WindowIndex == query.WindowIndex-1 && *row.WindowCurrent <= query.Previous
	afterReset := query.ResetAfter == nil || row.At.After(*query.ResetAfter)
	beforeReset := query.ResetBefore == nil || row.At.Before(*query.ResetBefore)

	return (current || previous) && afterReset && beforeReset
}

// WindowSummaries returns the configured summaries of the requested windows.
func (b *BanStore) WindowSummaries(_ context.Context, query supporthistory.SummaryQuery) ([]supporthistory.WindowSummary, error) {
	if err := b.record("WindowSummaries"); err != nil {
		return nil, err
	}

	var rows []supporthistory.WindowSummary

	for _, row := range b.Summaries {
		if slices.Contains(query.WindowIndexes, row.WindowIndex) {
			rows = append(rows, row)
		}
	}

	return rows, nil
}

// KindCounts aggregates the configured volume rows.
func (b *BanStore) KindCounts(_ context.Context, query supporthistory.KindQuery) (supporthistory.KindAggregate, error) {
	aggregate := supporthistory.KindAggregate{BySource: map[string]int64{}}
	if err := b.record("KindCounts"); err != nil {
		return aggregate, err
	}

	names := map[string]struct{}{}
	claimants := map[[2]string]int64{}

	for _, row := range b.Volume {
		if row.Kind != query.Kind || !slices.Contains(query.Networks, row.Network) || !inRange(row.At, query.From, query.Until) ||
			excluded(row, query.Exclude) {
			continue
		}

		aggregate.Total++
		aggregate.BySource[row.HitSource]++
		claimants[[2]string{row.ClaimedUsername, row.Account}]++

		if row.ClaimedUsername != "" {
			names[row.ClaimedUsername] = struct{}{}
		}
	}

	distinct := int64(len(names))
	aggregate.DistinctNames = &distinct
	aggregate.Claimants = topClaimants(claimants, query.ClaimantOffset, query.Claimants)

	return aggregate, nil
}

// topClaimants mirrors the claimant read: claimed name and account with their hits, most hits first, at most limit
// after skipping offset.
func topClaimants(counts map[[2]string]int64, offset, limit int) []supporthistory.ClaimantRecord {
	if limit <= 0 {
		return nil
	}

	claimants := make([]supporthistory.ClaimantRecord, 0, len(counts))

	for key, hits := range counts {
		claimants = append(claimants, supporthistory.ClaimantRecord{ClaimedUsername: key[0], Account: key[1], Hits: hits})
	}

	slices.SortFunc(claimants, func(left, right supporthistory.ClaimantRecord) int {
		return cmp.Or(cmp.Compare(right.Hits, left.Hits), strings.Compare(left.ClaimedUsername, right.ClaimedUsername),
			strings.Compare(left.Account, right.Account))
	})

	start := min(max(0, offset), len(claimants))

	return claimants[start:min(start+limit, len(claimants))]
}

// RequestHits mirrors the request-hit read: ban_hit rows of the requests on the networks, replays removed by event
// id, oldest first, at most Limit rows.
func (b *BanStore) RequestHits(_ context.Context, query supporthistory.RequestHitQuery) ([]supporthistory.HitRecord, error) {
	if err := b.record("RequestHits"); err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}

	var hits []supporthistory.HitRecord

	for _, row := range b.Volume {
		if row.Kind != kindBanHit || !slices.Contains(query.Networks, row.Network) ||
			!slices.Contains(query.RequestIDs, row.RequestID) || !inRange(row.At, query.From, query.Until) {
			continue
		}

		if _, replay := seen[row.EventID]; replay && row.EventID != "" {
			continue
		}

		seen[row.EventID] = struct{}{}
		hits = append(hits, supporthistory.HitRecord{At: row.At, EventID: row.EventID, RequestID: row.RequestID,
			Network: row.Network, Rule: row.Rule, BucketID: row.BucketID, HitSource: row.HitSource})
	}

	slices.SortStableFunc(hits, func(a, b supporthistory.HitRecord) int { return a.At.Compare(b.At) })

	if query.Limit > 0 && len(hits) > query.Limit {
		hits = hits[:query.Limit]
	}

	return hits, nil
}

// excluded reports whether a row lies in one of the excluded instance intervals.
func excluded(row VolumeRow, intervals []supporthistory.NetworkInterval) bool {
	return slices.ContainsFunc(intervals, func(interval supporthistory.NetworkInterval) bool {
		return interval.Network == row.Network && inRange(row.At, interval.From, interval.Until)
	})
}

// WithRecordedBan returns a ban store over store in which the login row of requestID was rejected by a recorded
// host ban: a different request activated it ten minutes earlier after one increment of another account and one
// of the row's own account, and the row's request hit it. Transport tests use it to exercise the ban context.
func WithRecordedBan(store *Store, requestID string) *BanStore {
	index := slices.IndexFunc(store.Logins, func(row supporthistory.LoginRecord) bool { return row.Session == requestID })
	if index < 0 {
		return &BanStore{Store: store, Contribs: map[string][]supporthistory.CountedRecord{}}
	}

	row := store.Logins[index]
	activatedAt := row.At.Add(-10 * time.Minute)
	expires := activatedAt.Add(time.Hour)
	network := row.ClientIP + "/32"
	window, current, previous, known := int64(7), int64(2), int64(0), true
	first, second := int64(1), int64(2)

	store.Lifecycle = append(store.Lifecycle, supporthistory.LifecycleRecord{At: activatedAt, ExpiresAt: &expires,
		EventID: "0123456789abcdef0123456789abcdef", Kind: "ban_activated", Network: network, Rule: fixtureRule,
		StoredRule: fixtureRule, BucketID: fixtureBucket, RequestID: "req-activator", PeriodSeconds: 3600,
		BanTimeSeconds: 3600, FailedRequests: 3, WindowIndex: &window, WindowCurrent: &current, WindowPrevious: &previous})

	counted := func(id string, offset time.Duration, current *int64, name, account string) supporthistory.CountedRecord {
		return supporthistory.CountedRecord{At: activatedAt.Add(-offset), EventID: id, RequestID: "req-" + id,
			WindowIndex: &window, WindowCurrent: current, ClaimedUsername: name, Account: account, AccountKnown: &known,
			ClientIP: row.ClientIP, CountSource: "backend_failure", Protocol: row.Protocol}
	}

	return &BanStore{Store: store, Recorded: []supporthistory.Prefix{{Family: 4, Bits: 32}},
		Contribs: map[string][]supporthistory.CountedRecord{fixtureBucket: {
			counted("fixture-other", 2*time.Second, &first, "other@example.test", "other-account"),
			counted("fixture-own", time.Second, &second, row.Username, row.Account),
		}},
		Volume: []VolumeRow{{CountedRecord: supporthistory.CountedRecord{At: row.At, EventID: "fixture-hit",
			RequestID: requestID, ClaimedUsername: row.Username}, Network: network, Kind: kindBanHit, HitSource: "redis",
			Rule: fixtureRule}}}
}
