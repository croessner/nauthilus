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
	"context"
	"slices"

	"github.com/croessner/nauthilus/v4/server/supporthistory"
)

// VolumeRow is one hit or tolerated row of the fake volume lane.
type VolumeRow struct {
	supporthistory.CountedRecord

	Network   string
	Kind      string
	HitSource string
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

// Contributions mirrors the §13.4 reference predicate over the configured counted rows of a bucket.
func (b *BanStore) Contributions(_ context.Context, query supporthistory.ContributionQuery) ([]supporthistory.CountedRecord, error) {
	if err := b.record("Contributions"); err != nil {
		return nil, err
	}

	var rows []supporthistory.CountedRecord

	for _, row := range b.Contribs[query.BucketID] {
		if contributionMatch(query, row) {
			rows = append(rows, row)
		}
	}

	return rows, nil
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

	for _, row := range b.Volume {
		if row.Kind != query.Kind || !slices.Contains(query.Networks, row.Network) || !inRange(row.At, query.From, query.Until) ||
			excluded(row, query.Exclude) {
			continue
		}

		aggregate.Total++
		aggregate.BySource[row.HitSource]++

		if row.ClaimedUsername != "" {
			names[row.ClaimedUsername] = struct{}{}
		}
	}

	distinct := int64(len(names))
	aggregate.DistinctNames = &distinct

	return aggregate, nil
}

// excluded reports whether a row lies in one of the excluded instance intervals.
func excluded(row VolumeRow, intervals []supporthistory.NetworkInterval) bool {
	return slices.ContainsFunc(intervals, func(interval supporthistory.NetworkInterval) bool {
		return interval.Network == row.Network && inRange(row.At, interval.From, interval.Until)
	})
}
