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

package windowsource

import (
	"context"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/croessner/nauthilus/v4/server/supportops"
)

// BucketSeries is one counted series of a bucketed collection: its labels and its whole count per bucket.
type BucketSeries struct {
	Labels map[string]string
	Counts []int64
}

// BucketResult is the answer of one bucketed collection: the completeness report with the covered instances and
// time span, the bucket grid, and the series of every build in build order. A build whose every query failed has
// nil series.
type BucketResult struct {
	Series  [][]BucketSeries
	Buckets []supportops.Window
	Report  supportops.SourceReport
}

// bucketCount is one instant query of a bucketed collection: the build, the bucket, and the part of that bucket.
type bucketCount struct {
	span   supportops.Window
	build  int
	bucket int
}

// CollectBuckets proves coverage with the coverage query and counts every build in every bucket of a grid of at
// most buckets buckets that tile the covered window exactly. Each bucket is counted by instant queries over its
// parts of at most MaxTimeWindow, evaluated at the exact part end, so no count depends on how the endpoint aligns
// range evaluations, no line is counted twice or outside the window, and a line on a bucket edge counts in the
// bucket that starts there.
func (e *Engine) CollectBuckets(ctx context.Context, query supportops.Query, buckets int, builds []func(rangeMillis int64) string) BucketResult {
	parts, window, clipped := e.windowParts(query.Window)
	grid := BucketGrid(window, buckets)
	result := BucketResult{Buckets: grid, Series: make([][]BucketSeries, len(builds))}

	ctx, cancel := context.WithTimeout(ctx, e.budget(parts))
	defer cancel()

	collection := newCollection(e, query, window)

	if clipped {
		collection.degrade(supportops.SourceStatusPartial, e.code("WINDOW_CLIPPED"))
	}

	slots := make(chan struct{}, maxParallelQueries)

	coverage, ok := collection.sumParts(ctx, slots, e.spec.Coverage, parts, true)
	if !ok {
		result.Report = collection.report(nil, window)

		return result
	}

	result.Series = collection.countBuckets(ctx, slots, e.bucketCounts(grid, len(builds)), builds, len(grid))
	result.Report = collection.report(collection.instances(coverage), window)

	return result
}

// bucketCounts lists the instant queries of a grid: every build in every part of every bucket.
func (e *Engine) bucketCounts(grid []supportops.Window, builds int) []bucketCount {
	var counts []bucketCount

	for build := range builds {
		for bucket, span := range grid {
			for _, part := range SplitWindow(span, e.partLength()) {
				counts = append(counts, bucketCount{span: part, build: build, bucket: bucket})
			}
		}
	}

	return counts
}

// countBuckets runs the instant queries and adds their samples per build, series, and bucket. A build whose every
// query failed has nil series; when every query of every build failed, the collection becomes unavailable.
func (c *collection) countBuckets(ctx context.Context, slots chan struct{}, counts []bucketCount,
	builds []func(rangeMillis int64) string, buckets int) [][]BucketSeries {
	answers := make([][]Sample, len(counts))
	succeeded := make([]bool, len(counts))

	var wait sync.WaitGroup

	for index, count := range counts {
		wait.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()

			answers[index], succeeded[index] = c.run(ctx, builds[count.build], count.span, false)
		})
	}

	wait.Wait()

	series := make([][]BucketSeries, len(builds))
	positions := make([]map[string]int, len(builds))
	answered := make([]bool, len(builds))

	for index, count := range counts {
		if !succeeded[index] {
			continue
		}

		answered[count.build] = true

		if positions[count.build] == nil {
			positions[count.build], series[count.build] = map[string]int{}, []BucketSeries{}
		}

		series[count.build] = addBucketSamples(series[count.build], positions[count.build], answers[index], count.bucket, buckets)
	}

	if !slices.Contains(answered, true) {
		c.escalate()
	}

	return series
}

// addBucketSamples adds the rounded samples of one query to their series in one bucket.
func addBucketSamples(series []BucketSeries, positions map[string]int, samples []Sample, bucket int, buckets int) []BucketSeries {
	for _, sample := range samples {
		key := labelsKey(sample.Labels)

		position, seen := positions[key]
		if !seen {
			position, positions[key] = len(series), len(series)

			series = append(series, BucketSeries{Labels: sample.Labels, Counts: make([]int64, buckets)})
		}

		series[position].Counts[bucket] = saturatingAdd(series[position].Counts[bucket], sample.Value)
	}

	return series
}

// BucketGrid splits window into at most buckets buckets that tile it exactly and end at the window end: every bucket
// spans the same whole number of seconds, except the first, which starts at the window start and may be shorter. The
// bucket bounds keep the millisecond precision of the window.
func BucketGrid(window supportops.Window, buckets int) []supportops.Window {
	buckets = max(buckets, 1)
	total := max(int64(math.Ceil(window.Until.Sub(window.From).Seconds())), 1)

	return SplitWindow(window, time.Duration((total+int64(buckets)-1)/int64(buckets))*time.Second)
}

// saturatingAdd adds a rounded non-negative value to a count without overflowing.
func saturatingAdd(count int64, value float64) int64 {
	rounded := math.Round(value)
	if rounded >= float64(math.MaxInt64-count) {
		return math.MaxInt64
	}

	return count + int64(rounded)
}
