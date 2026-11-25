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

// alignmentTolerance is how far an evaluation may be from a bucket end and still count for that bucket.
const alignmentTolerance = time.Second

// RangeResult is the answer of one bucketed range collection: the completeness report with the covered instances and
// time span, the bucket grid, and the series of every range query in query order. A failed query has nil series.
type RangeResult struct {
	Series  [][]Series
	Buckets []supportops.Window
	Report  supportops.SourceReport
}

// CollectRange proves coverage with the coverage query and runs the range queries over a grid of at most buckets
// equal buckets that ends at the covered window end. Each build receives the bucket width in seconds and must count
// over exactly that range, so the evaluations tile the grid. The grid can start up to buckets-1 seconds before the
// window; the report states the span it really covers.
func (e *Engine) CollectRange(ctx context.Context, query supportops.Query, buckets int, builds []func(stepSeconds int64) string) RangeResult {
	ctx, cancel := context.WithTimeout(ctx, e.spec.Timeout)
	defer cancel()

	window, clipped := e.coveredWindow(query.Window)
	collection := newCollection(e, query, window)

	if clipped {
		collection.degrade(supportops.SourceStatusPartial, e.code("WINDOW_CLIPPED"))
	}

	grid, step := BucketGrid(window, buckets)
	covered := supportops.Window{From: grid[0].From, Until: window.Until}

	coverage, ok := collection.run(ctx, e.spec.Coverage, true)
	if !ok {
		return RangeResult{Buckets: grid, Report: collection.report(nil, covered), Series: make([][]Series, len(builds))}
	}

	series := make([][]Series, len(builds))
	failures := make([]error, len(builds))

	var wait sync.WaitGroup

	for index, build := range builds {
		wait.Go(func() {
			series[index], failures[index] = collection.runRange(ctx, build(int64(step/time.Second)), grid[0].Until, window.Until, step)
		})
	}

	wait.Wait()
	collection.failAll(ctx, failures)

	return RangeResult{Series: series, Buckets: grid, Report: collection.report(collection.instances(coverage), covered)}
}

// runRange executes one range query; a failure degrades the collection to partial or timeout and is returned.
func (c *collection) runRange(ctx context.Context, query string, start time.Time, end time.Time, step time.Duration) ([]Series, error) {
	series, truncated, err := c.engine.client.Range(ctx, query, start, end, step)
	if truncated {
		c.markTruncated()
	}

	if err != nil {
		c.fail(ctx, err, false)

		return nil, err
	}

	return series, nil
}

// failAll makes the collection unavailable when every range query failed, so an answer without any counted series
// never reads as a quiet window.
func (c *collection) failAll(ctx context.Context, failures []error) {
	if len(failures) == 0 || slices.Contains(failures, nil) {
		return
	}

	c.fail(ctx, failures[0], true)
}

// BucketGrid splits window into at most buckets equal buckets of whole seconds that end at the window end. The first
// bucket starts at or before the window start.
func BucketGrid(window supportops.Window, buckets int) ([]supportops.Window, time.Duration) {
	total := max(int64(math.Ceil(window.Until.Sub(window.From).Seconds())), 1)
	stepSeconds := max((total+int64(max(buckets, 1))-1)/int64(max(buckets, 1)), 1)
	count := (total + stepSeconds - 1) / stepSeconds
	step := time.Duration(stepSeconds) * time.Second

	grid := make([]supportops.Window, 0, count)

	for index := range count {
		from := window.Until.Add(-time.Duration(count-index) * step)
		grid = append(grid, supportops.Window{From: from.UTC(), Until: from.Add(step).UTC()})
	}

	return grid, step
}

// BucketCounts maps the points of one series onto the grid by their evaluation time, which is the bucket end, and
// rounds every count to a whole number. A point that is not within a second of a bucket end, for example after a query
// frontend aligned the evaluations to the step, is dropped and reported, so a count never lands in a bucket whose span
// it does not cover.
func BucketCounts(series Series, grid []supportops.Window) ([]int64, bool) {
	counts := make([]int64, len(grid))
	misaligned := false

	if len(grid) == 0 {
		return counts, len(series.Points) > 0
	}

	step := grid[0].Until.Sub(grid[0].From)

	for _, point := range series.Points {
		offset := point.At.Sub(grid[0].Until)
		index := int(math.Round(float64(offset) / float64(step)))

		if index < 0 || index >= len(grid) || (offset-time.Duration(index)*step).Abs() > alignmentTolerance {
			misaligned = true

			continue
		}

		counts[index] = saturatingAdd(counts[index], point.Value)
	}

	return counts, misaligned
}

// saturatingAdd adds a rounded non-negative value to a count without overflowing.
func saturatingAdd(count int64, value float64) int64 {
	rounded := math.Round(value)
	if rounded >= float64(math.MaxInt64-count) {
		return math.MaxInt64
	}

	return count + int64(rounded)
}
