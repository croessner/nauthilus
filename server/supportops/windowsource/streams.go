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
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/croessner/nauthilus/v4/server/supportops"
)

// StreamsResult is the answer of one log stream collection: the streams of every query in query order (nil for a
// failed query), the completeness report, and whether an answer exceeded the byte bound, in which case the caller
// may retry with a smaller limit. A byte-bound answer does not degrade the report by itself.
type StreamsResult struct {
	Streams       [][]Stream
	Report        supportops.SourceReport
	Window        supportops.Window
	OverByteBound bool
}

// CollectStreams runs the log queries over the covered window up to end (exclusive), each returning at most limit
// entries, newest first. A zero end means the window end; an end outside the window is clipped to it.
func (e *Engine) CollectStreams(ctx context.Context, query supportops.Query, end time.Time, limit int, queries []string) StreamsResult {
	ctx, cancel := context.WithTimeout(ctx, e.spec.Timeout)
	defer cancel()

	window, clipped := e.coveredWindow(query.Window)
	collection := newCollection(e, query, window)

	if clipped {
		collection.degrade(supportops.SourceStatusPartial, e.code("WINDOW_CLIPPED"))
	}

	if end.IsZero() || end.After(window.Until) {
		end = window.Until
	}

	result := StreamsResult{Streams: make([][]Stream, len(queries)), Window: window}
	overBound := make([]bool, len(queries))
	failed := make([]bool, len(queries))

	var wait sync.WaitGroup

	for index, text := range queries {
		wait.Go(func() {
			streams, err := e.client.Streams(ctx, text, window.From, end, limit)

			switch {
			case errors.Is(err, ErrTruncated):
				overBound[index] = true
			case err != nil:
				failed[index] = true

				collection.fail(ctx, err, false)
			default:
				result.Streams[index] = streams
			}
		})
	}

	wait.Wait()

	for _, over := range overBound {
		result.OverByteBound = result.OverByteBound || over
	}

	if !slices.Contains(failed, false) {
		collection.escalate()
	}

	result.Report = collection.report(nil, supportops.Window{From: window.From, Until: end})

	return result
}

// escalate turns a partial collection into an unavailable one, for a collection in which every query failed.
func (c *collection) escalate() {
	c.mu.Lock()
	code := c.code
	c.mu.Unlock()

	c.degrade(supportops.SourceStatusUnavailable, code)
}

// SeriesResult is the answer of one stream listing: the label sets and the completeness report.
type SeriesResult struct {
	Streams []map[string]string
	Report  supportops.SourceReport
}

// CollectSeries lists the streams matching selector between start and end (exclusive) inside the covered window, at
// most MaxLogEventRead of them (label sets are small; the series bound of metric answers does not apply). A failed
// listing makes the report unavailable; a cut list marks it partial and truncated.
func (e *Engine) CollectSeries(ctx context.Context, query supportops.Query, selector string, start time.Time, end time.Time) SeriesResult {
	ctx, cancel := context.WithTimeout(ctx, e.spec.Timeout)
	defer cancel()

	window, _ := e.coveredWindow(query.Window)
	collection := newCollection(e, query, window)

	streams, truncated, err := e.client.Series(ctx, selector, start, end, supportops.MaxLogEventRead)
	if truncated {
		collection.markTruncated()
	}

	if err != nil {
		collection.fail(ctx, err, true)
	}

	return SeriesResult{Streams: streams, Report: collection.report(nil, supportops.Window{From: start, Until: end})}
}
