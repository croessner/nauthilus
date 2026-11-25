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
// may retry with a smaller limit. A byte-bound answer does not degrade the report by itself. Window is the covered
// window and ReadFrom the start of the part that was read: lines before ReadFrom inside the window are not part of
// this read.
type StreamsResult struct {
	ReadFrom      time.Time
	Streams       [][]Stream
	Report        supportops.SourceReport
	Window        supportops.Window
	OverByteBound bool

	// Failed is set when any query of the read failed, so the read part may miss lines.
	Failed bool
}

// CollectStreams runs the log queries over the newest part of the covered window up to end (exclusive), each
// returning at most limit entries, newest first. A zero end means the window end; an end outside the window is
// clipped to it. One read spans at most MaxTimeWindow; when no query returns a line, the next older part is read, so
// a long quiet span does not end a page empty while older lines exist.
func (e *Engine) CollectStreams(ctx context.Context, query supportops.Query, end time.Time, limit int, queries []string) StreamsResult {
	_, window, clipped := e.windowParts(query.Window)

	if end.IsZero() || end.After(window.Until) {
		end = window.Until
	}

	for until := end; ; {
		from := until.Add(-e.partLength())
		if from.Before(window.From) {
			from = window.From
		}

		result := e.readStreams(ctx, query, window, supportops.Window{From: from, Until: until}, limit, queries, clipped)
		if !from.After(window.From) || result.Failed || result.OverByteBound || holdsLines(result.Streams) {
			result.Report.Coverage.Until = supportops.TimePointer(end)

			return result
		}

		until = from
	}
}

// readStreams runs the log queries over one part within the source timeout; clipped states a clipped window.
func (e *Engine) readStreams(ctx context.Context, query supportops.Query, window supportops.Window, part supportops.Window,
	limit int, queries []string, clipped bool) StreamsResult {
	ctx, cancel := context.WithTimeout(ctx, e.spec.Timeout)
	defer cancel()

	collection := newCollection(e, query, window)

	if clipped {
		collection.degrade(supportops.SourceStatusPartial, e.code("WINDOW_CLIPPED"))
	}

	result := StreamsResult{Streams: make([][]Stream, len(queries)), Window: window, ReadFrom: part.From}
	overBound := make([]bool, len(queries))
	failed := make([]bool, len(queries))

	var wait sync.WaitGroup

	for index, text := range queries {
		wait.Go(func() {
			streams, err := e.client.Streams(ctx, text, part.From, part.Until, limit)

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

	result.OverByteBound, result.Failed = slices.Contains(overBound, true), slices.Contains(failed, true)

	if !slices.Contains(failed, false) {
		collection.escalate()
	}

	result.Report = collection.report(nil, part)

	return result
}

// holdsLines reports whether any stream of any query holds a line.
func holdsLines(results [][]Stream) bool {
	for _, streams := range results {
		for _, stream := range streams {
			if len(stream.Entries) > 0 {
				return true
			}
		}
	}

	return false
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

	_, window, _ := e.windowParts(query.Window)
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
