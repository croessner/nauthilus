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

package lokisource

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/supportops"
	"github.com/croessner/nauthilus/v4/server/supportops/windowsource"
)

// Gap reasons of the log events.
const (
	// gapStreamRunExceedsRead is one stream with more lines at one timestamp than one Loki read returns.
	gapStreamRunExceedsRead = "STREAM_RUN_EXCEEDS_READ"

	// gapLinesExceedByteBound is one stream whose lines at one timestamp exceed the source byte bound.
	gapLinesExceedByteBound = "LINES_EXCEED_SOURCE_BYTE_BOUND"

	// gapStreamsExceedListing is the part of a run in streams beyond the stream listing bound.
	gapStreamsExceedListing = "STREAMS_EXCEED_LISTING_BOUND"

	// gapStreamsUnlisted is a run whose streams the stream listing could not return.
	gapStreamsUnlisted = "STREAMS_UNLISTED"

	// streamsPerTiePage bounds the streams one page of a large run reads.
	streamsPerTiePage = 16
)

// LogEvents returns one page of stored log lines of the requested levels in the stable order (newest first, then
// stream key, then line), optionally of one instance and one exact message. Caller filters reach the query only as
// quoted LogQL strings. A page only ends inside a run of equal timestamps when every line of that run was read; a run
// larger than one read is paged stream by stream. When an answer exceeds the byte bound, the read shrinks instead, so
// a page never loses a line silently, and a part no read can return is a stated gap.
func (s *Source) LogEvents(ctx context.Context, query supportops.LogEventsQuery) supportops.LogEventsSourceResult {
	if query.Position.StreamDigest != "" || query.Position.StreamIndex > 0 {
		return s.tieEvents(ctx, query, query.Position.Before)
	}

	queries := s.eventQueries(query)
	skip := s.normalSkip(query.Position)
	read := eventRead{fetch: min(skip+query.Limit+1, supportops.MaxLogEventRead), floor: skip + 2}

	for {
		collected := s.CollectStreams(ctx, supportops.Query{Window: query.Window, Now: query.Now}, normalEnd(query.Position),
			read.fetch, queries)

		if collected.OverByteBound {
			if !read.shrink() {
				return s.probedEvents(ctx, query, skip)
			}

			continue
		}

		result, complete, runAt := s.pageLines(collected, query, read)
		if complete {
			return continuePart(result, collected)
		}

		if !read.grow() {
			if read.shrunk {
				return s.probedEvents(ctx, query, skip)
			}

			return s.tieEvents(ctx, query, runAt)
		}
	}
}

// continuePart continues a page whose read covered only the newest part of the window: when the page holds every
// line the read returned and older parts remain, the next page reads before the part start. Lines at exactly the
// part start belonged to the read part, so the position is exclusive. A part of which nothing could be read
// (unavailable or timed out) is never passed over, so the same request can be repeated; a part with one failed log
// format continues like before, and its page states partial.
func continuePart(result supportops.LogEventsSourceResult, collected windowsource.StreamsResult) supportops.LogEventsSourceResult {
	status := result.Report.Status
	if result.More || !collected.ReadFrom.After(collected.Window.From) || status == supportops.SourceStatusUnavailable ||
		status == supportops.SourceStatusTimeout {
		return result
	}

	result.More, result.Next = true, &supportops.LogPosition{Before: collected.ReadFrom, Exclusive: true}

	return result
}

// probeLine replaces every line of a probe read, so the read returns only times and streams.
const probeLine = ` | line_format "-"`

// probedEvents handles a position where even the smallest read exceeds the byte bound. Inside a run (lines at Before
// already returned) the run is read stream by stream right away; otherwise a probe read without line texts finds the
// time of the next line, and the run at that time is read stream by stream. An oversized stream becomes a stated gap
// and paging continues after it. The probe only asks for the newest time, so merged or deduplicated probe lines
// cannot shift a position.
func (s *Source) probedEvents(ctx context.Context, query supportops.LogEventsQuery, skip int) supportops.LogEventsSourceResult {
	if skip > 0 {
		return s.tieEvents(ctx, query, query.Position.Before)
	}

	queries := s.eventQueries(query)
	for index := range queries {
		queries[index] += probeLine
	}

	collected := s.CollectStreams(ctx, supportops.Query{Window: query.Window, Now: query.Now}, normalEnd(query.Position), 1, queries)
	if collected.OverByteBound || collected.Report.Status != supportops.SourceStatusOK {
		return failedEvents(collected.Report, "_RESULT_TRUNCATED")
	}

	lines, _, _ := s.readLines(collected.Streams, supportops.MaxLogEventRead+1)
	if len(lines) == 0 {
		return supportops.LogEventsSourceResult{Report: collected.Report, Lines: []supportops.LogLine{}, LimitApplied: query.Limit}
	}

	return s.tieEvents(ctx, query, lines[0].At)
}

// normalSkip returns the lines at exactly Before that earlier pages returned, or 0 for an exclusive position.
func (s *Source) normalSkip(position supportops.LogPosition) int {
	if position.Exclusive || position.Before.IsZero() {
		return 0
	}

	return position.Skip
}

// normalEnd returns the exclusive end of a normal read: the window end, just after Before, or Before itself once
// every line at Before is done.
func normalEnd(position supportops.LogPosition) time.Time {
	switch {
	case position.Before.IsZero():
		return time.Time{}
	case position.Exclusive:
		return position.Before
	default:
		return position.Before.Add(time.Nanosecond)
	}
}

// eventRead is the size of one log read: fetch lines per query, never below floor (the skipped lines plus one line
// and one look-ahead line). A read that shrank for the byte bound never grows again.
type eventRead struct {
	fetch  int
	floor  int
	shrunk bool
}

// shrink halves the read for the byte bound and reports whether a smaller read is left.
func (r *eventRead) shrink() bool {
	if r.fetch <= r.floor {
		return false
	}

	r.fetch, r.shrunk = max(r.fetch/2, r.floor), true

	return true
}

// grow doubles the read for a run of equal timestamps and reports whether a larger read is allowed.
func (r *eventRead) grow() bool {
	if r.shrunk || r.fetch >= supportops.MaxLogEventRead {
		return false
	}

	r.fetch = min(r.fetch*2, supportops.MaxLogEventRead)

	return true
}

// failedEvents reports a page that cannot be read within the source bounds; no line and no cursor are returned.
func failedEvents(report supportops.SourceReport, code string) supportops.LogEventsSourceResult {
	report.Status, report.Code, report.Truncated = supportops.SourceStatusPartial, codePrefix+code, true

	return supportops.LogEventsSourceResult{Report: report, Lines: []supportops.LogLine{}}
}

// eventQueries returns one log query per log format with the level, instance, and message filters. The instance is a
// label filter stage after the fixed selector, so it can only narrow the operator's selector, never replace it.
func (s *Source) eventQueries(query supportops.LogEventsQuery) []string {
	filters := ""

	if query.Instance != "" {
		filters = " | " + s.instanceLabel + "=" + strconv.Quote(query.Instance)
	}

	alternation := levelAlternation(query.Levels)
	queries := make([]string, 0, len(logFormats))

	for _, format := range logFormats {
		queries = append(queries, s.selector+filters+parserStages(format, alternation)+s.messageStage(query))
	}

	return queries
}

// messageStage returns the exact message filter of a query, or none.
func (s *Source) messageStage(query supportops.LogEventsQuery) string {
	if query.Message == nil {
		return ""
	}

	return " | " + overviewMessageLabel + "=" + strconv.Quote(*query.Message)
}

// readLines flattens the streams of every query into lines in the stable order, so pages are stable. The labels the parser stages added are dropped. A query that returned a full read may hold more
// lines at or before its oldest time, so only lines newer than the latest such cut are certain to be complete; cut
// reports whether any query was full and safeAfter the time a line must be newer than.
func (s *Source) readLines(results [][]windowsource.Stream, fetch int) (lines []supportops.LogLine, safeAfter time.Time, cut bool) {
	for _, streams := range results {
		count := 0
		oldest := time.Time{}

		for _, stream := range streams {
			labels := maps.Clone(stream.Labels)
			delete(labels, overviewLevelLabel)
			delete(labels, overviewMessageLabel)

			key := windowsource.StreamKey(labels)

			for _, entry := range stream.Entries {
				lines = append(lines, supportops.LogLine{At: entry.At, Labels: labels, Instance: labels[s.instanceLabel],
					Stream: key, Line: entry.Line})
				count++

				if oldest.IsZero() || entry.At.Before(oldest) {
					oldest = entry.At
				}
			}
		}

		if count >= fetch && oldest.After(safeAfter) {
			safeAfter, cut = oldest, true
		} else if count >= fetch {
			cut = true
		}
	}

	sortLines(lines)

	if cut {
		lines = slices.DeleteFunc(lines, func(line supportops.LogLine) bool { return !line.At.After(safeAfter) })
	}

	return lines, safeAfter, cut
}

// pageLines skips the lines earlier pages returned at exactly Before, keeps one page of the complete lines, and states
// the position of the next page. complete is false when the read was too small to return any line although more may
// follow; runAt is then the time of the run the read cut.
func (s *Source) pageLines(collected windowsource.StreamsResult, query supportops.LogEventsQuery, read eventRead) (supportops.LogEventsSourceResult, bool, time.Time) {
	lines, safeAfter, cut := s.readLines(collected.Streams, read.fetch)
	start := pageStart(lines, query.Position, s.normalSkip(query.Position))

	limit := max(min(query.Limit, read.fetch-s.normalSkip(query.Position)-1), 1)

	remaining := lines[start:]
	page := slices.Clone(remaining[:min(limit, len(remaining))])
	more := cut || len(remaining) > len(page)

	if more && len(page) == 0 {
		return supportops.LogEventsSourceResult{}, false, safeAfter
	}

	result := supportops.LogEventsSourceResult{Report: collected.Report, LimitApplied: limit, More: more, Lines: page}
	if more {
		result.Next = nextPosition(page, query)
	}

	result.Report.Coverage.Instances = lineInstances(page)

	return result, true, time.Time{}
}

// pageStart returns the index of the first line after Before and the skip lines earlier pages returned at Before.
func pageStart(lines []supportops.LogLine, position supportops.LogPosition, skip int) int {
	start := 0

	if position.Before.IsZero() {
		return start
	}

	for start < len(lines) && lines[start].At.After(position.Before) {
		start++
	}

	for skipped := 0; skipped < skip && start < len(lines) && lines[start].At.Equal(position.Before); skipped++ {
		start++
	}

	return start
}

// sortLines orders lines newest first, then by stream key, then by line, a unique order for distinct lines.
func sortLines(lines []supportops.LogLine) {
	slices.SortFunc(lines, func(left, right supportops.LogLine) int {
		return cmp.Or(right.At.Compare(left.At), strings.Compare(left.Stream, right.Stream), strings.Compare(left.Line, right.Line))
	})
}

// lineInstances returns the distinct instances of the lines in order.
func lineInstances(lines []supportops.LogLine) []string {
	instances := []string{}

	for _, line := range lines {
		if instance := windowsource.InstanceName(line.Instance); !slices.Contains(instances, instance) {
			instances = append(instances, instance)
		}
	}

	slices.Sort(instances)

	return instances
}

// nextPosition continues after the last line of the page: before its time plus the lines already returned at
// exactly that time, including those of earlier pages.
func nextPosition(page []supportops.LogLine, query supportops.LogEventsQuery) *supportops.LogPosition {
	last := page[len(page)-1].At
	skip := 0

	for _, line := range page {
		if line.At.Equal(last) {
			skip++
		}
	}

	if position := query.Position; last.Equal(position.Before) && !position.Exclusive {
		skip += position.Skip
	}

	return &supportops.LogPosition{Before: last, Skip: skip}
}
