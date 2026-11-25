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
	"context"
	"time"

	"github.com/croessner/nauthilus/v4/server/supportaccess"
	"github.com/croessner/nauthilus/v4/server/supportops"
	"github.com/croessner/nauthilus/v4/server/supportops/windowsource"
)

// tieCursor is the progress through a run of equal timestamps: the stream index in stream key order and the lines
// already done from that stream on. Done lines spill over into the following streams, so lines a normal page returned
// across streams and lines done inside one stream are the same kind of progress.
type tieCursor struct {
	stream  int
	pending int
}

// tieEvents pages the run of lines at exactly at stream by stream: the streams with data at that time come from the
// stream listing in stream key order, and each stream's run is read whole and sorted by line, so the order equals the
// normal order. A stream whose run no read can return is a stated gap, and paging continues with the next stream.
func (s *Source) tieEvents(ctx context.Context, query supportops.LogEventsQuery, at time.Time) supportops.LogEventsSourceResult {
	listed := s.CollectSeries(ctx, supportops.Query{Window: query.Window, Now: query.Now}, s.selector, at, at.Add(time.Nanosecond))
	if listed.Report.Status != supportops.SourceStatusOK && !listed.Report.Truncated {
		return unlistedRun(listed.Report, at, query.Limit)
	}

	streams := s.instanceStreams(listed.Streams, query.Instance)

	cursor, ok := tieStart(query.Position, at, streams)
	if !ok {
		return failedEvents(listed.Report, "_STREAMS_CHANGED")
	}

	result := s.pageRun(ctx, query, at, streams, cursor, listed.Report)
	if listed.Report.Truncated && result.Next != nil && result.Next.Exclusive {
		result.Gaps = append(result.Gaps, supportops.LogGap{At: at, Labels: map[string]string{}, Reason: gapStreamsExceedListing})
	}

	return s.finishRun(result)
}

// unlistedRun states a run whose streams cannot be listed as one gap at its time and continues before it, so a failed
// listing never ends the paging without a cursor.
func unlistedRun(report supportops.SourceReport, at time.Time, limit int) supportops.LogEventsSourceResult {
	report.Status, report.Code = supportops.SourceStatusPartial, codePrefix+"_STREAMS_UNLISTED"

	return supportops.LogEventsSourceResult{Report: report, Lines: []supportops.LogLine{}, LimitApplied: limit, More: true,
		Gaps: []supportops.LogGap{{At: at, Labels: map[string]string{}, Reason: gapStreamsUnlisted}},
		Next: &supportops.LogPosition{Before: at, Exclusive: true}}
}

// instanceStreams keeps the listed streams of the requested instance, or all of them without an instance filter.
func (s *Source) instanceStreams(streams []map[string]string, instance string) []map[string]string {
	if instance == "" {
		return streams
	}

	kept := make([]map[string]string, 0, len(streams))

	for _, labels := range streams {
		if labels[s.instanceLabel] == instance {
			kept = append(kept, labels)
		}
	}

	return kept
}

// tieStart turns a position into run progress. A position inside the run must name the same stream at its index; a
// position from a normal page carries lines done across streams.
func tieStart(position supportops.LogPosition, at time.Time, streams []map[string]string) (tieCursor, bool) {
	switch {
	case !position.Before.Equal(at) || position.Exclusive:
		return tieCursor{}, true
	case position.StreamDigest == "":
		return tieCursor{pending: position.Skip}, true
	case position.StreamIndex < 0 || position.StreamIndex >= len(streams):
		return tieCursor{}, false
	default:
		return tieCursor{stream: position.StreamIndex, pending: position.Skip},
			streamDigest(streams[position.StreamIndex]) == position.StreamDigest
	}
}

// streamDigest identifies a stream in a cursor without carrying its labels.
func streamDigest(labels map[string]string) string {
	return supportaccess.QueryDigest(windowsource.StreamKey(labels))
}

// pageRun collects one page from the streams of the run, starting at cursor, reading at most streamsPerTiePage
// streams. Lines already done spill over stream by stream; a page boundary or a failed read keeps the rest of them in
// the next position, so no line is repeated or skipped. A gap stream cannot consume done lines, so a pending count
// that reaches one is dropped and the page states it (lines may then repeat, never vanish).
func (s *Source) pageRun(ctx context.Context, query supportops.LogEventsQuery, at time.Time, streams []map[string]string,
	cursor tieCursor, report supportops.SourceReport) supportops.LogEventsSourceResult {
	result := supportops.LogEventsSourceResult{Report: report, LimitApplied: query.Limit, Lines: []supportops.LogLine{}, More: true}
	pending := cursor.pending

	for index := cursor.stream; index < len(streams); index++ {
		if index-cursor.stream == streamsPerTiePage {
			result.Next = runPosition(at, index, streams, pending)

			return result
		}

		lines, gap, failed := s.streamRun(ctx, query, at, streams[index])

		switch {
		case failed != nil:
			result.Report, result.Next = *failed, runPosition(at, index, streams, pending)

			return result
		case gap != "":
			result.Gaps = append(result.Gaps, supportops.LogGap{At: at, Labels: supportops.SanitizeLabels(streams[index]), Reason: gap})

			if pending > 0 {
				pending = 0
				result.Report.Code = codePrefix + "_RUN_POSITION_RESET"
			}

			continue
		}

		start := min(pending, len(lines))
		pending -= start

		taken := lines[start:min(len(lines), start+query.Limit-len(result.Lines))]
		result.Lines = append(result.Lines, taken...)

		if len(result.Lines) == query.Limit {
			result.Next = runPosition(at, index, streams, start+len(taken))

			return result
		}
	}

	result.Next = &supportops.LogPosition{Before: at, Exclusive: true}

	return result
}

// runPosition is the position at a stream of the run after skip of its lines.
func runPosition(at time.Time, index int, streams []map[string]string, skip int) *supportops.LogPosition {
	return &supportops.LogPosition{Before: at, StreamIndex: index, StreamDigest: streamDigest(streams[index]), Skip: skip}
}

// finishRun states the instances of the page and marks a page with gaps partial.
func (s *Source) finishRun(result supportops.LogEventsSourceResult) supportops.LogEventsSourceResult {
	result.Report.Coverage.Instances = lineInstances(result.Lines)

	if len(result.Gaps) > 0 && result.Report.Status == supportops.SourceStatusOK {
		result.Report.Status = supportops.SourceStatusPartial

		if result.Report.Code == "" {
			result.Report.Code = codePrefix + "_GAPS"
		}
	}

	return result
}

// streamRun reads every line of one stream at exactly at, sorted by line. It returns a gap reason when one read cannot
// return the whole run, or the failed report of an unreadable stream.
func (s *Source) streamRun(ctx context.Context, query supportops.LogEventsQuery, at time.Time,
	labels map[string]string) ([]supportops.LogLine, string, *supportops.SourceReport) {
	queries := make([]string, 0, len(logFormats))

	for _, format := range logFormats {
		queries = append(queries, streamSelector(labels)+parserStages(format, levelAlternation(query.Levels))+s.messageStage(query))
	}

	run := supportops.Query{Window: supportops.Window{From: at, Until: at.Add(time.Nanosecond)}, Now: query.Now}
	collected := s.CollectStreams(ctx, run, time.Time{}, supportops.MaxLogEventRead, queries)

	switch {
	case collected.OverByteBound:
		return nil, gapLinesExceedByteBound, nil
	case collected.Report.Status != supportops.SourceStatusOK:
		return nil, "", &collected.Report
	}

	lines, _, cut := s.readLines(collected.Streams, supportops.MaxLogEventRead)
	if cut {
		return nil, gapStreamRunExceedsRead, nil
	}

	return lines, "", nil
}
