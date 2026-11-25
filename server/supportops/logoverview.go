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

package supportops

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/croessner/nauthilus/v4/server/supportaccess"
)

// LogOverview answers one log overview request: the messages the log source counted inside the window at the
// requested levels, one group per level and exact message, in pages. Every call is audited, including denied and
// invalid ones.
func (s *Service) LogOverview(ctx context.Context, caller Caller, request LogOverviewRequest) (*LogOverviewResult, error) {
	return serve(ctx, s, caller, operationLogOverview, request.AuditReference, func(ctx context.Context, now time.Time) (*LogOverviewResult, int, *Error) {
		plan, err := planLogOverview(request, now)
		if err != nil {
			return nil, 0, err
		}

		ctx, done, err := s.admit(ctx, caller)
		if err != nil {
			return nil, 0, err
		}

		defer done()

		result, err := s.logOverview(ctx, plan, now)
		if err != nil {
			return nil, 0, err
		}

		return result, len(result.Messages), nil
	})
}

// logOverview asks the log source and assembles one page of the answer; a missing source is reported, never an
// error. A cursor beyond the groups of the current answer is invalid.
func (s *Service) logOverview(ctx context.Context, plan logOverviewPlan, now time.Time) (*LogOverviewResult, *Error) {
	sourceResult := LogOverviewSourceResult{Report: SourceReport{Status: SourceStatusNotConfigured}}

	if source, ok := s.sources[SourceLoki].(LogOverviewSource); ok {
		sourceResult = source.LogOverview(ctx, LogOverviewQuery{Window: plan.window, Now: now, Levels: plan.levels})
	}

	sourceResult.Report.settle(ctx, SourceLoki, SourceKindHistorical)

	groups := groupLogSeries(sourceResult.Series, sourceResult.Buckets)
	if plan.page.offset > len(groups) {
		return nil, newError(CodeInvalidCursor, nil)
	}

	result := &LogOverviewResult{SchemaVersion: SchemaVersion, Source: sourceResult.Report,
		Scope:   ResultScope{Window: plan.window, QueriedAt: now.UTC(), Deployment: s.deployment, Instance: s.instance},
		Buckets: append([]Window{}, sourceResult.Buckets...), BucketSeconds: bucketSeconds(sourceResult.Buckets)}

	result.Messages, result.Page = pageLogGroups(groups, plan.page)
	result.Notes = logOverviewNotes(result)

	return result, nil
}

// bucketSeconds returns the width of the grid buckets, or 0 without a grid.
func bucketSeconds(buckets []Window) int64 {
	if len(buckets) == 0 {
		return 0
	}

	return int64(buckets[0].Until.Sub(buckets[0].From) / time.Second)
}

// groupLogSeries merges the series of one level and one exact message across instances; different messages always
// stay apart. The message leaves complete, with authentication secrets replaced.
func groupLogSeries(series []LogSeries, buckets []Window) []LogMessageGroup {
	type groupKey struct{ level, message string }

	index := map[groupKey]int{}
	groups := []LogMessageGroup{}
	instances := []map[string]int64{}

	for _, entry := range series {
		total := sumCounts(entry.Counts)
		if total == 0 || len(entry.Counts) != len(buckets) || !slices.Contains(LogLevels, entry.Level) {
			continue
		}

		key := groupKey{entry.Level, entry.Message}

		position, seen := index[key]
		if !seen {
			position = len(groups)
			index[key] = position
			message, redacted := redactText(supportaccess.VerbatimText(entry.Message))

			groups = append(groups, LogMessageGroup{Level: entry.Level, Message: message, SecretsRedacted: redacted,
				MessageExact: message == entry.Message,
				Status:       StatusObserved, Counts: make([]int64, len(buckets)), Component: entry.Component, Symptom: entry.Symptom})
			instances = append(instances, map[string]int64{})
		}

		group := &groups[position]

		for bucket, count := range entry.Counts {
			group.Counts[bucket] = addCount(group.Counts[bucket], count)
		}

		group.Count = addCount(group.Count, total)
		instance := supportaccess.VerbatimText(entry.Instance)
		instances[position][instance] = addCount(instances[position][instance], total)
	}

	for position := range groups {
		finishLogGroup(&groups[position], instances[position], buckets)
	}

	slices.SortStableFunc(groups, func(left, right LogMessageGroup) int {
		return cmp.Or(cmp.Compare(right.Count, left.Count),
			cmp.Compare(slices.Index(LogLevels, left.Level), slices.Index(LogLevels, right.Level)),
			cmp.Compare(left.Message, right.Message))
	})

	return groups
}

// finishLogGroup sorts the instance counts and states the first and last bucket with a count.
func finishLogGroup(group *LogMessageGroup, instances map[string]int64, buckets []Window) {
	group.Instances = make([]LogInstanceCount, 0, len(instances))

	for instance, count := range instances {
		group.Instances = append(group.Instances, LogInstanceCount{Instance: instance, Count: count})
	}

	slices.SortFunc(group.Instances, func(left, right LogInstanceCount) int {
		return cmp.Or(cmp.Compare(right.Count, left.Count), cmp.Compare(left.Instance, right.Instance))
	})

	for bucket, count := range group.Counts {
		if count == 0 {
			continue
		}

		if group.FirstBucket == nil {
			group.FirstBucket = TimePointer(buckets[bucket].From)
		}

		group.LastBucket = TimePointer(buckets[bucket].Until)
	}
}

// pageLogGroups returns the groups of one page, numbered by their position in the whole answer, and the page state.
func pageLogGroups(groups []LogMessageGroup, page pagePlan) ([]LogMessageGroup, LogPageResult) {
	end := min(page.offset+page.limit, len(groups))
	paged := slices.Clone(groups[page.offset:end])

	for position := range paged {
		paged[position].ID = fmt.Sprintf("L%d", page.offset+position+1)
	}

	result := LogPageResult{Limit: page.limit, Offset: page.offset, Total: len(groups)}

	if end < len(groups) {
		next := page.encode(pageCursor{Offset: end})
		result.NextCursor = &next
	}

	return paged, result
}

// logOverviewNotes explains how to read the overview: observations are not incidents, and every bound, page, and gap
// of the answer is named.
func logOverviewNotes(result *LogOverviewResult) []string {
	notes := []string{NoteValuesAreUntrusted, NoteLogMessagesAreNotIncidents}

	if slices.ContainsFunc(result.Messages, func(group LogMessageGroup) bool { return group.SecretsRedacted }) {
		notes = append(notes, NoteLogSecretsRedacted)
	}

	notes = append(notes, pageNotes(result.Page.NextCursor != nil, result.Page.Offset > 0)...)
	notes = append(notes, logSourceNotes(result.Source)...)

	if from := result.Source.Coverage.From; from != nil && from.Before(result.Scope.Window.From) {
		notes = append(notes, NoteLogBucketsExceedWindow)
	}

	return notes
}

// pageNotes names a continued answer and the requery semantics of every paged answer.
func pageNotes(more bool, continued bool) []string {
	var notes []string

	if more {
		notes = append(notes, NoteLogMorePages)
	}

	if more || continued {
		notes = append(notes, NoteLogPagesRequery)
	}

	return notes
}

// logSourceNotes names a missing, incomplete, or uncovered log source.
func logSourceNotes(report SourceReport) []string {
	switch {
	case isInactive(report):
		return []string{NoteNoHistoricalSource}
	case len(report.Coverage.Instances) == 0 && (report.Status != SourceStatusOK || report.Truncated):
		return []string{NoteHistoricalSourceIncomplete, NoteLogNoCoverage}
	case len(report.Coverage.Instances) == 0:
		return []string{NoteLogNoCoverage}
	case report.Status != SourceStatusOK || report.Truncated:
		return []string{NoteHistoricalSourceIncomplete}
	default:
		return nil
	}
}

// sumCounts sums counts without overflowing.
func sumCounts(counts []int64) int64 {
	var total int64

	for _, count := range counts {
		total = addCount(total, count)
	}

	return total
}

// addCount adds two non-negative counts and saturates at the largest count.
func addCount(left int64, right int64) int64 {
	if right > 0 && left > math.MaxInt64-right {
		return math.MaxInt64
	}

	return left + right
}
