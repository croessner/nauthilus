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
)

// maxLogGroups bounds the message groups of one log overview answer.
const maxLogGroups = 50

// LogOverview answers one log overview request: the warning and error messages the log source counted inside the
// window, grouped by level and normalized message. Every call is audited, including denied and invalid ones.
func (s *Service) LogOverview(ctx context.Context, caller Caller, request LogOverviewRequest) (*LogOverviewResult, error) {
	return serve(ctx, s, caller, operationLogOverview, request.AuditReference, func(ctx context.Context, now time.Time) (*LogOverviewResult, int, *Error) {
		window, levels, err := planLogOverview(request, now)
		if err != nil {
			return nil, 0, err
		}

		ctx, done, err := s.admit(ctx, caller)
		if err != nil {
			return nil, 0, err
		}

		defer done()

		result := s.logOverview(ctx, window, levels, now)

		return result, len(result.Messages), nil
	})
}

// logOverview asks the log source and assembles the bounded answer; a missing source is reported, never an error.
func (s *Service) logOverview(ctx context.Context, window Window, levels []string, now time.Time) *LogOverviewResult {
	sourceResult := LogOverviewSourceResult{Report: SourceReport{Status: SourceStatusNotConfigured}}

	if source, ok := s.sources[SourceLoki].(LogOverviewSource); ok {
		sourceResult = source.LogOverview(ctx, LogOverviewQuery{Window: window, Now: now, Levels: levels})
	}

	sourceResult.Report.settle(ctx, SourceLoki, SourceKindHistorical)

	groups := groupLogSeries(sourceResult.Series, sourceResult.Buckets)
	result := &LogOverviewResult{SchemaVersion: SchemaVersion, Source: sourceResult.Report,
		Scope:   ResultScope{Window: window, QueriedAt: now.UTC(), Deployment: s.deployment, Instance: s.instance},
		Buckets: append([]Window{}, sourceResult.Buckets...), BucketSeconds: bucketSeconds(sourceResult.Buckets)}

	result.Messages, result.Omitted = boundLogGroups(groups)
	result.Notes = logOverviewNotes(result, groups)

	return result
}

// bucketSeconds returns the width of the grid buckets, or 0 without a grid.
func bucketSeconds(buckets []Window) int64 {
	if len(buckets) == 0 {
		return 0
	}

	return int64(buckets[0].Until.Sub(buckets[0].From) / time.Second)
}

// groupLogSeries normalizes every series message and merges series of the same level and normalized message.
// A profiled symptom survives only when every merged series is the literal message of that symptom.
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

		message, form := normalizeLogMessage(entry.Message)
		key := groupKey{entry.Level, message}

		position, seen := index[key]
		if !seen {
			position = len(groups)
			index[key] = position

			groups = append(groups, LogMessageGroup{Level: entry.Level, Message: message, MessageForm: form,
				Status: StatusObserved, Counts: make([]int64, len(buckets)), Component: entry.Component, Symptom: entry.Symptom})
			instances = append(instances, map[string]int64{})
		}

		group := &groups[position]
		if form != MessageFormLiteral {
			group.MessageForm = MessageFormNormalized
		}

		if form != MessageFormLiteral || group.Symptom != entry.Symptom {
			group.Component, group.Symptom = "", ""
		}

		for bucket, count := range entry.Counts {
			group.Counts[bucket] = addCount(group.Counts[bucket], count)
		}

		group.Count = addCount(group.Count, total)
		instances[position][entry.Instance] = addCount(instances[position][entry.Instance], total)
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

// boundLogGroups keeps the first maxLogGroups groups, numbers them, and states what was left out.
func boundLogGroups(groups []LogMessageGroup) ([]LogMessageGroup, LogOmission) {
	var omitted LogOmission

	if len(groups) > maxLogGroups {
		for _, group := range groups[maxLogGroups:] {
			omitted.Groups++
			omitted.Lines = addCount(omitted.Lines, group.Count)
		}

		groups = groups[:maxLogGroups]
	}

	for position := range groups {
		groups[position].ID = fmt.Sprintf("L%d", position+1)
	}

	return groups, omitted
}

// logOverviewNotes explains how to read the overview: observations are not incidents, and every bound or gap of the
// answer is named.
func logOverviewNotes(result *LogOverviewResult, groups []LogMessageGroup) []string {
	notes := []string{NoteValuesAreUntrusted, NoteLogMessagesAreNotIncidents}

	if slices.ContainsFunc(groups, func(group LogMessageGroup) bool { return group.MessageForm == MessageFormNormalized }) {
		notes = append(notes, NoteLogMessagesNormalized)
	}

	if result.Omitted.Groups > 0 {
		notes = append(notes, NoteLogGroupsOmitted)
	}

	switch {
	case isInactive(result.Source):
		notes = append(notes, NoteNoHistoricalSource)
	case result.Source.Status != SourceStatusOK || result.Source.Truncated:
		notes = append(notes, NoteHistoricalSourceIncomplete)
	}

	if !isInactive(result.Source) && len(result.Source.Coverage.Instances) == 0 {
		notes = append(notes, NoteLogNoCoverage)
	}

	if from := result.Source.Coverage.From; from != nil && from.Before(result.Scope.Window.From) {
		notes = append(notes, NoteLogBucketsExceedWindow)
	}

	return notes
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
