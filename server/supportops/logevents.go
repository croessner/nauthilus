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
	"context"
	"slices"
	"time"
	"unicode/utf8"
)

// LogEvents answers one log events request: the stored log lines of the window at the requested levels, newest
// first, in pages, with every field complete except authentication secrets. Every call is audited, including denied
// and invalid ones.
func (s *Service) LogEvents(ctx context.Context, caller Caller, request LogEventsRequest) (*LogEventsResult, error) {
	return serve(ctx, s, caller, operationLogEvents, request.AuditReference, func(ctx context.Context, now time.Time) (*LogEventsResult, int, *Error) {
		plan, err := planLogEvents(request, now)
		if err != nil {
			return nil, 0, err
		}

		ctx, done, err := s.admit(ctx, caller)
		if err != nil {
			return nil, 0, err
		}

		defer done()

		result := s.logEvents(ctx, plan, now)

		return result, len(result.Events), nil
	})
}

// logEventsPlan is a validated log events request.
type logEventsPlan struct {
	message  *string
	window   Window
	levels   []string
	instance string
	page     pagePlan
}

// planLogEvents validates a log events request: window, levels, the bounded instance and message filters, and the
// page bound to all of them.
func planLogEvents(request LogEventsRequest, now time.Time) (logEventsPlan, *Error) {
	window, err := planHeader(request.SchemaVersion, request.AuditReference, pageWindow(request.Window, request.Page), now)
	if err != nil {
		return logEventsPlan{}, err
	}

	levels, ok := planLevels(request.Levels)
	if !ok || !validFilter(request.Instance, maxInstanceFilterRunes) ||
		(request.Message != nil && (*request.Message == "" || !validFilter(*request.Message, maxMessageFilterRunes))) {
		return logEventsPlan{}, newError(CodeInvalidRequest, nil)
	}

	parts := append([]string{operationLogEvents, request.Instance, messageKey(request.Message)}, levels...)

	page, err := planPage(request.Page, DefaultLogEventPageLimit, MaxLogEventPageLimit, window, parts...)
	if err != nil {
		return logEventsPlan{}, err
	}

	return logEventsPlan{message: request.Message, window: window, levels: levels, instance: request.Instance, page: page}, nil
}

// validFilter accepts valid UTF-8 of at most maxRunes runes; an empty filter means none.
func validFilter(value string, maxRunes int) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) <= maxRunes
}

// messageKey renders the optional message filter for a query digest; an absent filter differs from every message.
func messageKey(message *string) string {
	if message == nil {
		return "\x00none"
	}

	return "=" + *message
}

// logEvents asks the log source for one page and assembles the answer; a missing source is reported, never an error.
func (s *Service) logEvents(ctx context.Context, plan logEventsPlan, now time.Time) *LogEventsResult {
	query := LogEventsQuery{Window: plan.window, Now: now, Levels: plan.levels, Instance: plan.instance, Message: plan.message,
		Position: plan.page.position(), Limit: plan.page.limit}

	sourceResult := LogEventsSourceResult{Report: SourceReport{Status: SourceStatusNotConfigured}}

	if source, ok := s.sources[SourceLoki].(LogEventsSource); ok {
		sourceResult = source.LogEvents(ctx, query)
	}

	sourceResult.Report.settle(ctx, SourceLoki, SourceKindHistorical)

	result := &LogEventsResult{SchemaVersion: SchemaVersion, Source: sourceResult.Report, Events: make([]LogEvent, 0, len(sourceResult.Lines)),
		Scope:  ResultScope{Window: plan.window, QueriedAt: now.UTC(), Deployment: s.deployment, Instance: s.instance},
		Filter: LogEventsFilter{Levels: plan.levels, Instance: plan.instance, Message: plan.message},
		Page:   LogEventsPage{Limit: plan.page.limit, LimitApplied: sourceResult.LimitApplied},
		Gaps:   append([]LogGap{}, sourceResult.Gaps...)}

	for _, line := range sourceResult.Lines {
		result.Events = append(result.Events, logEventOf(line))
	}

	if next := sourceResult.Next; sourceResult.More && next != nil {
		cursor := plan.page.encode(positionCursor(*next))
		result.Page.NextCursor = &cursor
	}

	result.Notes = logEventNotes(result, plan.page.cursorGiven)

	return result
}

// logEventNotes explains how to read the events: observations are not incidents, and every page, bound, and gap is
// named.
func logEventNotes(result *LogEventsResult, continued bool) []string {
	notes := []string{NoteValuesAreUntrusted, NoteLogMessagesAreNotIncidents}

	if slices.ContainsFunc(result.Events, func(event LogEvent) bool {
		return event.SecretsRedacted || len(event.RedactedFields) > 0
	}) {
		notes = append(notes, NoteLogSecretsRedacted)
	}

	if result.Page.LimitApplied > 0 && result.Page.LimitApplied < result.Page.Limit {
		notes = append(notes, NoteLogPageReducedBySourceLimit)
	}

	notes = append(notes, pageNotes(result.Page.NextCursor != nil, continued)...)

	switch {
	case isInactive(result.Source):
		notes = append(notes, NoteNoHistoricalSource)
	case result.Source.Status != SourceStatusOK || result.Source.Truncated:
		notes = append(notes, NoteHistoricalSourceIncomplete)
	}

	return notes
}
