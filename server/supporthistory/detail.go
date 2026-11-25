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

package supporthistory

import (
	"context"
	"slices"
	"time"
)

// attemptLookup is the validated input of one attempt detail lookup.
type attemptLookup struct {
	around  time.Time
	subject Subject
	key     AttemptKey
	events  eventsSelection
	bound   bool
}

// queriedAt returns the query time of a lookup: the frozen time of an events cursor, else now.
func (l attemptLookup) queriedAt(now time.Time) time.Time {
	if l.events.queriedAt != nil {
		return *l.events.queriedAt
	}

	return now
}

// GetAttempt returns one attempt with one page of its recorded events; events_page continues the events. When the
// caller names a subject, the attempt is returned only when one of its rows belongs to that subject; a guessed id
// yields the same null answer as an unknown one.
func (s *Service) GetAttempt(ctx context.Context, caller Caller, request AttemptDetailRequest) (*AttemptDetailResult, error) {
	var (
		lookup  attemptLookup
		subject Subject
	)

	if request.Subject != nil {
		subject = *request.Subject
	}

	validate := func() *Error {
		parsed, keyErr := parseAttemptID(request.AttemptID)
		if keyErr != nil {
			return keyErr
		}

		lookup.key = parsed

		if err := request.validate(); err != nil {
			return err
		}

		selection, err := request.eventsSelection()
		lookup.events = selection

		return err
	}

	ctx, call, err := s.begin(ctx, caller, operationAttemptDetail, permissionHistoryRead,
		[]string{subject.Login, subject.Account}, request.AuditReference, validate)
	if err != nil {
		return nil, err
	}

	if request.Subject != nil {
		lookup.subject = *request.Subject
	}

	lookup.around, lookup.bound = request.Around.UTC(), request.Subject != nil

	result, detailErr := s.getAttempt(ctx, lookup)
	if detailErr != nil {
		call.finish(ctx, 0, detailErr)

		return nil, detailErr
	}

	results := 0
	if result.Attempt != nil {
		results = 1
	}

	call.finish(ctx, results, nil)

	return result, nil
}

// getAttempt reads, binds, and builds one attempt. A continuation keeps the query time of its cursor, so every page
// reads the same range and derives the same attempt-level members.
func (s *Service) getAttempt(ctx context.Context, lookup attemptLookup) (*AttemptDetailResult, *Error) {
	queriedAt, around, key := lookup.queriedAt(s.now().UTC()), lookup.around, lookup.key
	window := Window{From: around.Add(-widenedAttemptMargin), Until: minTime(around.Add(widenedAttemptMargin), queriedAt)}

	result := &AttemptDetailResult{SchemaVersion: SchemaVersion, QueriedAt: queriedAt}

	var matcher subjectMatcher

	if lookup.bound {
		resolution, accounts, err := subjectResolver{identity: s.identity, attempts: s.attempts}.resolve(ctx,
			lookup.subject, window, false)
		if err != nil {
			return nil, mapStoreError(ctx, err)
		}

		result.SubjectResolution = &resolution
		matcher = newSubjectMatcher(lookup.subject.Login, accounts, AttemptFilter{})
	}

	rows, err := s.fetchWithWidening(ctx, []AttemptKey{key}, around, around, queriedAt, nil)
	if err != nil {
		return nil, mapStoreError(ctx, err)
	}

	rows.boundedGroups()

	eventsRead := sourceRead{source: SourceAuthEvents, retention: eventRetention,
		queried: rows.eventSource.queried, failed: rows.eventSource.failed}
	logins, events := rows.logins[key], rows.events[key]

	if lookup.bound {
		matcher = matcher.withRecordedAccounts(lookup.subject.Login, logins)
	}

	cutover := s.completionCutoverAt(ctx, window.Until)

	if (len(logins) > 0 || len(events) > 0) && (!lookup.bound || belongsToSubject(matcher, logins, events)) {
		input := attemptInput{key: key, logins: logins, events: events, matcher: matcher, read: rows.ranges[key],
			eventsRead: eventsRead.failed == nil, queriedAt: queriedAt, completionSince: cutover.since}

		attempt, buildErr := s.detailAttempt(ctx, input, lookup)
		if buildErr != nil {
			return nil, mapStoreError(ctx, buildErr)
		}

		result.Attempt = attempt
	}

	var attempts []Attempt
	if result.Attempt != nil {
		attempts = []Attempt{*result.Attempt}
	}

	result.History = s.attemptCoverage(ctx, window, queriedAt, eventsRead, cutover, attempts)
	result.ResultBasis = resultBasis(result.Attempt != nil, result.History, SourceLogins, false)

	return result, nil
}

// detailAttempt builds the attempt of a detail lookup with its selected events page; a continuation reads the page
// rows after the cursor position separately from the interpretation rows.
func (s *Service) detailAttempt(ctx context.Context, input attemptInput, lookup attemptLookup) (*Attempt, error) {
	input.listing = eventListing{after: lookup.events.after, limit: lookup.events.limit}

	if after := lookup.events.after; after != nil {
		rows, err := s.fetchEventsPage(ctx, input.key, input.read, *after, lookup.events.limit)
		if err != nil {
			return nil, err
		}

		input.listing.rows = rows
	}

	attempt, next := buildAttempt(input)
	attachEventsPage(&attempt, next, AttemptReference{AttemptID: attempt.AttemptID, Around: lookup.around},
		input.queriedAt, lookup.events.limit, lookup.events.requested)

	return &attempt, nil
}

// belongsToSubject binds an attempt to the named subject through any of its rows.
func belongsToSubject(matcher subjectMatcher, logins []LoginRecord, events []AuthEventRecord) bool {
	return slices.ContainsFunc(logins, func(record LoginRecord) bool {
		matched, _ := matcher.identityOfLogin(record)

		return matched
	}) || slices.ContainsFunc(events, func(record AuthEventRecord) bool {
		matched, _ := matcher.identityOfEvent(record)

		return matched
	})
}

// attemptCoverage builds the coverage block of attempt answers from source presence and the reads of this call.
func (s *Service) attemptCoverage(ctx context.Context, window Window, queriedAt time.Time, eventsRead sourceRead,
	cutover completionCutover, attempts []Attempt) Coverage {
	logins := sourceRead{source: SourceLogins, retention: loginRetention, queried: true,
		presence: s.attempts.Presence(ctx, SourceLogins)}

	eventsRead.source, eventsRead.retention, eventsRead.queried = SourceAuthEvents, eventRetention, true
	eventsRead.presence = s.attempts.Presence(ctx, SourceAuthEvents)

	since, known := s.attempts.ContractRowsSince(ctx, window.From, minTime(window.Until, queriedAt))
	legacy := slices.ContainsFunc(attempts, func(attempt Attempt) bool { return attempt.Recording.LegacyRows > 0 })

	coverage := buildCoverage(coverageInput{now: queriedAt, window: window, deployment: s.attempts.Deployment(),
		reads: []sourceRead{logins, eventsRead}, contractSince: since, contractKnown: known,
		limits: attemptLimits(cutover), legacyRows: legacy, conditions: cutover.conditions()})
	coverage.CompletionEventsSince = cutover.since

	return coverage
}
