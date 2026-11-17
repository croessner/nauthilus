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

// GetAttempt returns every recorded event of one attempt. Support callers must name the subject, and the attempt is
// returned only when one of its rows belongs to that subject; a guessed id yields the same null answer as an unknown
// one.
func (s *Service) GetAttempt(ctx context.Context, caller Caller, request AttemptDetailRequest) (*AttemptDetailResult, error) {
	var (
		key     AttemptKey
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

		key = parsed

		return request.validate(caller)
	}

	ctx, call, err := s.begin(ctx, caller, operationAttemptDetail, permissionAttemptsRead,
		[]string{subject.Login, subject.Account}, request.AuditReference, validate)
	if err != nil {
		return nil, err
	}

	if request.Subject != nil {
		subject = *request.Subject
	}

	result, detailErr := s.getAttempt(ctx, caller, key, subject, request.Around.UTC(), request.Subject != nil)
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

// getAttempt reads, binds, and builds one attempt.
func (s *Service) getAttempt(ctx context.Context, caller Caller, key AttemptKey, subject Subject, around time.Time, bound bool) (*AttemptDetailResult, *Error) {
	queriedAt := s.now().UTC()
	window := Window{From: around.Add(-widenedAttemptMargin), Until: minTime(around.Add(widenedAttemptMargin), queriedAt)}

	result := &AttemptDetailResult{SchemaVersion: SchemaVersion, QueriedAt: queriedAt}

	var matcher subjectMatcher

	if bound {
		resolution, accounts, err := subjectResolver{identity: s.identity, attempts: s.attempts}.resolve(ctx, subject,
			window, false)
		if err != nil {
			return nil, mapStoreError(ctx, err)
		}

		result.SubjectResolution = &resolution
		matcher = newSubjectMatcher(subject.Login, accounts, AttemptFilter{})
	}

	rows, err := s.fetchWithWidening(ctx, []AttemptKey{key}, around, around, queriedAt, nil)
	if err != nil {
		return nil, mapStoreError(ctx, err)
	}

	rows.boundedGroups()

	eventsRead := sourceRead{source: SourceAuthEvents, retention: eventRetention,
		queried: rows.eventSource.queried, failed: rows.eventSource.failed}
	logins, events := rows.logins[key], rows.events[key]

	if bound {
		matcher = matcher.withRecordedAccounts(subject.Login, logins)
	}

	if (len(logins) > 0 || len(events) > 0) && (!bound || belongsToSubject(matcher, logins, events)) {
		attempt := buildAttempt(attemptInput{key: key, logins: logins, events: events, matcher: matcher,
			read: rows.ranges[key], projection: caller.projection(), eventsRead: eventsRead.failed == nil})
		result.Attempt = &attempt
	}

	var attempts []Attempt
	if result.Attempt != nil {
		attempts = []Attempt{*result.Attempt}
	}

	result.History = s.attemptCoverage(ctx, window, queriedAt, eventsRead, attempts)
	result.ResultBasis = resultBasis(result.Attempt != nil, result.History, SourceLogins, false)

	return result, nil
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
func (s *Service) attemptCoverage(ctx context.Context, window Window, queriedAt time.Time, eventsRead sourceRead, attempts []Attempt) Coverage {
	logins := sourceRead{source: SourceLogins, retention: loginRetention, queried: true,
		presence: s.attempts.Presence(ctx, SourceLogins)}

	eventsRead.source, eventsRead.retention, eventsRead.queried = SourceAuthEvents, eventRetention, true
	eventsRead.presence = s.attempts.Presence(ctx, SourceAuthEvents)

	since, known := s.attempts.ContractRowsSince(ctx, window.From, minTime(window.Until, queriedAt))
	legacy := slices.ContainsFunc(attempts, func(attempt Attempt) bool { return attempt.Recording.LegacyRows > 0 })

	return buildCoverage(coverageInput{now: queriedAt, window: window, deployment: s.attempts.Deployment(),
		reads: []sourceRead{logins, eventsRead}, contractSince: since, contractKnown: known,
		limits: attemptKnownLimits, legacyRows: legacy})
}
