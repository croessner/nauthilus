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

// attemptRows holds the fetched rows of several attempts, grouped by key, with the range each group was read from.
type attemptRows struct {
	logins      map[AttemptKey][]LoginRecord
	events      map[AttemptKey][]AuthEventRecord
	ranges      map[AttemptKey]readRange
	eventSource sourceRead
}

// loginKey returns the attempt key of a login row.
func loginKey(record LoginRecord) AttemptKey {
	if record.FlowRef != "" {
		return AttemptKey{Kind: AttemptFlow, Value: record.FlowRef}
	}

	return AttemptKey{Kind: AttemptRequest, Value: record.Session}
}

// eventKey returns the attempt key of a step event.
func eventKey(record AuthEventRecord) AttemptKey {
	if record.FlowRef != "" {
		return AttemptKey{Kind: AttemptFlow, Value: record.FlowRef}
	}

	return AttemptKey{Kind: AttemptRequest, Value: record.RequestID}
}

// rowQuery renders the keys into a store row query.
func rowQuery(keys []AttemptKey, read readRange, subject *SubjectMatch) RowQuery {
	query := RowQuery{From: read.from, Until: read.until, Subject: subject, LimitPerGroup: MaxEventsPerAttempt + 1}

	for _, key := range keys {
		if key.Kind == AttemptFlow {
			query.Flows = append(query.Flows, key.Value)
		} else {
			query.Requests = append(query.Requests, key.Value)
		}
	}

	slices.Sort(query.Flows)
	slices.Sort(query.Requests)

	return query
}

// fetchRows reads the rows of the keys in one range. A login read failure fails the operation; a step-event read
// failure only makes the answer partial.
func (s *Service) fetchRows(ctx context.Context, keys []AttemptKey, read readRange, subject *SubjectMatch, rows *attemptRows) error {
	query := rowQuery(keys, read, subject)

	logins, err := s.attempts.LoginRows(ctx, query)
	if err != nil {
		return err
	}

	events, eventsErr := s.attempts.AuthEvents(ctx, query)
	rows.eventSource.queried = true

	if eventsErr != nil {
		rows.eventSource.failed = eventsErr
	}

	wanted := map[AttemptKey]struct{}{}
	for _, key := range keys {
		wanted[key] = struct{}{}
		delete(rows.logins, key)
		delete(rows.events, key)
		rows.ranges[key] = read
	}

	for _, record := range logins {
		if key := loginKey(record); hasKey(wanted, key) {
			rows.logins[key] = append(rows.logins[key], record)
		}
	}

	for _, record := range events {
		if key := eventKey(record); hasKey(wanted, key) {
			rows.events[key] = append(rows.events[key], record)
		}
	}

	return nil
}

// hasKey reports set membership.
func hasKey(set map[AttemptKey]struct{}, key AttemptKey) bool {
	_, ok := set[key]

	return ok
}

// rangeAround builds a read range with a margin around [first, last], closed at queriedAt.
func rangeAround(first, last, queriedAt time.Time, margin time.Duration) readRange {
	read := readRange{from: first.Add(-margin), until: last.Add(margin)}
	if !read.until.Before(queriedAt) {
		read.until, read.openEnd = queriedAt, true
	}

	return read
}

// fetchWithWidening reads attempts with the initial margin and re-reads those whose rows touch a boundary, or that
// returned nothing, with the widened margin; a group that still touches it keeps the boundary gap.
func (s *Service) fetchWithWidening(ctx context.Context, keys []AttemptKey, first, last, queriedAt time.Time, subject *SubjectMatch) (attemptRows, error) {
	rows := attemptRows{logins: map[AttemptKey][]LoginRecord{}, events: map[AttemptKey][]AuthEventRecord{},
		ranges: map[AttemptKey]readRange{}}

	if len(keys) == 0 {
		return rows, nil
	}

	if err := s.fetchRows(ctx, keys, rangeAround(first, last, queriedAt, initialAttemptMargin), subject, &rows); err != nil {
		return rows, err
	}

	var widen []AttemptKey

	for _, key := range keys {
		empty := len(rows.logins[key]) == 0 && len(rows.events[key]) == 0
		if empty || rowsTouchBoundary(rows.ranges[key], rows.logins[key], rows.events[key]) {
			widen = append(widen, key)
		}
	}

	if len(widen) == 0 {
		return rows, nil
	}

	err := s.fetchRows(ctx, widen, rangeAround(first, last, queriedAt, widenedAttemptMargin), subject, &rows)

	return rows, err
}

// boundedGroups trims oversized groups and flags them.
func (r *attemptRows) boundedGroups() {
	for key, logins := range r.logins {
		if len(logins)+len(r.events[key]) > MaxEventsPerAttempt {
			read := r.ranges[key]
			read.limitHit = true
			r.ranges[key] = read
		}
	}

	for key, events := range r.events {
		if len(events)+len(r.logins[key]) > MaxEventsPerAttempt {
			read := r.ranges[key]
			read.limitHit = true
			r.ranges[key] = read
		}
	}
}

// collectAttempts fetches and builds the attempts of one page; on later pages it drops attempts with a
// subject-matching row newer than the cursor, because the newest-activity anchor already served them.
func (s *Service) collectAttempts(ctx context.Context, scope searchScope, page []AttemptAnchor) ([]Attempt, sourceRead, error) {
	eventsRead := sourceRead{source: SourceAuthEvents, retention: eventRetention}
	if len(page) == 0 {
		return []Attempt{}, eventsRead, nil
	}

	keys := make([]AttemptKey, 0, len(page))
	first, last := page[0].At, page[0].At

	for _, anchor := range page {
		keys = append(keys, anchor.Key)
		first, last = minTime(first, anchor.At), maxTime(last, anchor.At)
	}

	match := scope.matcher.subjectMatch()

	rows, err := s.fetchWithWidening(ctx, keys, first, last, scope.queriedAt, &match)
	if err != nil {
		return nil, eventsRead, err
	}

	rows.boundedGroups()
	eventsRead.queried, eventsRead.failed = rows.eventSource.queried, rows.eventSource.failed
	attempts := make([]Attempt, 0, len(page))

	for _, key := range keys {
		if scope.cursor != nil && alreadyServed(scope, rows.logins[key], rows.events[key]) {
			continue
		}

		attempts = append(attempts, buildAttempt(attemptInput{key: key, logins: rows.logins[key],
			events: rows.events[key], matcher: scope.matcher, read: rows.ranges[key], projection: scope.projection,
			eventsRead: eventsRead.failed == nil, queriedAt: scope.queriedAt, completionSince: scope.completion.since}))
	}

	return attempts, eventsRead, nil
}

// alreadyServed reports whether an attempt had subject-matching activity inside the already scanned range
// (cursor, scan upper bound); rows at or after the window end or the query time never anchored and do not count.
func alreadyServed(scope searchScope, logins []LoginRecord, events []AuthEventRecord) bool {
	position := scope.cursor.position().At
	upper := minTime(scope.window.Until, scope.queriedAt)
	scanned := func(at time.Time) bool { return at.After(position) && at.Before(upper) }

	return slices.ContainsFunc(logins, func(record LoginRecord) bool {
		return scanned(record.At) && scope.matcher.anchorsLogin(record)
	}) || slices.ContainsFunc(events, func(record AuthEventRecord) bool {
		return scanned(record.At) && scope.matcher.anchorsEvent(record)
	})
}
