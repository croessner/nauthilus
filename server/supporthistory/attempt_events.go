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
	"cmp"
	"math"
	"time"
)

const (
	// listAttemptEvents names the events list of one attempt in cursor digests.
	listAttemptEvents = "attempt_events"

	// attemptRowBound is the per-source row bound of an interpretation read: one row more than an events page holds,
	// so a full page always shows whether more rows follow.
	attemptRowBound = MaxEventsPerAttempt + 1

	// sourceRankLogins and sourceRankAuthEvents order the sources at one instant: login rows precede step events.
	sourceRankLogins     = 0
	sourceRankAuthEvents = 1

	// eventsCursorMarks are the integer parts of an events cursor: the source rank, the number of listed events, and
	// the ties listed at the cursor position.
	eventsCursorMarks = 3
)

// eventPosition is the position of one event in the merged event order of an attempt (time, source rank, event id),
// with the number of events listed up to and including it and the ties listed at exactly this position.
type eventPosition struct {
	at      time.Time
	eventID string
	source  int
	served  int
	ties    int
}

// compare orders two positions in the merged event order; served and ties are no part of the order.
func (p eventPosition) compare(other eventPosition) int {
	return cmp.Or(p.at.Compare(other.at), cmp.Compare(p.source, other.source), cmp.Compare(p.eventID, other.eventID))
}

// storePositions renders the position as the continuation positions of both sources. The own source continues
// strictly after an event id, so stored replays of the listed event never fill a read; a legacy row without event id
// continues from the position inclusively and its ties are stepped over after the read. At one instant every login
// row precedes every step event, so the other source continues before or after the whole instant.
func (p eventPosition) storePositions() (logins, events *RowPosition) {
	own := &RowPosition{At: p.at, EventID: p.eventID, Bound: RowFromEventID}
	if p.eventID != "" {
		own.Bound = RowAfterEventID
	}

	if p.source == sourceRankLogins {
		return own, &RowPosition{At: p.at, Bound: RowFromInstant}
	}

	return &RowPosition{At: p.at, Bound: RowAfterInstant}, own
}

// loginPosition returns the event position of a login row.
func loginPosition(record LoginRecord) eventPosition {
	return eventPosition{at: record.At.UTC(), eventID: record.EventID, source: sourceRankLogins}
}

// authEventPosition returns the event position of a step event.
func authEventPosition(record AuthEventRecord) eventPosition {
	return eventPosition{at: record.At.UTC(), eventID: record.EventID, source: sourceRankAuthEvents}
}

// pageRows are the rows of one attempt read with a per-source bound. A source that returned its whole bound can
// continue beyond its last row, so the earliest such last row is the horizon up to which the rows are complete.
type pageRows struct {
	horizon *eventPosition
	logins  []LoginRecord
	events  []AuthEventRecord
}

// newPageRows wraps the rows of one attempt read with bound rows per source and derives their horizon.
func newPageRows(logins []LoginRecord, events []AuthEventRecord, bound int) pageRows {
	rows := pageRows{logins: logins, events: events}

	if len(logins) >= bound {
		rows.lower(lastPosition(logins, loginPosition))
	}

	if len(events) >= bound {
		rows.lower(lastPosition(events, authEventPosition))
	}

	return rows
}

// lower moves the horizon back to position when it lies earlier.
func (r *pageRows) lower(position eventPosition) {
	if r.horizon == nil || position.compare(*r.horizon) < 0 {
		r.horizon = &position
	}
}

// lastPosition returns the latest position of non-empty rows.
func lastPosition[T any](records []T, position func(T) eventPosition) eventPosition {
	last := position(records[0])

	for _, record := range records[1:] {
		if candidate := position(record); candidate.compare(last) > 0 {
			last = candidate
		}
	}

	return last
}

// eventListing selects the events page of an attempt answer.
type eventListing struct {
	// rows are separately read continuation rows; nil lists the page from the interpretation rows.
	rows  *pageRows
	after *eventPosition
	limit int
}

// listEvents lists one events page and its findings and returns the position to continue after, or nil when no
// recorded event follows. projected are the ordered interpretation events of the attempt. A page may end inside a
// group of events that share their whole position (legacy rows without event id at one instant): the cursor carries
// the ties listed at its position, and the continuation steps over exactly those.
func listEvents(input attemptInput, projected []projectedEvent) ([]Event, []Finding, *eventPosition) {
	listing := input.listing
	horizon := newPageRows(input.logins, input.events, attemptRowBound).horizon
	served, earlier := 0, 0
	continued := func(projectedEvent) bool { return false }

	if after := listing.after; after != nil {
		served, earlier = after.served, after.ties
		continued = func(item projectedEvent) bool { return item.key.compare(*after) == 0 }
	}

	if listing.rows != nil {
		logins, _ := dedupeByID(listing.rows.logins, loginEventID)
		events, _ := dedupeByID(listing.rows.events, authEventID)
		projected = skipListed(projectRows(input, logins, events), earlier, continued)
		horizon = listing.rows.horizon
	}

	complete := completePrefix(projected, horizon)
	end := min(len(complete), cmp.Or(listing.limit, MaxEventsPerAttempt))
	events, findings := sequence(complete[:end], served)

	if end == 0 || (end == len(projected) && horizon == nil) {
		return events, findings, nil
	}

	next := complete[end-1].key
	next.served = served + end
	next.ties = listedTies(complete[:end], sameEventPosition, continued, earlier)

	return events, findings, &next
}

// sameEventPosition reports whether two projected events share their whole merged position.
func sameEventPosition(a, b projectedEvent) bool {
	return a.key.compare(b.key) == 0
}

// completePrefix returns the leading events no unread row can precede: with a horizon, only events up to it.
func completePrefix(projected []projectedEvent, horizon *eventPosition) []projectedEvent {
	if horizon == nil {
		return projected
	}

	end := len(projected)
	for end > 0 && projected[end-1].key.compare(*horizon) > 0 {
		end--
	}

	return projected[:end]
}

// eventsDigest binds an events cursor to the detail lookup it continues.
func eventsDigest(reference AttemptReference) string {
	return queryDigest(listAttemptEvents, reference.AttemptID, reference.Around.UTC().Format(time.RFC3339Nano))
}

// attachEventsPage adds the events continuation of an attempt: a cursor while more events follow; the block also
// appears without a cursor when the caller selected an events page.
func attachEventsPage(attempt *Attempt, next *eventPosition, reference AttemptReference, queriedAt time.Time, limit int, requested bool) {
	if next == nil && !requested {
		return
	}

	page := &EventsPage{Detail: AttemptReference{AttemptID: reference.AttemptID, Around: reference.Around.UTC()},
		Limit: limit}

	if next != nil {
		cursor := encodeListCursor(listCursorState{Digest: eventsDigest(reference), Key: next.eventID,
			AtMillis: next.at.UnixMilli(), QueriedAt: queriedAt.UnixMilli(),
			Marks: []int64{int64(next.source), int64(next.served), int64(next.ties)}})
		page.NextCursor = &cursor
	}

	attempt.EventsPage = page
}

// eventsSelection is the validated events page of an attempt detail lookup.
type eventsSelection struct {
	after     *eventPosition
	queriedAt *time.Time
	limit     int
	requested bool
}

// reference returns the detail arguments an events cursor is bound to.
func (r *AttemptDetailRequest) reference() AttemptReference {
	return AttemptReference{AttemptID: r.AttemptID, Around: r.Around.UTC()}
}

// eventsSelection validates the events page of a detail request: the limit and a cursor of the same lookup.
func (r *AttemptDetailRequest) eventsSelection() (eventsSelection, *Error) {
	selection := eventsSelection{limit: MaxEventsPerAttempt}
	if r.EventsPage == nil {
		return selection, nil
	}

	limit, err := pageLimit(r.EventsPage.Limit, MaxEventsPerAttempt, MaxEventsPerAttempt)
	if err != nil {
		return selection, err
	}

	selection.limit, selection.requested = limit, true

	state, err := decodeListCursor(r.EventsPage.Cursor, eventsDigest(r.reference()), eventsCursorMarks)
	if err != nil || state == nil {
		return selection, err
	}

	source, served := state.Marks[0], state.Marks[1]
	if state.AtMillis <= 0 || (source != sourceRankLogins && source != sourceRankAuthEvents) || served <= 0 ||
		served > math.MaxInt32 {
		return selection, invalid(CodeInvalidCursor)
	}

	ties, err := cursorTies(state.Marks[2])
	if err != nil {
		return selection, err
	}

	queriedAt := state.queriedAt()
	selection.queriedAt = &queriedAt
	selection.after = &eventPosition{at: state.at(), eventID: state.Key, source: int(source), served: int(served),
		ties: ties}

	return selection, nil
}
