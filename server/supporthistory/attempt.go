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
	"slices"
	"time"
)

// Attempt-level values.
const (
	outcomeSucceeded      = "succeeded"
	outcomeRejected       = "rejected"
	outcomeTechnicalError = "technical_error"
	outcomeNotObserved    = "not_observed"
	outcomeUnknown        = "unknown"

	basisRequestAnswer   = "request_terminal_answer"
	basisFailureLatched  = "primary_failure_latched"
	basisFailureKept     = "primary_failure_kept"
	basisNone            = "none"
	basisLegacy          = "legacy"
	stepRecorded         = "recorded"
	stepNotRecorded      = "not_recorded"
	stepWithheld         = "withheld"
	stepNotApplicable    = "not_applicable"
	certaintyObserved    = "observed"
	certaintyUncertain   = "uncertain"
	sourceNameLogins     = "logins"
	sourceNameAuthEvents = "auth_events"

	progressPreCredential   = "pre_credential_rejected"
	progressPrimaryRejected = "primary_rejected"
	progressPrimaryOK       = "primary_succeeded"
	progressFactorCompleted = "second_factor_completed"
	progressLatched         = "primary_failure_latched"
	progressTechnical       = "technical_error"
	progressNone            = "none"
)

// Gap codes of one attempt.
const (
	gapConflictingTerminal = "CONFLICTING_TERMINAL_RECORDS"
	gapLegacyRows          = "LEGACY_ROWS_UNINTERPRETED"
	gapPrimaryNotRecorded  = "PRIMARY_ROW_NOT_RECORDED"
	gapEventsNotRead       = "AUTH_EVENTS_NOT_READ"
	gapBeyondReadWindow    = "ATTEMPT_MAY_EXTEND_BEYOND_READ_WINDOW"
	gapNoFlowCompletion    = "FLOW_COMPLETION_NEVER_RECORDED"
)

// readRange is the time range rows of an attempt were read from; open marks an end at queried_at.
type readRange struct {
	from     time.Time
	until    time.Time
	openEnd  bool
	limitHit bool
}

// touchesBoundary reports whether a row lies so close to a closed boundary that siblings may lie beyond it.
func (r readRange) touchesBoundary(at time.Time) bool {
	if at.Sub(r.from) < flowSilenceBound {
		return true
	}

	return !r.openEnd && r.until.Sub(at) <= flowSilenceBound
}

// attemptInput is everything the builder needs for one attempt.
type attemptInput struct {
	key        AttemptKey
	logins     []LoginRecord
	events     []AuthEventRecord
	matcher    subjectMatcher
	read       readRange
	projection Projection
	eventsRead bool
}

// projectedEvent is one interpreted, projected event before sequencing.
type projectedEvent struct {
	event   Event
	reading interpretation
}

// buildAttempt correlates, interprets, and projects the rows of one attempt.
func buildAttempt(input attemptInput) Attempt {
	logins, loginReplays := dedupeByID(input.logins, loginEventID)
	events, _ := dedupeByID(input.events, authEventID)
	latched := slices.ContainsFunc(events, func(record AuthEventRecord) bool {
		return record.FailLatched || record.FlowEffect == flowEffectFailureKept
	})
	withhold := latched && input.projection == ProjectionSupport
	visible, visibleReplays := dedupeByID(visibleEvents(input.events, withhold), authEventID)

	projected := make([]projectedEvent, 0, len(logins)+len(visible))
	for _, record := range logins {
		projected = append(projected, projectLogin(record, input))
	}

	for _, record := range visible {
		projected = append(projected, projectAuthEvent(record, input))
	}

	sortProjected(projected)

	attempt := Attempt{AttemptID: attemptID(input.key), Kind: string(input.key.Kind), Projection: string(input.projection)}
	attempt.Recording = recordingOf(input, logins, loginReplays+visibleReplays, withhold, projected)
	attempt.Events, attempt.Findings = sequence(projected, withhold, &attempt.Recording)
	attempt.StartedAt, attempt.LastObservedAt = observedSpan(projected, events)
	attempt.Outcome, attempt.OutcomeBasis, attempt.FinalOutcomeObserved = attemptOutcome(input, logins, events, latched)
	attempt.Progress = attemptProgress(logins, events, input.key.Kind, latched)
	attempt.Steps = attemptSteps(input, logins, visible, withhold)
	attempt.Recording.KnownGaps = attemptGaps(input, logins, visible, attempt)

	return attempt
}

// visibleEvents removes fail-latched factor events from the support projection (contract §7.2, §11).
func visibleEvents(records []AuthEventRecord, withhold bool) []AuthEventRecord {
	if !withhold {
		return records
	}

	return slices.DeleteFunc(slices.Clone(records), func(record AuthEventRecord) bool {
		return record.FailLatched || record.FlowEffect == flowEffectFailureKept
	})
}

// dedupeByID merges replays of the same non-empty event id; rows without id (legacy) are never merged. It returns
// the kept rows and the number of merged replays.
func dedupeByID[T any](records []T, id func(T) string) ([]T, int) {
	seen := map[string]struct{}{}
	result := make([]T, 0, len(records))

	for _, record := range records {
		if key := id(record); key != "" {
			if _, ok := seen[key]; ok {
				continue
			}

			seen[key] = struct{}{}
		}

		result = append(result, record)
	}

	return result, len(records) - len(result)
}

// loginEventID returns the idempotency key of a login row.
func loginEventID(record LoginRecord) string {
	return record.EventID
}

// authEventID returns the idempotency key of a step event.
func authEventID(record AuthEventRecord) string {
	return record.EventID
}

// sortProjected orders events by time, logins before step events at the same instant, then by event id.
func sortProjected(events []projectedEvent) {
	slices.SortStableFunc(events, func(a, b projectedEvent) int {
		if order := a.event.OccurredAt.Compare(b.event.OccurredAt); order != 0 {
			return order
		}

		if order := cmp.Compare(a.event.Source, b.event.Source); order != 0 {
			return -order
		}

		return cmp.Compare(stringValue(a.event.EventID), stringValue(b.event.EventID))
	})
}

// sequence numbers the visible events, applies the per-attempt bound, and collects findings.
func sequence(projected []projectedEvent, withheld bool, recording *Recording) ([]Event, []Finding) {
	if len(projected) > MaxEventsPerAttempt {
		projected = projected[:MaxEventsPerAttempt]
		recording.EventsTruncated = true
	}

	events := make([]Event, 0, len(projected))
	findings := []Finding{}

	for index, item := range projected {
		item.event.Sequence = index + 1
		events = append(events, item.event)

		if item.reading.finding {
			findings = append(findings, findingOf(item))
		}
	}

	if withheld {
		findings = append(findings, Finding{Code: CodeFactorOnLatchedFlow, Category: categorySecondFactor,
			Certainty: certaintyObserved, Uncertainty: []string{}})
	}

	return events, findings
}

// findingOf turns one interpreted event into a finding that references it.
func findingOf(item projectedEvent) Finding {
	certainty := certaintyObserved
	if len(item.reading.uncertainty) > 0 {
		certainty = certaintyUncertain
	}

	uncertainty := append([]string{}, item.reading.uncertainty...)

	return Finding{EventID: item.event.EventID, Code: item.reading.code, Category: item.reading.category,
		Certainty: certainty, Uncertainty: uncertainty}
}

// observedSpan computes start and last observation over visible events only, so withheld retries leak nothing.
// An attempt whose only evidence is withheld gets one minute-truncated instant.
func observedSpan(projected []projectedEvent, events []AuthEventRecord) (time.Time, time.Time) {
	if len(projected) > 0 {
		return projected[0].event.OccurredAt, projected[len(projected)-1].event.OccurredAt
	}

	var earliest time.Time

	for _, record := range events {
		if earliest.IsZero() || record.At.Before(earliest) {
			earliest = record.At
		}
	}

	earliest = earliest.Truncate(time.Minute)

	return earliest, earliest
}

// recordingOf counts merged replays and legacy rows of the visible evidence and flags the store bound.
func recordingOf(input attemptInput, logins []LoginRecord, replays int, withheld bool, projected []projectedEvent) Recording {
	legacy := 0

	for _, record := range logins {
		if record.ContractVersion < 1 {
			legacy++
		}
	}

	// The store bound of a latched flow can be filled by withheld factor events; reporting it would leak them.
	return Recording{ReplayedRowsMerged: replays, LegacyRows: legacy, EventsWithheld: withheld,
		EventsTruncated: input.read.limitHit && len(projected) > 0 && !withheld, KnownGaps: []string{}}
}
