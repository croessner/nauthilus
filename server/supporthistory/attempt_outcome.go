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

import "slices"

// attemptOutcome derives the attempt result only from recorded terminal evidence.
//
// A request attempt carries the sealed terminal answer of its request. An IdP flow is rejected only when the flow
// was latched after a primary failure (any latched step event proves it can no longer succeed); a completed login is
// never recorded, so every other flow stays not_observed.
func attemptOutcome(input attemptInput, logins []LoginRecord, events []AuthEventRecord, latched bool) (string, string, bool) {
	if input.key.Kind == AttemptFlow {
		if !latched {
			return outcomeNotObserved, basisNone, false
		}

		kept := slices.ContainsFunc(events, func(record AuthEventRecord) bool {
			return record.FlowEffect == flowEffectFailureKept
		})
		if kept && input.projection == ProjectionDetail {
			return outcomeRejected, basisFailureKept, true
		}

		return outcomeRejected, basisFailureLatched, true
	}

	return requestOutcome(logins)
}

// contractResults collects the distinct interpreted results of the contract rows of one request.
func contractResults(logins []LoginRecord) map[string]struct{} {
	results := map[string]struct{}{}

	for _, record := range logins {
		if record.ContractVersion >= 1 {
			results[interpretLogin(record, AttemptRequest).result] = struct{}{}
		}
	}

	return results
}

// requestOutcome maps the interpreted terminal result shared by every contract row of one request, so a deliberate
// TLS rejection reads as rejected although the client saw a tempfail; rows that disagree make the answer unknown.
func requestOutcome(logins []LoginRecord) (string, string, bool) {
	results := contractResults(logins)

	switch {
	case len(results) == 0 && len(logins) > 0:
		return outcomeUnknown, basisLegacy, false
	case len(results) == 0:
		return outcomeNotObserved, basisNone, false
	case len(results) > 1:
		return outcomeUnknown, basisRequestAnswer, false
	}

	for result := range results {
		switch result {
		case resultSucceeded:
			return outcomeSucceeded, basisRequestAnswer, true
		case resultRejected:
			return outcomeRejected, basisRequestAnswer, true
		case resultTechnicalError:
			return outcomeTechnicalError, basisRequestAnswer, true
		}
	}

	return outcomeUnknown, basisRequestAnswer, false
}

// progressRank orders progress values; the furthest recorded step wins regardless of row timestamps.
var progressRank = map[string]int{
	progressNone: 0, progressTechnical: 1, progressPreCredential: 2, progressPrimaryRejected: 3, progressPrimaryOK: 4,
	progressFactorCompleted: 5, progressLatched: 6,
}

// attemptProgress names the furthest recorded step, derived from record types, not from timestamp order.
func attemptProgress(logins []LoginRecord, events []AuthEventRecord, kind AttemptKind, latched bool) string {
	if latched {
		return progressLatched
	}

	progress := progressNone
	raise := func(candidate string) {
		if progressRank[candidate] > progressRank[progress] {
			progress = candidate
		}
	}

	for _, record := range logins {
		raise(loginProgress(interpretLogin(record, kind)))
	}

	for _, record := range events {
		if record.FlowEffect == flowEffectCompleted {
			raise(progressFactorCompleted)
		}
	}

	return progress
}

// loginProgress maps one interpreted login row to its progress value.
func loginProgress(reading interpretation) string {
	switch {
	case reading.result == resultSucceeded:
		return progressPrimaryOK
	case reading.result == resultTechnicalError:
		return progressTechnical
	case reading.stage == stagePreCredential:
		return progressPreCredential
	case reading.result == resultRejected:
		return progressPrimaryRejected
	default:
		return progressNone
	}
}

// attemptSteps states per step whether evidence was recorded, withheld, or does not apply.
func attemptSteps(input attemptInput, logins []LoginRecord, visible []AuthEventRecord, withheld bool) Steps {
	steps := Steps{Primary: stepNotRecorded, SecondFactor: stepNotRecorded}
	if len(logins) > 0 {
		steps.Primary = stepRecorded
	}

	switch {
	case withheld:
		steps.SecondFactor = stepWithheld
	case len(visible) > 0:
		steps.SecondFactor = stepRecorded
	case input.key.Kind == AttemptRequest:
		steps.SecondFactor = stepNotApplicable
	}

	return steps
}

// attemptGaps lists the known evidence gaps of one attempt; an empty list only means no gap is known.
func attemptGaps(input attemptInput, logins []LoginRecord, events []AuthEventRecord, attempt Attempt) []string {
	gaps := []string{}
	add := func(condition bool, gap string) {
		if condition {
			gaps = append(gaps, gap)
		}
	}

	add(input.key.Kind == AttemptRequest && len(contractResults(logins)) > 1, gapConflictingTerminal)
	add(attempt.Recording.LegacyRows > 0, gapLegacyRows)
	add(input.key.Kind == AttemptFlow && len(logins) == 0, gapPrimaryNotRecorded)
	add(input.key.Kind == AttemptFlow && !input.eventsRead, gapEventsNotRead)
	add(rowsTouchBoundary(input.read, logins, events), gapBeyondReadWindow)
	add(input.key.Kind == AttemptFlow && attempt.Outcome == outcomeNotObserved, gapNoFlowCompletion)

	return gaps
}

// rowsTouchBoundary reports whether any row of the attempt lies close to a closed read boundary.
func rowsTouchBoundary(read readRange, logins []LoginRecord, events []AuthEventRecord) bool {
	if read.from.IsZero() {
		return false
	}

	return slices.ContainsFunc(logins, func(record LoginRecord) bool { return read.touchesBoundary(record.At) }) ||
		slices.ContainsFunc(events, func(record AuthEventRecord) bool { return read.touchesBoundary(record.At) })
}
