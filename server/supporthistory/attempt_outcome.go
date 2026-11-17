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
// A request attempt carries the sealed terminal answer of its request. An IdP flow is rejected when the flow was
// latched after a primary failure (any latched step event proves it can no longer succeed), and it ends with the
// recorded redemption of its authorization code (tokens issued, rejected, or failed). Every other flow stays
// not_observed. Completion events on a latched flow contradict each other and leave the outcome unknown.
func attemptOutcome(input attemptInput, logins []LoginRecord, factor []AuthEventRecord, latched bool,
	evidence completionEvidence, completed bool) (string, string, bool) {
	if input.key.Kind != AttemptFlow {
		return requestOutcome(logins)
	}

	switch outcome, basis, final := evidence.outcome(); {
	case latched && completed:
		return outcomeUnknown, basisNone, false
	case latched:
		return latchedOutcome(input, factor)
	case final:
		return outcome, basis, true
	}

	return outcomeNotObserved, basisNone, false
}

// latchedOutcome is the rejection of a flow whose primary step failed; the detail role sees whether the latched
// step-up was consumed.
func latchedOutcome(input attemptInput, factor []AuthEventRecord) (string, string, bool) {
	kept := slices.ContainsFunc(factor, func(record AuthEventRecord) bool {
		return record.FlowEffect == flowEffectFailureKept
	})
	if kept && input.projection == ProjectionDetail {
		return outcomeRejected, basisFailureKept, true
	}

	return outcomeRejected, basisFailureLatched, true
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
	progressFactorCompleted: 5, progressLatched: 6, progressCodeIssued: 7, progressTokensIssued: 8,
}

// attemptProgress names the furthest recorded step, derived from record types, not from timestamp order. A recorded
// redemption failure implies an issued code.
func attemptProgress(logins []LoginRecord, events, completion []AuthEventRecord, kind AttemptKind, latched bool) string {
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

	for _, record := range completion {
		raise(completionProgress(interpretCompletionEvent(record)))
	}

	return progress
}

// completionProgress maps one interpreted completion event to its progress value.
func completionProgress(reading interpretation) string {
	switch {
	case reading.code == CodeTokensIssued:
		return progressTokensIssued
	case reading.code == CodeAuthorizationCodeIssued,
		reading.stage == stageTokenExchange && (reading.result == resultRejected || reading.result == resultTechnicalError):
		return progressCodeIssued
	default:
		return progressNone
	}
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

// attemptSteps states per step whether evidence was recorded, withheld, or does not apply. The second factor reads
// only second-factor events; a reused session is no unrecorded primary step.
func attemptSteps(input attemptInput, logins []LoginRecord, visibleFactor []AuthEventRecord, withheld bool,
	evidence completionEvidence, completion []AuthEventRecord) Steps {
	steps := Steps{Primary: stepNotRecorded, SecondFactor: stepNotRecorded,
		CodeIssuance:   evidence.stepState(eventTypeCodeIssuance, completion),
		CodeRedemption: evidence.stepState(eventTypeCodeRedemption, completion)}

	switch {
	case len(logins) > 0:
		steps.Primary = stepRecorded
	case evidence.sessionReused():
		steps.Primary = stepSessionReused
	}

	switch {
	case withheld:
		steps.SecondFactor = stepWithheld
	case len(visibleFactor) > 0:
		steps.SecondFactor = stepRecorded
	case input.key.Kind == AttemptRequest:
		steps.SecondFactor = stepNotApplicable
	}

	return steps
}

// attemptGaps lists the known evidence gaps of one attempt; an empty list only means no gap is known.
func attemptGaps(input attemptInput, logins []LoginRecord, events []AuthEventRecord, attempt Attempt,
	evidence completionEvidence, latchedCompletion bool) []string {
	gaps := []string{}
	add := func(condition bool, gap string) {
		if condition {
			gaps = append(gaps, gap)
		}
	}

	flow := input.key.Kind == AttemptFlow
	conflicting := latchedCompletion || evidence.conflicting ||
		!flow && len(contractResults(logins)) > 1

	add(conflicting, gapConflictingTerminal)
	add(attempt.Recording.LegacyRows > 0, gapLegacyRows)
	add(flow && len(logins) == 0 && attempt.Steps.Primary != stepSessionReused, gapPrimaryNotRecorded)
	add(flow && !input.eventsRead, gapEventsNotRead)
	add(rowsTouchBoundary(input.read, logins, events), gapBeyondReadWindow)
	add(flow && attempt.Outcome == outcomeNotObserved, evidence.completionGap())

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
