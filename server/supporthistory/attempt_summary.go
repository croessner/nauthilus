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

// summarizeAttempts renders the compact form of already projected attempts, so a summary never shows more than the
// detailed attempt of the same caller.
func summarizeAttempts(attempts []Attempt) []AttemptSummary {
	summaries := make([]AttemptSummary, 0, len(attempts))
	for _, attempt := range attempts {
		summaries = append(summaries, summarizeAttempt(attempt))
	}

	return summaries
}

// summarizeAttempt condenses one attempt: its outcome, the codes of its findings, the decisive code of an attempt
// that did not succeed, and the client addresses, protocols, and request ids of its subject rows.
func summarizeAttempt(attempt Attempt) AttemptSummary {
	summary := AttemptSummary{StartedAt: attempt.StartedAt, LastObservedAt: attempt.LastObservedAt,
		Detail:       AttemptReference{AttemptID: attempt.AttemptID, Around: attempt.StartedAt},
		FindingCodes: []string{}, ClientIPs: []string{}, Protocols: []string{}, RequestIDs: []string{},
		KnownGaps: append([]string{}, attempt.Recording.KnownGaps...), AttemptID: attempt.AttemptID,
		Kind: attempt.Kind, Outcome: attempt.Outcome, OutcomeBasis: attempt.OutcomeBasis, Progress: attempt.Progress,
		FinalObserved: attempt.FinalOutcomeObserved, Truncated: attempt.Recording.EventsTruncated}

	for _, finding := range attempt.Findings {
		summary.FindingCodes = appendDistinct(summary.FindingCodes, finding.Code)
	}

	if attempt.Outcome != outcomeSucceeded && len(attempt.Findings) > 0 {
		reason := attempt.Findings[len(attempt.Findings)-1].Code
		summary.Reason = &reason
	}

	for _, event := range attempt.Events {
		if !event.Identity.SubjectMatch {
			continue
		}

		summary.ClientIPs = appendDistinct(summary.ClientIPs, stringValue(event.Context.ClientIP))
		summary.Protocols = appendDistinct(summary.Protocols, stringValue(event.Context.Protocol))

		if event.Source == sourceNameLogins {
			summary.RequestIDs = appendDistinct(summary.RequestIDs, event.RequestID)
		}
	}

	return summary
}

// appendDistinct appends a non-empty value once, keeping first-seen order.
func appendDistinct(values []string, value string) []string {
	if value == "" || slices.Contains(values, value) {
		return values
	}

	return append(values, value)
}
