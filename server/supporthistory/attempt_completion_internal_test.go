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
	"strings"
	"testing"
	"time"
)

// completionInput builds the input of one authorization-code flow with an issued code.
func completionInput(issuedAt, queriedAt time.Time, read readRange, events ...AuthEventRecord) attemptInput {
	issuance := AuthEventRecord{At: issuedAt, EventID: "iss", EventType: eventTypeCodeIssuance, EventVersion: 1,
		Result: eventResultSuccess, Reason: reasonExistingSession, FlowEffect: flowEffectCodeIssued}

	return attemptInput{key: AttemptKey{Kind: AttemptFlow, Value: strings.Repeat("c", 32)}, queriedAt: queriedAt,
		read: read, eventsRead: true, events: append([]AuthEventRecord{issuance}, events...)}
}

// stateOf evaluates the completion state of an input.
func stateOf(input attemptInput) (string, bool) {
	factor, completion := splitStepEvents(input.events)
	evidence := evaluateCompletion(input, nil, factor, completion, false)

	return evidence.block.State, evidence.conflicting
}

// TestCompletionExpiryNeedsTheWholeRedemptionHorizon pins that the expiry is stated only when the read range covers
// the redemption horizon (code lifetime plus export delay), and stays pending while the horizon is open.
func TestCompletionExpiryNeedsTheWholeRedemptionHorizon(t *testing.T) {
	issuedAt := time.Date(2026, time.November, 17, 18, 35, 7, 0, time.UTC)
	horizon := issuedAt.Add(10*time.Minute + lateEventHorizon)

	cases := []struct {
		name      string
		queriedAt time.Time
		read      readRange
		want      string
	}{
		{"open horizon", horizon.Add(-time.Second), readRange{from: issuedAt.Add(-time.Hour), openEnd: true,
			until: horizon.Add(-time.Second)}, completionRedemptionPending},
		{"open read end", horizon.Add(time.Hour), readRange{from: issuedAt.Add(-time.Hour), openEnd: true,
			until: horizon.Add(time.Hour)}, completionCodeExpired},
		{"closed read covers the horizon", horizon.Add(time.Hour), readRange{from: issuedAt.Add(-time.Hour),
			until: horizon}, completionCodeExpired},
		{"closed read ends before the horizon", horizon.Add(time.Hour), readRange{from: issuedAt.Add(-time.Hour),
			until: issuedAt.Add(5 * time.Minute)}, completionUnknown},
		{"rows cut by the per-attempt bound", horizon.Add(time.Hour), readRange{from: issuedAt.Add(-time.Hour),
			openEnd: true, until: horizon.Add(time.Hour), limitHit: true}, completionUnknown},
	}

	for _, testCase := range cases {
		if got, _ := stateOf(completionInput(issuedAt, testCase.queriedAt, testCase.read)); got != testCase.want {
			t.Fatalf("%s: state = %s, want %s", testCase.name, got, testCase.want)
		}
	}
}

// TestCompletionFailuresThatDisagreeAreConflicting pins that two different recorded failures of one code never pick
// one, while a success still dominates them.
func TestCompletionFailuresThatDisagreeAreConflicting(t *testing.T) {
	issuedAt := time.Date(2026, time.November, 17, 18, 35, 7, 0, time.UTC)
	read := readRange{from: issuedAt.Add(-time.Hour), openEnd: true, until: issuedAt.Add(time.Hour)}
	rejected := AuthEventRecord{At: issuedAt.Add(time.Second), EventID: "r1", EventType: eventTypeCodeRedemption,
		EventVersion: 1, Result: eventResultRejected, Reason: "pkce_mismatch", FlowEffect: flowEffectCodeConsumed}
	failed := AuthEventRecord{At: issuedAt.Add(2 * time.Second), EventID: "r2", EventType: eventTypeCodeRedemption,
		EventVersion: 1, Result: eventResultError, Reason: "token_issue_error", FlowEffect: flowEffectCodeConsumed}
	success := AuthEventRecord{At: issuedAt.Add(3 * time.Second), EventID: "r3", EventType: eventTypeCodeRedemption,
		EventVersion: 1, Result: eventResultSuccess, Reason: flowEffectTokensIssued, FlowEffect: flowEffectTokensIssued}

	if state, conflicting := stateOf(completionInput(issuedAt, issuedAt.Add(time.Hour), read, rejected, failed)); state != completionUnknown || !conflicting {
		t.Fatalf("disagreeing failures = %s conflicting=%v, want unknown and conflicting", state, conflicting)
	}

	if state, conflicting := stateOf(completionInput(issuedAt, issuedAt.Add(time.Hour), read, rejected, failed, success)); state != completionTokensIssued || conflicting {
		t.Fatalf("success with failures = %s conflicting=%v, want tokens_issued", state, conflicting)
	}
}

// TestCodeLifetimeIsPinnedPerEventVersion pins the lifetime table; a changed code TTL needs a new event version.
func TestCodeLifetimeIsPinnedPerEventVersion(t *testing.T) {
	if lifetime, ok := CodeLifetimeOfIssuanceVersion(1); !ok || lifetime != 10*time.Minute {
		t.Fatalf("v1 lifetime = %v %v, want 10m", lifetime, ok)
	}

	if _, ok := CodeLifetimeOfIssuanceVersion(2); ok {
		t.Fatal("an unknown issuance version must not have a lifetime")
	}
}
