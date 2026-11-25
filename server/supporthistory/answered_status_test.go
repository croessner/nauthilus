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

package supporthistory_test

import (
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/supporthistory"
)

// answeredLogin returns one subject login row that carries the stored answered status of its decision.
func answeredLogin(at time.Time, session, flow, outcome string, code int, message string) supporthistory.LoginRecord {
	record := subjectLogin(at, session, flow, outcome, "", "")
	record.OutcomeStage = "auth_decision"
	record.AnsweredStatusCode, record.AnsweredStatusMessage = code, message

	return record
}

// TestDecisionCarriesTheAnsweredStatus pins that the stored host status code and status text of a contract row reach
// the decision block, that unknown values stay null instead of reading as success, and that legacy rows expose none.
func TestDecisionCarriesTheAnsweredStatus(t *testing.T) {
	store := fixtureStore(t)
	at := scenarioBase.Add(-3 * time.Minute)
	legacy := answeredLogin(at.Add(3*time.Second), "req-answer-legacy", "", "", 403, "Invalid login or password")
	legacy.ContractVersion, legacy.EventID, legacy.Operation = 0, "", ""
	inconsistent := answeredLogin(at.Add(4*time.Second), "req-answer-inconsistent", "", "unknown", 200, "OK")
	store.Logins = append(store.Logins,
		answeredLogin(at, "req-answer-ok", "", "ok", 200, "OK"),
		answeredLogin(at.Add(time.Second), "req-answer-tls", "", "tempfail", 500, "TLS transport encryption required"),
		answeredLogin(at.Add(2*time.Second), "req-answer-unknown", "", "unknown", 0, ""),
		legacy, inconsistent)

	attempts, _ := attemptsByID(t, newService(t, store), caller(definitions.ScopeHistoryRead))

	cases := []struct {
		id, message string
		code        int
		decision    bool
	}{
		{"rq1.req-answer-ok", "OK", 200, true},
		{"rq1.req-answer-tls", "TLS transport encryption required", 500, true},
		{"rq1.req-answer-unknown", "", 0, true},
		{"rq1.req-answer-inconsistent", "", 0, true},
		{"rq1.req-answer-legacy", "", 0, false},
	}

	for _, testCase := range cases {
		attempt, ok := attempts[testCase.id]
		if !ok || len(attempt.Events) != 1 {
			t.Fatalf("%s: attempt = %+v, want one event", testCase.id, attempt)
		}

		decision := attempt.Events[0].Decision
		if !testCase.decision {
			if decision != nil {
				t.Fatalf("%s: legacy decision = %+v, want none", testCase.id, decision)
			}

			continue
		}

		assertAnsweredStatus(t, testCase.id, decision, testCase.code, testCase.message)
	}
}

// assertAnsweredStatus compares the answered status of one decision; a zero code or empty message expects null.
func assertAnsweredStatus(t *testing.T, id string, decision *supporthistory.Decision, code int, message string) {
	t.Helper()

	if decision == nil {
		t.Fatalf("%s: decision = nil, want answered status", id)
	}

	switch {
	case code == 0 && decision.AnsweredStatusCode != nil:
		t.Fatalf("%s: answered_status_code = %d, want null", id, *decision.AnsweredStatusCode)
	case code != 0 && (decision.AnsweredStatusCode == nil || *decision.AnsweredStatusCode != code):
		t.Fatalf("%s: answered_status_code = %v, want %d", id, decision.AnsweredStatusCode, code)
	case message == "" && decision.AnsweredStatusMessage != nil:
		t.Fatalf("%s: answered_status_message = %q, want null", id, *decision.AnsweredStatusMessage)
	case message != "" && (decision.AnsweredStatusMessage == nil || *decision.AnsweredStatusMessage != message):
		t.Fatalf("%s: answered_status_message = %v, want %q", id, decision.AnsweredStatusMessage, message)
	}
}

// TestAnsweredMessageOfOtherIdentitiesIsReleased pins that the free-text status message of another identity in the
// same flow reaches every history scope together with its status code.
func TestAnsweredMessageOfOtherIdentitiesIsReleased(t *testing.T) {
	flow := strings.Repeat("6", 32)
	at := scenarioBase.Add(-4 * time.Minute)
	foreign := answeredLogin(at.Add(time.Second), "flow6-b", flow, "fail", 403, "Account mallory@example.test locked")
	foreign.Username, foreign.Account = "mallory@example.test", ""
	id := "fl1." + flow

	for _, scope := range historyScopes {
		t.Run(scope, func(t *testing.T) {
			store := fixtureStore(t)
			store.Logins = append(store.Logins,
				answeredLogin(at, "flow6-a", flow, "fail", 403, "Invalid login or password"), foreign)
			attempts, _ := attemptsByID(t, newService(t, store), caller(scope))

			events := attempts[id].Events
			if len(events) != 2 || stringValue(events[1].Identity.SuppliedLogin) != "mallory@example.test" {
				t.Fatalf("events = %+v, want both identities released", events)
			}

			assertAnsweredStatus(t, id+" own", events[0].Decision, 403, "Invalid login or password")
			assertAnsweredStatus(t, id+" foreign", events[1].Decision, 403, "Account mallory@example.test locked")
		})
	}
}
