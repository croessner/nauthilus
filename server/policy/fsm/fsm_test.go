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

package fsm

import (
	"strings"
	"testing"

	"github.com/croessner/nauthilus/server/policy"
)

func TestEvaluateAcceptsAllowedTransitions(t *testing.T) {
	for _, testCase := range evaluateAllowedTransitionCases() {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := Evaluate(testCase.markers)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result.TerminalState != testCase.terminal {
				t.Fatalf("terminal state = %q, want %q", result.TerminalState, testCase.terminal)
			}

			if len(result.TargetEventPath) != len(testCase.markers) {
				t.Fatalf("target event path = %v, want %v", result.TargetEventPath, testCase.markers)
			}
		})
	}
}

func TestNextStateMatchesTransitionTable(t *testing.T) {
	for current, events := range allowedTransitionTable() {
		for marker, want := range events {
			t.Run(string(current)+"/"+strings.TrimPrefix(marker, "auth.fsm.event."), func(t *testing.T) {
				got, err := nextState(current, marker)
				if err != nil {
					t.Fatalf("nextState() error = %v", err)
				}

				if got != want {
					t.Fatalf("state = %q, want %q", got, want)
				}
			})
		}
	}
}

func TestNextStateRejectsUnlistedTransitions(t *testing.T) {
	allowed := allowedTransitionSet()
	for _, current := range allStates() {
		for _, marker := range allTargetMarkers() {
			if _, ok := allowed[current][marker]; ok {
				continue
			}

			t.Run(string(current)+"/"+strings.TrimPrefix(marker, "auth.fsm.event."), func(t *testing.T) {
				_, err := nextState(current, marker)
				if err == nil {
					t.Fatal("nextState() error = nil, want error")
				}
			})
		}
	}
}

func TestEvaluateRejectsInvalidAndTerminalTransitions(t *testing.T) {
	tests := []struct {
		name    string
		markers []string
	}{
		{
			name:    "auth event from init",
			markers: []string{policy.FSMEventMarkerAuthPermit},
		},
		{
			name:    "final event before auth checkpoint",
			markers: []string{policy.FSMEventMarkerParseOK, policy.FSMEventMarkerPreAuthOK, policy.FSMEventMarkerAuthPermit},
		},
		{
			name:    "event after terminal",
			markers: []string{policy.FSMEventMarkerParseOK, policy.FSMEventMarkerPreAuthDeny, policy.FSMEventMarkerAbort},
		},
		{
			name:    "unknown marker",
			markers: []string{policy.FSMEventMarkerParseOK, "auth.fsm.event.unknown"},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Evaluate(testCase.markers)
			if err == nil {
				t.Fatal("Evaluate() error = nil, want error")
			}
		})
	}
}

type evaluateCase struct {
	name     string
	terminal string
	markers  []string
}

func evaluateAllowedTransitionCases() []evaluateCase {
	return []evaluateCase{
		allowedCase("auth success", "auth_ok", policy.FSMEventMarkerPreAuthOK, policy.FSMEventMarkerAuthEvaluated, policy.FSMEventMarkerAuthPermit),
		allowedCase("pre auth deny", "auth_fail", policy.FSMEventMarkerPreAuthDeny),
		allowedCase("pre auth temporary failure", "auth_tempfail", policy.FSMEventMarkerPreAuthTempFail),
		allowedCase("pre auth abort", "aborted", policy.FSMEventMarkerPreAuthAbort),
		allowedCase("basic auth success after input parse", "auth_ok", policy.FSMEventMarkerBasicAuthOK),
		allowedCase("basic auth failure after pre auth", "auth_fail", policy.FSMEventMarkerPreAuthOK, policy.FSMEventMarkerBasicAuthFail),
		allowedCase("password empty user", "auth_tempfail", policy.FSMEventMarkerPreAuthOK, policy.FSMEventMarkerAuthEvaluated, policy.FSMEventMarkerAuthEmptyUser),
		allowedCase("password empty pass", "auth_fail", policy.FSMEventMarkerPreAuthOK, policy.FSMEventMarkerAuthEvaluated, policy.FSMEventMarkerAuthEmptyPass),
		allowedCase("account provider success", "auth_ok", policy.FSMEventMarkerPreAuthOK, policy.FSMEventMarkerAccountProviderEvaluated, policy.FSMEventMarkerAuthPermit),
		allowedCase("abort from account provider checkpoint", "aborted", policy.FSMEventMarkerPreAuthOK, policy.FSMEventMarkerAccountProviderEvaluated, policy.FSMEventMarkerAbort),
	}
}

func allowedCase(name string, terminal string, markers ...string) evaluateCase {
	return evaluateCase{
		name:     name,
		terminal: terminal,
		markers:  append([]string{policy.FSMEventMarkerParseOK}, markers...),
	}
}

func allowedTransitionTable() map[state]map[string]state {
	return map[state]map[string]state{
		stateInit:                   initTransitions(),
		stateInputParsed:            inputParsedTransitions(),
		statePreAuthChecked:         preAuthCheckedTransitions(),
		stateAuthChecked:            authCheckedTransitions(),
		stateAccountProviderChecked: accountProviderCheckedTransitions(),
	}
}

func initTransitions() map[string]state {
	return map[string]state{
		policy.FSMEventMarkerParseOK:   stateInputParsed,
		policy.FSMEventMarkerParseFail: stateAborted,
		policy.FSMEventMarkerAbort:     stateAborted,
	}
}

func inputParsedTransitions() map[string]state {
	return map[string]state{
		policy.FSMEventMarkerPreAuthOK:       statePreAuthChecked,
		policy.FSMEventMarkerPreAuthDeny:     stateAuthFail,
		policy.FSMEventMarkerPreAuthTempFail: stateAuthTempFail,
		policy.FSMEventMarkerPreAuthAbort:    stateAborted,
		policy.FSMEventMarkerBasicAuthOK:     stateAuthOK,
		policy.FSMEventMarkerBasicAuthFail:   stateAuthFail,
		policy.FSMEventMarkerAbort:           stateAborted,
	}
}

func preAuthCheckedTransitions() map[string]state {
	return map[string]state{
		policy.FSMEventMarkerBasicAuthOK:              stateAuthOK,
		policy.FSMEventMarkerBasicAuthFail:            stateAuthFail,
		policy.FSMEventMarkerAuthEvaluated:            stateAuthChecked,
		policy.FSMEventMarkerAccountProviderEvaluated: stateAccountProviderChecked,
		policy.FSMEventMarkerAbort:                    stateAborted,
	}
}

func authCheckedTransitions() map[string]state {
	return map[string]state{
		policy.FSMEventMarkerAuthPermit:    stateAuthOK,
		policy.FSMEventMarkerAuthDeny:      stateAuthFail,
		policy.FSMEventMarkerAuthTempFail:  stateAuthTempFail,
		policy.FSMEventMarkerAuthEmptyUser: stateAuthTempFail,
		policy.FSMEventMarkerAuthEmptyPass: stateAuthFail,
		policy.FSMEventMarkerAbort:         stateAborted,
	}
}

func accountProviderCheckedTransitions() map[string]state {
	return map[string]state{
		policy.FSMEventMarkerAuthPermit:   stateAuthOK,
		policy.FSMEventMarkerAuthDeny:     stateAuthFail,
		policy.FSMEventMarkerAuthTempFail: stateAuthTempFail,
		policy.FSMEventMarkerAbort:        stateAborted,
	}
}

func allowedTransitionSet() map[state]map[string]struct{} {
	allowed := make(map[state]map[string]struct{}, len(allowedTransitionTable()))
	for current, transitions := range allowedTransitionTable() {
		allowed[current] = make(map[string]struct{}, len(transitions))
		for marker := range transitions {
			allowed[current][marker] = struct{}{}
		}
	}

	return allowed
}

func allStates() []state {
	return []state{
		stateInit,
		stateInputParsed,
		statePreAuthChecked,
		stateAuthChecked,
		stateAccountProviderChecked,
		stateAuthOK,
		stateAuthFail,
		stateAuthTempFail,
		stateAborted,
	}
}

func allTargetMarkers() []string {
	return []string{
		policy.FSMEventMarkerParseOK,
		policy.FSMEventMarkerParseFail,
		policy.FSMEventMarkerPreAuthOK,
		policy.FSMEventMarkerPreAuthDeny,
		policy.FSMEventMarkerPreAuthTempFail,
		policy.FSMEventMarkerPreAuthAbort,
		policy.FSMEventMarkerAuthEvaluated,
		policy.FSMEventMarkerAuthPermit,
		policy.FSMEventMarkerAuthDeny,
		policy.FSMEventMarkerAuthTempFail,
		policy.FSMEventMarkerAuthEmptyUser,
		policy.FSMEventMarkerAuthEmptyPass,
		policy.FSMEventMarkerAccountProviderEvaluated,
		policy.FSMEventMarkerBasicAuthOK,
		policy.FSMEventMarkerBasicAuthFail,
		policy.FSMEventMarkerAbort,
	}
}
