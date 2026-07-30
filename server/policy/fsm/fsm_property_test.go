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
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy"
	"pgregory.net/rapid"
)

const unknownModelMarker = "auth.fsm.event.model_unknown"

var modelTransitions = map[string]map[string]string{
	StateInit: {
		policy.FSMEventMarkerParseOK:   StateInputParsed,
		policy.FSMEventMarkerParseFail: StateAborted,
		policy.FSMEventMarkerAbort:     StateAborted,
	},
	StateInputParsed: {
		policy.FSMEventMarkerPreAuthOK:       StatePreAuthChecked,
		policy.FSMEventMarkerPreAuthDeny:     StateAuthFail,
		policy.FSMEventMarkerPreAuthTempFail: StateAuthTempFail,
		policy.FSMEventMarkerPreAuthAbort:    StateAborted,
		policy.FSMEventMarkerBasicAuthOK:     StateAuthOK,
		policy.FSMEventMarkerBasicAuthFail:   StateAuthFail,
		policy.FSMEventMarkerAbort:           StateAborted,
	},
	StatePreAuthChecked: {
		policy.FSMEventMarkerBasicAuthOK:              StateAuthOK,
		policy.FSMEventMarkerBasicAuthFail:            StateAuthFail,
		policy.FSMEventMarkerAuthEvaluated:            StateAuthChecked,
		policy.FSMEventMarkerAccountProviderEvaluated: StateAccountProviderChecked,
		policy.FSMEventMarkerAbort:                    StateAborted,
	},
	StateAuthChecked: {
		policy.FSMEventMarkerAuthPermit:    StateAuthOK,
		policy.FSMEventMarkerAuthDeny:      StateAuthFail,
		policy.FSMEventMarkerAuthTempFail:  StateAuthTempFail,
		policy.FSMEventMarkerAuthEmptyUser: StateAuthTempFail,
		policy.FSMEventMarkerAuthEmptyPass: StateAuthFail,
		policy.FSMEventMarkerAbort:         StateAborted,
	},
	StateAccountProviderChecked: {
		policy.FSMEventMarkerAuthPermit:   StateAuthOK,
		policy.FSMEventMarkerAuthDeny:     StateAuthFail,
		policy.FSMEventMarkerAuthTempFail: StateAuthTempFail,
		policy.FSMEventMarkerAbort:        StateAborted,
	},
}

var modelDecisionStates = map[policy.Decision]string{
	policy.DecisionPermit:   StateAuthOK,
	policy.DecisionDeny:     StateAuthFail,
	policy.DecisionTempFail: StateAuthTempFail,
}

func TestEvaluateMatchesIndependentModelProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		markers := rapid.SliceOfN(modelMarkerGenerator(), 0, 16).Draw(t, "markers")
		original := append([]string(nil), markers...)
		want, wantErr := evaluateModel(markers)

		got, gotErr := Evaluate(markers)
		assertModelEvaluation(t, got, gotErr, want, wantErr)

		if !slices.Equal(markers, original) {
			t.Fatalf("Evaluate() mutated markers: got %v, want %v", markers, original)
		}

		repeated, repeatedErr := Evaluate(markers)
		assertModelEvaluation(t, repeated, repeatedErr, got, gotErr)
	})
}

func TestTerminalStatesRejectFurtherEventsProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		terminalState := rapid.SampledFrom(modelTerminalStates()).Draw(t, "terminal")
		marker := modelMarkerGenerator().Draw(t, "marker")

		next, err := NextState(terminalState, marker)
		if err == nil {
			t.Fatalf("NextState(%q, %q) = %q, want error", terminalState, marker, next)
		}
	})
}

func TestTerminalStateForDecisionProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		decision := rapid.SampledFrom([]policy.Decision{
			policy.DecisionPermit,
			policy.DecisionDeny,
			policy.DecisionTempFail,
			"",
			"unsupported",
		}).Draw(t, "decision")

		if got, want := TerminalStateForDecision(decision), modelDecisionStates[decision]; got != want {
			t.Fatalf("TerminalStateForDecision(%q) = %q, want %q", decision, got, want)
		}
	})
}

// evaluateModel applies the independently declared transition table.
func evaluateModel(markers []string) (Result, error) {
	current := StateInit
	result := Result{
		TargetEventPath: make([]string, 0, len(markers)),
		Transitions:     make([]Transition, 0, len(markers)),
	}

	for _, marker := range markers {
		stateTransitions, knownState := modelTransitions[current]
		next, accepted := stateTransitions[marker]

		if !knownState || !accepted {
			result.TerminalState = current

			return result, errors.New("model rejected transition")
		}

		result.TargetEventPath = append(result.TargetEventPath, marker)
		result.Transitions = append(result.Transitions, Transition{
			From:        current,
			EventMarker: marker,
			To:          next,
		})
		current = next
	}

	result.TerminalState = current

	return result, nil
}

// assertModelEvaluation compares successful prefixes and the error boundary.
func assertModelEvaluation(t *rapid.T, got Result, gotErr error, want Result, wantErr error) {
	t.Helper()

	if (gotErr != nil) != (wantErr != nil) {
		t.Fatalf("error boundary mismatch: got %v, want %v", gotErr, wantErr)
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Evaluate() = %#v, want %#v", got, want)
	}
}

// modelMarkerGenerator returns all declared markers plus one invalid marker.
func modelMarkerGenerator() *rapid.Generator[string] {
	return rapid.SampledFrom([]string{
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
		unknownModelMarker,
	})
}

// modelTerminalStates returns every terminal state in the model.
func modelTerminalStates() []string {
	return []string{
		StateAuthOK,
		StateAuthFail,
		StateAuthTempFail,
		StateAborted,
	}
}
