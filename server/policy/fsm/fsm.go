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

// Package fsm evaluates policy-owned auth FSM markers.
package fsm

import (
	"fmt"

	"github.com/croessner/nauthilus/server/policy"
)

type state string

const (
	stateInit                   state = "init"
	stateInputParsed            state = "input_parsed"
	statePreAuthChecked         state = "pre_auth_checked"
	stateAuthChecked            state = "auth_checked"
	stateAccountProviderChecked state = "account_provider_checked"
	stateAuthOK                 state = "auth_ok"
	stateAuthFail               state = "auth_fail"
	stateAuthTempFail           state = "auth_tempfail"
	stateAborted                state = "aborted"
)

const (
	// StateInit is the initial auth FSM state.
	StateInit = string(stateInit)

	// StateInputParsed is reached after parser success.
	StateInputParsed = string(stateInputParsed)

	// StatePreAuthChecked is reached after pre-auth checks pass.
	StatePreAuthChecked = string(statePreAuthChecked)

	// StateAuthChecked is reached after auth backend evaluation.
	StateAuthChecked = string(stateAuthChecked)

	// StateAccountProviderChecked is reached after account-provider evaluation.
	StateAccountProviderChecked = string(stateAccountProviderChecked)

	// StateAuthOK is the successful terminal state.
	StateAuthOK = string(stateAuthOK)

	// StateAuthFail is the denial terminal state.
	StateAuthFail = string(stateAuthFail)

	// StateAuthTempFail is the temporary-failure terminal state.
	StateAuthTempFail = string(stateAuthTempFail)

	// StateAborted is the aborted terminal state.
	StateAborted = string(stateAborted)
)

// Transition records one accepted target FSM transition.
type Transition struct {
	From        string
	EventMarker string
	To          string
}

// Result contains the outcome of applying target FSM event markers.
type Result struct {
	TerminalState   string
	TargetEventPath []string
	Transitions     []Transition
}

// ComparisonInput contains current production FSM facts and target markers.
type ComparisonInput struct {
	PolicyName           string
	ResponseMarker       string
	CurrentTerminalState string
	Operation            policy.Operation
	CurrentEventPath     []string
	TargetEventMarkers   []string
}

// ComparisonResult contains the side-by-side FSM diagnostic result.
type ComparisonResult struct {
	PolicyName           string
	ResponseMarker       string
	CurrentTerminalState string
	TargetTerminalState  string
	Error                string
	Operation            policy.Operation
	CurrentEventPath     []string
	TargetEventPath      []string
	Mismatch             bool
}

// Evaluate applies target FSM event markers from the initial state.
func Evaluate(markers []string) (Result, error) {
	current := stateInit
	result := Result{
		TargetEventPath: make([]string, 0, len(markers)),
		Transitions:     make([]Transition, 0, len(markers)),
	}

	for _, marker := range markers {
		next, err := nextState(current, marker)
		if err != nil {
			result.TerminalState = string(current)

			return result, err
		}

		result.TargetEventPath = append(result.TargetEventPath, marker)
		result.Transitions = append(result.Transitions, Transition{
			From:        string(current),
			EventMarker: marker,
			To:          string(next),
		})
		current = next
	}

	result.TerminalState = string(current)

	return result, nil
}

// Compare evaluates target markers and compares their terminal state with production.
func Compare(input ComparisonInput) ComparisonResult {
	result := ComparisonResult{
		PolicyName:           input.PolicyName,
		ResponseMarker:       input.ResponseMarker,
		CurrentTerminalState: input.CurrentTerminalState,
		Operation:            input.Operation,
		CurrentEventPath:     currentEventPath(input),
	}

	evaluation, err := Evaluate(input.TargetEventMarkers)
	result.TargetTerminalState = evaluation.TerminalState
	result.TargetEventPath = append([]string(nil), evaluation.TargetEventPath...)
	if err != nil {
		result.Error = err.Error()
		result.Mismatch = true

		return result
	}

	result.Mismatch = result.CurrentTerminalState != "" && result.CurrentTerminalState != result.TargetTerminalState

	return result
}

// TerminalStateForDecision returns the target terminal state for a final effect.
func TerminalStateForDecision(decision policy.Decision) string {
	switch decision {
	case policy.DecisionPermit:
		return string(stateAuthOK)
	case policy.DecisionDeny:
		return string(stateAuthFail)
	case policy.DecisionTempFail:
		return string(stateAuthTempFail)
	default:
		return ""
	}
}

// IsTerminal reports whether the state is terminal.
func IsTerminal(current string) bool {
	return terminal(state(current))
}

// NextState returns the next state for the supplied target marker.
func NextState(current string, marker string) (string, error) {
	next, err := nextState(state(current), marker)
	if err != nil {
		return "", err
	}

	return string(next), nil
}

func nextState(current state, marker string) (state, error) {
	if terminal(current) {
		return "", fmt.Errorf("invalid target auth fsm transition from terminal state: state=%s marker=%s", current, marker)
	}

	if marker == policy.FSMEventMarkerAbort {
		return stateAborted, nil
	}

	switch current {
	case stateInit:
		return nextFromInit(marker)
	case stateInputParsed:
		return nextFromInputParsed(marker)
	case statePreAuthChecked:
		return nextFromPreAuthChecked(marker)
	case stateAuthChecked:
		return nextFromAuthChecked(marker)
	case stateAccountProviderChecked:
		return nextFromAccountProviderChecked(marker)
	default:
		return "", fmt.Errorf("invalid target auth fsm state: state=%s marker=%s", current, marker)
	}
}

func nextFromInit(marker string) (state, error) {
	switch marker {
	case policy.FSMEventMarkerParseOK:
		return stateInputParsed, nil
	case policy.FSMEventMarkerParseFail:
		return stateAborted, nil
	default:
		return "", fmt.Errorf("invalid target auth fsm transition: state=%s marker=%s", stateInit, marker)
	}
}

func nextFromInputParsed(marker string) (state, error) {
	switch marker {
	case policy.FSMEventMarkerPreAuthOK:
		return statePreAuthChecked, nil
	case policy.FSMEventMarkerPreAuthDeny:
		return stateAuthFail, nil
	case policy.FSMEventMarkerPreAuthTempFail:
		return stateAuthTempFail, nil
	case policy.FSMEventMarkerPreAuthAbort:
		return stateAborted, nil
	case policy.FSMEventMarkerBasicAuthOK:
		return stateAuthOK, nil
	case policy.FSMEventMarkerBasicAuthFail:
		return stateAuthFail, nil
	default:
		return "", fmt.Errorf("invalid target auth fsm transition: state=%s marker=%s", stateInputParsed, marker)
	}
}

func nextFromPreAuthChecked(marker string) (state, error) {
	switch marker {
	case policy.FSMEventMarkerBasicAuthOK:
		return stateAuthOK, nil
	case policy.FSMEventMarkerBasicAuthFail:
		return stateAuthFail, nil
	case policy.FSMEventMarkerAuthEvaluated:
		return stateAuthChecked, nil
	case policy.FSMEventMarkerAccountProviderEvaluated:
		return stateAccountProviderChecked, nil
	default:
		return "", fmt.Errorf("invalid target auth fsm transition: state=%s marker=%s", statePreAuthChecked, marker)
	}
}

func nextFromAuthChecked(marker string) (state, error) {
	switch marker {
	case policy.FSMEventMarkerAuthPermit:
		return stateAuthOK, nil
	case policy.FSMEventMarkerAuthDeny:
		return stateAuthFail, nil
	case policy.FSMEventMarkerAuthTempFail, policy.FSMEventMarkerAuthEmptyUser:
		return stateAuthTempFail, nil
	case policy.FSMEventMarkerAuthEmptyPass:
		return stateAuthFail, nil
	default:
		return "", fmt.Errorf("invalid target auth fsm transition: state=%s marker=%s", stateAuthChecked, marker)
	}
}

func nextFromAccountProviderChecked(marker string) (state, error) {
	switch marker {
	case policy.FSMEventMarkerAuthPermit:
		return stateAuthOK, nil
	case policy.FSMEventMarkerAuthDeny:
		return stateAuthFail, nil
	case policy.FSMEventMarkerAuthTempFail:
		return stateAuthTempFail, nil
	default:
		return "", fmt.Errorf("invalid target auth fsm transition: state=%s marker=%s", stateAccountProviderChecked, marker)
	}
}

func terminal(current state) bool {
	switch current {
	case stateAuthOK, stateAuthFail, stateAuthTempFail, stateAborted:
		return true
	default:
		return false
	}
}

func currentEventPath(input ComparisonInput) []string {
	return append([]string(nil), input.CurrentEventPath...)
}
