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
	"fmt"
	"slices"
	"strings"

	"github.com/croessner/nauthilus/v4/server/policy"
)

var (
	// ErrRuleMarkerRequired identifies a terminal policy rule without an auth FSM event marker.
	ErrRuleMarkerRequired = errors.New("auth fsm event marker required")

	// ErrRuleMarkerInvalid identifies a policy rule marker the auth FSM cannot apply at its checkpoint.
	ErrRuleMarkerInvalid = errors.New("auth fsm event marker invalid")
)

// policyRuleMarkers lists the markers configured policy rules may select, in stable diagnostic order.
// Parser, evaluation, caller-auth, and generic abort markers stay owned by the host orchestration.
var policyRuleMarkers = []string{
	policy.FSMEventMarkerPreAuthOK,
	policy.FSMEventMarkerPreAuthDeny,
	policy.FSMEventMarkerPreAuthTempFail,
	policy.FSMEventMarkerPreAuthAbort,
	policy.FSMEventMarkerAuthPermit,
	policy.FSMEventMarkerAuthDeny,
	policy.FSMEventMarkerAuthTempFail,
	policy.FSMEventMarkerAuthEmptyUser,
	policy.FSMEventMarkerAuthEmptyPass,
}

// RuleMarkerError describes why one policy rule marker cannot drive the auth FSM.
type RuleMarkerError struct {
	Kind       error
	Allowed    []string
	Checkpoint policy.Stage
	Decision   policy.Decision
	Marker     string
}

// Error returns the checkpoint, decision, and allowed markers of the rejected rule marker.
func (e *RuleMarkerError) Error() string {
	allowed := "none, the auth FSM has no transition for this decision at this checkpoint"
	if len(e.Allowed) > 0 {
		allowed = strings.Join(e.Allowed, ", ")
	}

	if errors.Is(e.Kind, ErrRuleMarkerRequired) {
		return fmt.Sprintf("decision %s at checkpoint %s requires fsm_event_marker; allowed: %s",
			e.Decision, e.Checkpoint, allowed)
	}

	return fmt.Sprintf("fsm_event_marker %s is not valid for decision %s at checkpoint %s; allowed: %s",
		e.Marker, e.Decision, e.Checkpoint, allowed)
}

// Unwrap exposes the rule-marker error category.
func (e *RuleMarkerError) Unwrap() error {
	return e.Kind
}

// CheckpointEventPrefix returns the markers the authn orchestration applies before the marker of a rule
// selected at checkpoint. An empty preAuthMarker selects the neutral pre-auth marker.
func CheckpointEventPrefix(operation policy.Operation, checkpoint policy.Stage, preAuthMarker string) []string {
	markers := []string{policy.FSMEventMarkerParseOK}
	if checkpoint == policy.StagePreAuth {
		return markers
	}

	if preAuthMarker == "" {
		preAuthMarker = policy.FSMEventMarkerPreAuthOK
	}

	markers = append(markers, preAuthMarker)

	if operation == policy.OperationListAccounts {
		return append(markers, policy.FSMEventMarkerAccountProviderEvaluated)
	}

	return append(markers, policy.FSMEventMarkerAuthEvaluated)
}

// AllowedRuleMarkers returns the policy rule markers that move the auth FSM from the checkpoint entry state
// to the state implied by decision, in stable order.
func AllowedRuleMarkers(operation policy.Operation, checkpoint policy.Stage, decision policy.Decision) []string {
	entry, err := Evaluate(CheckpointEventPrefix(operation, checkpoint, ""))
	if err != nil {
		return nil
	}

	want := ruleTargetState(state(entry.TerminalState), decision)
	if want == "" {
		return nil
	}

	var allowed []string

	for _, marker := range policyRuleMarkers {
		if next, nextErr := nextState(state(entry.TerminalState), marker); nextErr == nil && next == want {
			allowed = append(allowed, marker)
		}
	}

	return allowed
}

// ValidateRuleMarker reports whether a rule selected at checkpoint can apply marker for decision. Terminal
// decisions must select a marker; neutral decisions may omit it.
func ValidateRuleMarker(
	operation policy.Operation,
	checkpoint policy.Stage,
	decision policy.Decision,
	marker string,
) error {
	allowed := AllowedRuleMarkers(operation, checkpoint, decision)

	if marker == "" {
		if TerminalStateForDecision(decision) == "" {
			return nil
		}

		return &RuleMarkerError{
			Kind: ErrRuleMarkerRequired, Allowed: allowed, Checkpoint: checkpoint, Decision: decision,
		}
	}

	if slices.Contains(allowed, marker) {
		return nil
	}

	return &RuleMarkerError{
		Kind: ErrRuleMarkerInvalid, Allowed: allowed, Checkpoint: checkpoint, Decision: decision, Marker: marker,
	}
}

// ruleTargetState returns the state a rule decision must reach from entry, or empty when no rule marker applies.
func ruleTargetState(entry state, decision policy.Decision) state {
	if terminalState := TerminalStateForDecision(decision); terminalState != "" {
		return state(terminalState)
	}

	if decision == policy.DecisionNeutral && entry == stateInputParsed {
		return statePreAuthChecked
	}

	return ""
}
