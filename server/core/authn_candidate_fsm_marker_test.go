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

package core

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	policyfsm "github.com/croessner/nauthilus/v4/server/policy/fsm"
	"github.com/croessner/nauthilus/v4/server/policy/report"
)

// authnCandidateFSMMarkerCase captures one checkpoint selection and its expected auth FSM path.
type authnCandidateFSMMarkerCase struct {
	name      string
	operation policy.Operation
	preAuth   *report.FinalDecision
	final     *report.FinalDecision
	wantPath  []string
	wantState string
}

// authnCandidateFSMMarkerCases lists pre-auth, final, and account-listing marker projections.
func authnCandidateFSMMarkerCases() []authnCandidateFSMMarkerCase {
	return []authnCandidateFSMMarkerCase{
		{
			name:      "pre_auth denial applies only its own marker",
			operation: policy.OperationAuthenticate,
			preAuth:   &report.FinalDecision{Stage: policy.StagePreAuth, FSMEventMarker: policy.FSMEventMarkerPreAuthDeny},
			final:     &report.FinalDecision{Stage: policy.StagePreAuth, FSMEventMarker: policy.FSMEventMarkerPreAuthDeny},
			wantPath:  []string{policy.FSMEventMarkerParseOK, policy.FSMEventMarkerPreAuthDeny},
			wantState: policyfsm.StateAuthFail,
		},
		{
			name:      "auth_decision denial defaults an unmarked neutral pre-auth selection",
			operation: policy.OperationAuthenticate,
			preAuth:   &report.FinalDecision{Stage: policy.StagePreAuth},
			final:     &report.FinalDecision{Stage: policy.StageAuthDecision, FSMEventMarker: policy.FSMEventMarkerAuthDeny},
			wantPath: []string{
				policy.FSMEventMarkerParseOK, policy.FSMEventMarkerPreAuthOK, policy.FSMEventMarkerAuthEvaluated,
				policy.FSMEventMarkerAuthDeny,
			},
			wantState: policyfsm.StateAuthFail,
		},
		{
			name:      "list_accounts permit enters through the account provider",
			operation: policy.OperationListAccounts,
			final:     &report.FinalDecision{Stage: policy.StageAuthDecision, FSMEventMarker: policy.FSMEventMarkerAuthPermit},
			wantPath: []string{
				policy.FSMEventMarkerParseOK, policy.FSMEventMarkerPreAuthOK,
				policy.FSMEventMarkerAccountProviderEvaluated, policy.FSMEventMarkerAuthPermit,
			},
			wantState: policyfsm.StateAuthOK,
		},
	}
}

func TestAuthnCandidateFSMEventMarkersProjectCheckpointSelections(t *testing.T) {
	for _, test := range authnCandidateFSMMarkerCases() {
		t.Run(test.name, func(t *testing.T) {
			execution := &authnCandidateExecution{
				operation: test.operation,
				selected:  map[string]*report.FinalDecision{string(policy.StagePreAuth): test.preAuth},
			}

			path := execution.authnCandidateFSMEventMarkers(test.final)
			if !slices.Equal(path, test.wantPath) {
				t.Fatalf("marker path = %v, want %v", path, test.wantPath)
			}

			result, err := policyfsm.Evaluate(path)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result.TerminalState != test.wantState {
				t.Fatalf("terminal state = %q, want %q", result.TerminalState, test.wantState)
			}
		})
	}
}

// TestAuthnCandidateUnmarkedTerminalRuleIsRejectedBeforeRuntime pins the production symptom of an unmarked deny rule
// at auth_decision and proves configuration validation rejects the same rule before it can be selected.
func TestAuthnCandidateUnmarkedTerminalRuleIsRejectedBeforeRuntime(t *testing.T) {
	execution := &authnCandidateExecution{operation: policy.OperationAuthenticate}
	final := &report.FinalDecision{Stage: policy.StageAuthDecision, Effect: policy.DecisionDeny}

	_, err := policyfsm.Evaluate(execution.authnCandidateFSMEventMarkers(final))
	if err == nil || !strings.Contains(err.Error(), "invalid target auth fsm transition: state=auth_checked marker=") {
		t.Fatalf("Evaluate() error = %v, want the unmarked auth_checked transition failure", err)
	}

	err = policyfsm.ValidateRuleMarker(policy.OperationAuthenticate, final.Stage, final.Effect, final.FSMEventMarker)
	if !errors.Is(err, policyfsm.ErrRuleMarkerRequired) {
		t.Fatalf("ValidateRuleMarker() error = %v, want %v", err, policyfsm.ErrRuleMarkerRequired)
	}
}

// TestAuthnIntermediatePermitIsRejectedBeforeRuntime pins the runtime failure of a permit selected before the final
// checkpoint and proves configuration validation excludes that decision at intermediate checkpoints.
func TestAuthnIntermediatePermitIsRejectedBeforeRuntime(t *testing.T) {
	_, done, err := resolveAuthnCheckpointResult(
		string(policy.StageSubjectAnalysis),
		policy.OperationAuthenticate,
		nil,
		authnApplicationResult{},
		mustAuthnDecisionResponse(t, decision.EffectPermit),
		false,
	)
	if !done || err == nil || !strings.Contains(err.Error(), "unsupported intermediate authn Policy effect") {
		t.Fatalf("resolveAuthnCheckpointResult() done=%v error=%v, want the intermediate permit failure", done, err)
	}

	if slices.Contains(policy.AuthnCheckpointDecisions(false), policy.DecisionPermit) {
		t.Fatal("intermediate checkpoints allow permit")
	}
}

// TestAuthnFinalNeutralIsRejectedBeforeRuntime pins the auth FSM failure of a neutral rule selected at the final
// checkpoint and proves configuration validation excludes that decision there.
func TestAuthnFinalNeutralIsRejectedBeforeRuntime(t *testing.T) {
	execution := &authnCandidateExecution{operation: policy.OperationAuthenticate}
	final := &report.FinalDecision{Stage: policy.StageAuthDecision, Effect: policy.DecisionNeutral}

	_, err := policyfsm.Evaluate(execution.authnCandidateFSMEventMarkers(final))
	if err == nil || !strings.Contains(err.Error(), "invalid target auth fsm transition: state=auth_checked marker=") {
		t.Fatalf("Evaluate() error = %v, want the unmarked auth_checked transition failure", err)
	}

	if slices.Contains(policy.AuthnCheckpointDecisions(true), policy.DecisionNeutral) {
		t.Fatal("the final checkpoint allows neutral")
	}
}
