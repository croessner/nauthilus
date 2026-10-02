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
	"slices"
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy"
)

func TestCheckpointEventPrefixMirrorsAuthnOrchestration(t *testing.T) {
	tests := []struct {
		name       string
		operation  policy.Operation
		checkpoint policy.Stage
		want       []string
	}{
		{
			name: "pre_auth applies only the parser marker", operation: policy.OperationAuthenticate,
			checkpoint: policy.StagePreAuth, want: []string{policy.FSMEventMarkerParseOK},
		},
		{
			name: "auth_decision follows the passed pre-auth checkpoint", operation: policy.OperationAuthenticate,
			checkpoint: policy.StageAuthDecision,
			want: []string{
				policy.FSMEventMarkerParseOK, policy.FSMEventMarkerPreAuthOK, policy.FSMEventMarkerAuthEvaluated,
			},
		},
		{
			name: "intermediate checkpoints share the auth evaluation entry", operation: policy.OperationLookupIdentity,
			checkpoint: policy.StageSubjectAnalysis,
			want: []string{
				policy.FSMEventMarkerParseOK, policy.FSMEventMarkerPreAuthOK, policy.FSMEventMarkerAuthEvaluated,
			},
		},
		{
			name: "list_accounts enters through the account provider", operation: policy.OperationListAccounts,
			checkpoint: policy.StageAuthDecision,
			want: []string{
				policy.FSMEventMarkerParseOK, policy.FSMEventMarkerPreAuthOK,
				policy.FSMEventMarkerAccountProviderEvaluated,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := CheckpointEventPrefix(test.operation, test.checkpoint)
			if !slices.Equal(got, test.want) {
				t.Fatalf("CheckpointEventPrefix() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestAllowedRuleMarkersFollowTransitionTable(t *testing.T) {
	tests := []struct {
		name       string
		operation  policy.Operation
		checkpoint policy.Stage
		decision   policy.Decision
		want       []string
	}{
		{
			name: "pre_auth neutral", operation: policy.OperationAuthenticate, checkpoint: policy.StagePreAuth,
			decision: policy.DecisionNeutral, want: []string{policy.FSMEventMarkerPreAuthOK},
		},
		{
			name: "pre_auth deny", operation: policy.OperationAuthenticate, checkpoint: policy.StagePreAuth,
			decision: policy.DecisionDeny, want: []string{policy.FSMEventMarkerPreAuthDeny},
		},
		{
			name: "pre_auth tempfail", operation: policy.OperationLookupIdentity, checkpoint: policy.StagePreAuth,
			decision: policy.DecisionTempFail, want: []string{policy.FSMEventMarkerPreAuthTempFail},
		},
		{
			name: "pre_auth permit has no policy marker", operation: policy.OperationAuthenticate,
			checkpoint: policy.StagePreAuth, decision: policy.DecisionPermit, want: nil,
		},
		{
			name: "auth_decision permit", operation: policy.OperationAuthenticate, checkpoint: policy.StageAuthDecision,
			decision: policy.DecisionPermit, want: []string{policy.FSMEventMarkerAuthPermit},
		},
		{
			name: "auth_decision deny", operation: policy.OperationAuthenticate, checkpoint: policy.StageAuthDecision,
			decision: policy.DecisionDeny,
			want:     []string{policy.FSMEventMarkerAuthDeny, policy.FSMEventMarkerAuthEmptyPass},
		},
		{
			name: "auth_decision tempfail", operation: policy.OperationAuthenticate, checkpoint: policy.StageAuthDecision,
			decision: policy.DecisionTempFail,
			want:     []string{policy.FSMEventMarkerAuthTempFail, policy.FSMEventMarkerAuthEmptyUser},
		},
		{
			name: "auth_decision neutral has no policy marker", operation: policy.OperationAuthenticate,
			checkpoint: policy.StageAuthDecision, decision: policy.DecisionNeutral, want: nil,
		},
		{
			name: "list_accounts deny", operation: policy.OperationListAccounts, checkpoint: policy.StageAuthDecision,
			decision: policy.DecisionDeny, want: []string{policy.FSMEventMarkerAuthDeny},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := AllowedRuleMarkers(test.operation, test.checkpoint, test.decision)
			if !slices.Equal(got, test.want) {
				t.Fatalf("AllowedRuleMarkers() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestValidateRuleMarker(t *testing.T) {
	tests := []struct {
		name       string
		operation  policy.Operation
		checkpoint policy.Stage
		decision   policy.Decision
		marker     string
		wantErr    error
	}{
		{
			name: "omitted terminal marker is derived", operation: policy.OperationAuthenticate,
			checkpoint: policy.StageAuthDecision, decision: policy.DecisionDeny,
		},
		{
			name: "omitted list_accounts marker is derived", operation: policy.OperationListAccounts,
			checkpoint: policy.StageAuthDecision, decision: policy.DecisionTempFail,
		},
		{
			name: "pre_auth permit has no derivable marker", operation: policy.OperationAuthenticate,
			checkpoint: policy.StagePreAuth, decision: policy.DecisionPermit, wantErr: ErrRuleMarkerInvalid,
		},
		{
			name: "valid terminal marker", operation: policy.OperationAuthenticate,
			checkpoint: policy.StageAuthDecision, decision: policy.DecisionDeny, marker: policy.FSMEventMarkerAuthDeny,
		},
		{
			name: "marker from another checkpoint", operation: policy.OperationAuthenticate,
			checkpoint: policy.StageAuthDecision, decision: policy.DecisionDeny,
			marker: policy.FSMEventMarkerPreAuthDeny, wantErr: ErrRuleMarkerInvalid,
		},
		{
			name: "internal orchestration marker", operation: policy.OperationAuthenticate,
			checkpoint: policy.StagePreAuth, decision: policy.DecisionDeny,
			marker: policy.FSMEventMarkerBasicAuthFail, wantErr: ErrRuleMarkerInvalid,
		},
		{
			name: "unknown marker", operation: policy.OperationAuthenticate,
			checkpoint: policy.StageAuthDecision, decision: policy.DecisionPermit,
			marker: "auth.fsm.event.unknown", wantErr: ErrRuleMarkerInvalid,
		},
		{
			name: "neutral pre_auth may omit the marker", operation: policy.OperationAuthenticate,
			checkpoint: policy.StagePreAuth, decision: policy.DecisionNeutral,
		},
		{
			name: "neutral pre_auth may select pre_auth_ok", operation: policy.OperationAuthenticate,
			checkpoint: policy.StagePreAuth, decision: policy.DecisionNeutral, marker: policy.FSMEventMarkerPreAuthOK,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateRuleMarker(test.operation, test.checkpoint, test.decision, test.marker)
			if test.wantErr == nil {
				if err != nil {
					t.Fatalf("ValidateRuleMarker() error = %v", err)
				}

				return
			}

			if !errors.Is(err, test.wantErr) {
				t.Fatalf("ValidateRuleMarker() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestAllowedRuleMarkersReachDecisionTerminalState(t *testing.T) {
	operations := []policy.Operation{
		policy.OperationAuthenticate, policy.OperationLookupIdentity, policy.OperationListAccounts,
	}
	checkpoints := []policy.Stage{policy.StagePreAuth, policy.StageSubjectAnalysis, policy.StageAuthDecision}
	decisions := []policy.Decision{policy.DecisionPermit, policy.DecisionDeny, policy.DecisionTempFail}

	for _, operation := range operations {
		for _, checkpoint := range checkpoints {
			for _, decision := range decisions {
				for _, marker := range AllowedRuleMarkers(operation, checkpoint, decision) {
					path := append(CheckpointEventPrefix(operation, checkpoint), marker)

					result, err := Evaluate(path)
					if err != nil {
						t.Fatalf("%s/%s/%s marker %s: Evaluate() error = %v", operation, checkpoint, decision, marker, err)
					}

					if result.TerminalState != TerminalStateForDecision(decision) {
						t.Fatalf("%s/%s/%s marker %s: terminal state = %s, want %s", operation, checkpoint, decision,
							marker, result.TerminalState, TerminalStateForDecision(decision))
					}
				}
			}
		}
	}
}

func TestDefaultRuleMarkerDerivesFromCheckpointAndDecision(t *testing.T) {
	tests := []struct {
		name       string
		checkpoint policy.Stage
		decision   policy.Decision
		want       string
	}{
		{name: "pre_auth neutral", checkpoint: policy.StagePreAuth, decision: policy.DecisionNeutral, want: policy.FSMEventMarkerPreAuthOK},
		{name: "pre_auth deny", checkpoint: policy.StagePreAuth, decision: policy.DecisionDeny, want: policy.FSMEventMarkerPreAuthDeny},
		{name: "pre_auth tempfail", checkpoint: policy.StagePreAuth, decision: policy.DecisionTempFail, want: policy.FSMEventMarkerPreAuthTempFail},
		{name: "pre_auth permit", checkpoint: policy.StagePreAuth, decision: policy.DecisionPermit},
		{name: "auth_decision permit", checkpoint: policy.StageAuthDecision, decision: policy.DecisionPermit, want: policy.FSMEventMarkerAuthPermit},
		{name: "auth_decision deny", checkpoint: policy.StageAuthDecision, decision: policy.DecisionDeny, want: policy.FSMEventMarkerAuthDeny},
		{name: "auth_decision tempfail", checkpoint: policy.StageAuthDecision, decision: policy.DecisionTempFail, want: policy.FSMEventMarkerAuthTempFail},
		{name: "auth_decision neutral", checkpoint: policy.StageAuthDecision, decision: policy.DecisionNeutral},
		{name: "intermediate deny", checkpoint: policy.StageSubjectAnalysis, decision: policy.DecisionDeny, want: policy.FSMEventMarkerAuthDeny},
		{name: "intermediate neutral", checkpoint: policy.StageAuthBackend, decision: policy.DecisionNeutral},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := DefaultRuleMarker(test.checkpoint, test.decision); got != test.want {
				t.Fatalf("DefaultRuleMarker() = %q, want %q", got, test.want)
			}
		})
	}
}

// TestDefaultRuleMarkerIsAlwaysAllowed proves a derived marker never needs the validation an explicit marker gets.
func TestDefaultRuleMarkerIsAlwaysAllowed(t *testing.T) {
	operations := []policy.Operation{
		policy.OperationAuthenticate, policy.OperationLookupIdentity, policy.OperationListAccounts,
	}
	checkpoints := []policy.Stage{
		policy.StagePreAuth, policy.StageAuthBackend, policy.StageSubjectAnalysis, policy.StageAccountProvider,
		policy.StageAuthDecision,
	}
	decisions := []policy.Decision{
		policy.DecisionPermit, policy.DecisionDeny, policy.DecisionTempFail, policy.DecisionNeutral,
	}

	for _, operation := range operations {
		for _, checkpoint := range checkpoints {
			for _, decision := range decisions {
				marker := DefaultRuleMarker(checkpoint, decision)
				allowed := AllowedRuleMarkers(operation, checkpoint, decision)

				if marker == "" {
					if decision != policy.DecisionNeutral && len(allowed) > 0 {
						t.Fatalf("%s/%s/%s: no default marker, allowed %v", operation, checkpoint, decision, allowed)
					}

					continue
				}

				if !slices.Contains(allowed, marker) {
					t.Fatalf("%s/%s/%s: default marker %s not in %v", operation, checkpoint, decision, marker, allowed)
				}
			}
		}
	}
}
