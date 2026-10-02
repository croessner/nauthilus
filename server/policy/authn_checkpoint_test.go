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

package policy

import (
	"slices"
	"testing"
)

func TestFinalAuthnCheckpointFollowsAuthenticationWorkOrder(t *testing.T) {
	tests := []struct {
		name        string
		checkpoints []string
		want        string
	}{
		{name: "empty plan", want: ""},
		{name: "builtin authenticate plan", checkpoints: []string{"auth_decision", "pre_auth"}, want: "auth_decision"},
		{
			name:        "configured plan without auth_decision",
			checkpoints: []string{"subject_analysis", "pre_auth", "auth_backend"}, want: "subject_analysis",
		},
		{
			name:        "list_accounts plan",
			checkpoints: []string{"auth_decision", "account_provider"}, want: "auth_decision",
		},
		{name: "unknown names sort last and lexically", checkpoints: []string{"zeta", "pre_auth", "alpha"}, want: "zeta"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := slices.Clone(test.checkpoints)
			if got := FinalAuthnCheckpoint(input); got != test.want {
				t.Fatalf("FinalAuthnCheckpoint() = %q, want %q", got, test.want)
			}

			if !slices.Equal(input, test.checkpoints) {
				t.Fatalf("FinalAuthnCheckpoint() mutated its input to %v", input)
			}
		})
	}
}

func TestAuthnCheckpointDecisionsSeparateFinalAndIntermediateOutcomes(t *testing.T) {
	if got := AuthnCheckpointDecisions(true); !slices.Equal(got, []Decision{DecisionPermit, DecisionDeny, DecisionTempFail}) {
		t.Fatalf("final decisions = %v", got)
	}

	if got := AuthnCheckpointDecisions(false); !slices.Equal(got, []Decision{DecisionDeny, DecisionTempFail, DecisionNeutral}) {
		t.Fatalf("intermediate decisions = %v", got)
	}
}
