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

package decision_test

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

func TestDecisionServiceAuthenticationInputOwnsOpaqueEvidence(t *testing.T) {
	credential := []byte("opaque-evidence")

	input, err := decision.NewAuthenticationInput(decision.AuthenticationEvidence{
		Kind:          "bearer",
		Credential:    credential,
		TransportKind: "http",
		Listener:      "http.policy",
		HTTPRoute:     "/api/v1/policy/decisions",
		GRPCMethod:    "/nauthilus.policy.v1.DecisionService/Evaluate",
		Peer:          "192.0.2.10",
		MTLSIdentity:  "spiffe://example.test/policy-client",
		Protected:     true,
	})
	if err != nil {
		t.Fatalf("NewAuthenticationInput() error = %v", err)
	}

	credential[0] = 'X'
	copyOne := input.Credential()
	copyOne[0] = 'Y'

	if string(input.Credential()) != "opaque-evidence" {
		t.Fatal("AuthenticationInput exposed mutable credential storage")
	}

	if input.Listener() != "http.policy" ||
		input.HTTPRoute() != "/api/v1/policy/decisions" ||
		input.GRPCMethod() != "/nauthilus.policy.v1.DecisionService/Evaluate" ||
		input.Peer() != "192.0.2.10" ||
		input.MTLSIdentity() != "spiffe://example.test/policy-client" ||
		!input.Protected() {
		t.Fatal("AuthenticationInput did not preserve server-observed transport evidence")
	}
}

func TestDecisionCheckpointOwnsFacts(t *testing.T) {
	facts, err := decision.NewFactSet(nil)
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	checkpoint, err := decision.NewCheckpoint("pre_auth", facts)
	if err != nil {
		t.Fatalf("NewCheckpoint() error = %v", err)
	}

	if checkpoint.Name() != "pre_auth" || checkpoint.Facts().Len() != 0 {
		t.Fatalf("Checkpoint = %q/%d, want pre_auth/0", checkpoint.Name(), checkpoint.Facts().Len())
	}
}
