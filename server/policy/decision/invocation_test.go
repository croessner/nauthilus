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
	"errors"
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

func TestDecisionCheckpointSharesImmutableFactsWithoutAllocation(t *testing.T) {
	facts, err := decision.NewFactSet(nil)
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	checkpoint, err := decision.NewCheckpoint("pre_auth", facts)
	if err != nil {
		t.Fatalf("NewCheckpoint() error = %v", err)
	}

	if allocs := testing.AllocsPerRun(100, func() { _ = checkpoint.Facts() }); allocs != 0 {
		t.Fatalf("Checkpoint.Facts() allocations = %.0f, want 0", allocs)
	}
}

func TestFactSetAllIteratesWithoutAllocation(t *testing.T) {
	provenance, err := decision.NewProvenance(decision.FactSourceCaller, "client-a", "request")
	if err != nil {
		t.Fatalf("NewProvenance() error = %v", err)
	}

	text := "value"

	value, err := decision.NewValue(decision.ValueInput{String: &text})
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	first, _ := decision.NewFact("input.first", decision.FactCategoryResource, value, provenance)
	second, _ := decision.NewFact("input.second", decision.FactCategoryResource, value, provenance)

	facts, err := decision.NewFactSet([]decision.Fact{first, second})
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	var ids []string
	for fact := range facts.All() {
		ids = append(ids, fact.ID())
	}

	if len(ids) != 2 || ids[0] != "input.first" || ids[1] != "input.second" {
		t.Fatalf("FactSet.All() = %v, want ordered facts", ids)
	}

	if allocs := testing.AllocsPerRun(100, func() {
		for range facts.All() {
		}
	}); allocs != 0 {
		t.Fatalf("FactSet.All() allocations = %.0f, want 0", allocs)
	}
}

func TestFactSetWithAndMergeKeepOrderAndRejectCollisions(t *testing.T) {
	provenance, err := decision.NewProvenance(decision.FactSourceCaller, "client-a", "request")
	if err != nil {
		t.Fatalf("NewProvenance() error = %v", err)
	}

	text := "value"

	value, err := decision.NewValue(decision.ValueInput{String: &text})
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	first, _ := decision.NewFact("input.first", decision.FactCategoryResource, value, provenance)
	second, _ := decision.NewFact("input.second", decision.FactCategoryResource, value, provenance)

	base, err := decision.NewFactSet([]decision.Fact{first})
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	extra, err := decision.NewFactSet([]decision.Fact{second})
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	merged, err := decision.MergeFactSets(base, extra)
	if err != nil {
		t.Fatalf("MergeFactSets() error = %v", err)
	}

	if ids := merged.Facts(); len(ids) != 2 || ids[0].ID() != "input.first" || ids[1].ID() != "input.second" {
		t.Fatalf("MergeFactSets() = %v, want base then extra", ids)
	}

	if base.Len() != 1 {
		t.Fatal("MergeFactSets() changed the base set")
	}

	if _, err := merged.With(first); !errors.Is(err, decision.ErrFactCollision) {
		t.Fatalf("With() collision error = %v, want ErrFactCollision", err)
	}

	if _, err := base.With(decision.Fact{}); !errors.Is(err, decision.ErrInvalidFact) {
		t.Fatalf("With() unconstructed fact error = %v, want ErrInvalidFact", err)
	}

	empty, _ := decision.NewFactSet(nil)
	if allocs := testing.AllocsPerRun(100, func() {
		_, _ = base.With()
		_, _ = decision.MergeFactSets(base, empty)
		_, _ = decision.MergeFactSets(empty, base)
	}); allocs != 0 {
		t.Fatalf("empty merge allocations = %.0f, want 0", allocs)
	}
}
