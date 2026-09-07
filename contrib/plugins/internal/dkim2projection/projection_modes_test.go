// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package dkim2projection

import (
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

func TestVerifierProjectionAcceptsCurrentScopeWithoutHistoryEvaluation(t *testing.T) {
	request := asCurrentProjection(t, testDecisionRequest(t, "192.0.2.25"))

	if _, err := Decode(request); err != nil {
		t.Fatalf("Decode() error = %v for valid current projection", err)
	}
}

func TestVerifierProjectionAcceptsOrdinaryChainWithoutCustodyLinks(t *testing.T) {
	request := testDecisionRequestWithHops(t, []Hop{
		testUnchangedHop(1, CustodyOrigin),
		testUnchangedHop(2, "ordinary"),
	})

	if _, err := Decode(request); err != nil {
		t.Fatalf("Decode() error = %v for valid ordinary chain", err)
	}
}

func TestVerifierProjectionAcceptsEvaluatedNextDomainCustody(t *testing.T) {
	request := testDecisionRequestWithHops(t, []Hop{
		testUnchangedHop(1, CustodyOrigin),
		testUnchangedHop(2, CustodyNextDomain),
	})
	request = replaceRequestStringFact(t, request, FactCustodyStructure, CustodyLinksEvaluated)

	if _, err := Decode(request); err != nil {
		t.Fatalf("Decode() error = %v for valid next-domain chain", err)
	}
}

func TestVerifierProjectionAcceptsTerminalCustodyOnlyAtFinalHop(t *testing.T) {
	request := testDecisionRequestWithHops(t, []Hop{
		testUnchangedHop(1, CustodyOrigin),
		testUnchangedHop(2, CustodyOrdinary),
		testUnchangedHop(3, CustodyTerminal),
	})
	request = replaceRequestStringFact(t, request, FactCustodyStructure, CustodyTerminalRequires)

	if _, err := Decode(request); err != nil {
		t.Fatalf("Decode() error = %v for valid terminal chain", err)
	}
}

//nolint:funlen // The table keeps every mode and custody fail-closed boundary together.
func TestVerifierProjectionRejectsIncoherentProjectionModesAndCustody(t *testing.T) {
	tests := []struct {
		name    string
		request func(*testing.T) pluginapi.DecisionFactRequest
	}{
		{
			name: "current scope with multiple records",
			request: func(t *testing.T) pluginapi.DecisionFactRequest {
				request := testDecisionRequestWithHops(t, []Hop{
					testUnchangedHop(1, CustodyOrigin), testUnchangedHop(2, CustodyOrdinary),
				})

				return asCurrentProjection(t, request)
			},
		},
		{
			name: "current scope with evaluated history",
			request: func(t *testing.T) pluginapi.DecisionFactRequest {
				return replaceRequestStringFact(t, testDecisionRequest(t, "192.0.2.25"), FactScope, ScopeCurrent)
			},
		},
		{
			name: "current pass with non-evaluated custody",
			request: func(t *testing.T) pluginapi.DecisionFactRequest {
				request := asCurrentProjection(t, testDecisionRequest(t, "192.0.2.25"))

				return replaceRequestStringFact(t, request, FactCustodyStructure, StateNotEvaluated)
			},
		},
		{
			name: "chain scope with partial history",
			request: func(t *testing.T) pluginapi.DecisionFactRequest {
				return replaceRequestStringFact(t, testDecisionRequest(t, "192.0.2.25"), FactHistoricalContent, "partial")
			},
		},
		{
			name: "chain scope with non-evaluated protection",
			request: func(t *testing.T) pluginapi.DecisionFactRequest {
				return replaceRequestStringFacts(t, testDecisionRequest(t, "192.0.2.25"), map[string]string{
					FactDoNotModifyState:  StateNotEvaluated,
					FactDoNotExplodeState: StateNotEvaluated,
				})
			},
		},
		{
			name: "absent custody with next-domain transition",
			request: func(t *testing.T) pluginapi.DecisionFactRequest {
				return testDecisionRequestWithHops(t, []Hop{
					testUnchangedHop(1, CustodyOrigin), testUnchangedHop(2, CustodyNextDomain),
				})
			},
		},
		{
			name: "evaluated links without next-domain transition",
			request: func(t *testing.T) pluginapi.DecisionFactRequest {
				request := testDecisionRequestWithHops(t, []Hop{
					testUnchangedHop(1, CustodyOrigin), testUnchangedHop(2, CustodyOrdinary),
				})

				return replaceRequestStringFact(t, request, FactCustodyStructure, CustodyLinksEvaluated)
			},
		},
		{
			name: "terminal aggregate without terminal final hop",
			request: func(t *testing.T) pluginapi.DecisionFactRequest {
				request := testDecisionRequestWithHops(t, []Hop{
					testUnchangedHop(1, CustodyOrigin), testUnchangedHop(2, CustodyOrdinary),
				})

				return replaceRequestStringFact(t, request, FactCustodyStructure, CustodyTerminalRequires)
			},
		},
		{
			name: "terminal transition before final hop",
			request: func(t *testing.T) pluginapi.DecisionFactRequest {
				request := testDecisionRequestWithHops(t, []Hop{
					testUnchangedHop(1, CustodyOrigin),
					testUnchangedHop(2, CustodyTerminal),
					testUnchangedHop(3, CustodyOrdinary),
				})

				return replaceRequestStringFact(t, request, FactCustodyStructure, CustodyTerminalRequires)
			},
		},
		{
			name: "multiple terminal transitions",
			request: func(t *testing.T) pluginapi.DecisionFactRequest {
				request := testDecisionRequestWithHops(t, []Hop{
					testUnchangedHop(1, CustodyOrigin),
					testUnchangedHop(2, CustodyTerminal),
					testUnchangedHop(3, CustodyTerminal),
				})

				return replaceRequestStringFact(t, request, FactCustodyStructure, CustodyTerminalRequires)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Decode(test.request(t)); err == nil {
				t.Fatal("Decode() error = nil for incoherent projection")
			}
		})
	}
}

// asCurrentProjection maps a binding-valid request onto the non-evaluated current-scope aggregate state.
func asCurrentProjection(t *testing.T, request pluginapi.DecisionFactRequest) pluginapi.DecisionFactRequest {
	t.Helper()

	return replaceRequestStringFacts(t, request, map[string]string{
		FactScope:                ScopeCurrent,
		FactHistoricalContent:    StateNotEvaluated,
		FactHistoricalSignatures: StateNotEvaluated,
		FactDoNotModifyState:     StateNotEvaluated,
		FactDoNotExplodeState:    StateNotEvaluated,
	})
}

// replaceRequestStringFacts applies a compact set of immutable string fact replacements.
func replaceRequestStringFacts(
	t *testing.T,
	request pluginapi.DecisionFactRequest,
	replacements map[string]string,
) pluginapi.DecisionFactRequest {
	t.Helper()

	for id, value := range replacements {
		request = replaceRequestStringFact(t, request, id, value)
	}

	return request
}

// testDecisionRequestWithHops creates a complete-chain request with producer-compatible bindings.
func testDecisionRequestWithHops(t *testing.T, hops []Hop) pluginapi.DecisionFactRequest {
	t.Helper()

	boundHops, ProjectionBinding := testBoundHops(hops)
	last := boundHops[len(boundHops)-1]
	request := testDecisionRequest(t, "192.0.2.25")
	request = replaceRequestFact(t, request, "resource.dkim2.projection_binding", testBytesValue(t, ProjectionBinding))
	request = replaceRequestFact(t, request, "resource.dkim2.chain", testChainValue(t, boundHops))
	request = replaceRequestFact(t, request, "resource.dkim2.target_sequence", testIntegerValue(t, last.Sequence))
	request = replaceRequestFact(t, request, "resource.dkim2.target_message_instance", testIntegerValue(t, last.MessageInstance))
	request = replaceRequestFact(t, request, "resource.dkim2.claimed_hop_count", testIntegerValue(t, int64(len(boundHops))))

	return request
}

// testUnchangedHop returns one deterministic pass hop without Recipe changes or protection flags.
func testUnchangedHop(Sequence int64, CustodyTransition string) Hop {
	return Hop{
		SignerDomain: "relay.example", SignatureAlgorithms: []string{"ed25519-sha256"}, SignatureState: "pass",
		CustodyTransition: CustodyTransition, RecipeMode: "unchanged", RecipeBodyMode: RecipeBodyAbsent,
		ChangeClasses: []string{}, AffectedHeaders: []string{},
		HistoryHeaderState: HistoryMatched, HistoryBodyState: HistoryMatched, BodyAvailability: "known",
		Sequence: Sequence, MessageInstance: 1,
	}
}

// testBoundHops calculates Recipe, projection, and bound-hop digests in producer order.
func testBoundHops(hops []Hop) ([]Hop, []byte) {
	result := append([]Hop(nil), hops...)
	for index := range result {
		recipe := CalculateRecipeDescriptorDigest(result[index])
		result[index].RecipeDigest = recipe[:]
	}

	projection := CalculateProjectionBinding(result)
	for index := range result {
		binding := CalculateBoundHopBinding(projection, result[index])
		result[index].HopBinding = binding[:]
	}

	return result, projection[:]
}
