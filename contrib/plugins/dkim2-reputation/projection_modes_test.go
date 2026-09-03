// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

func TestCollectAcceptsSupportedProjectionModes(t *testing.T) {
	plugin := NewPlugin()
	plugin.swapConfig(mustTestConfig(t))
	provider := decisionFactProvider{plugin: plugin}
	tests := []struct {
		name    string
		request pluginapi.DecisionFactRequest
	}{
		{name: "current", request: asCurrentProjection(t, testDecisionRequest(t, "192.0.2.25"))},
		{name: "ordinary chain", request: testDecisionRequestWithHops(t, []verifierHop{
			testUnchangedHop(1, custodyOrigin), testUnchangedHop(2, custodyOrdinary),
		})},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := provider.Collect(context.Background(), test.request)
			if err != nil {
				t.Fatalf("Collect() error = %v", err)
			}

			if result.ErrorClass != "" || len(result.Facts) != 1 || result.Facts[0].Name != outputAssessedChain {
				t.Fatalf("Collect() = %#v, want one assessed_chain fact", result)
			}
		})
	}
}

func TestVerifierProjectionAcceptsCurrentScopeWithoutHistoryEvaluation(t *testing.T) {
	request := asCurrentProjection(t, testDecisionRequest(t, "192.0.2.25"))

	if _, err := decodeVerifierProjection(request); err != nil {
		t.Fatalf("decodeVerifierProjection() error = %v for valid current projection", err)
	}
}

func TestVerifierProjectionAcceptsOrdinaryChainWithoutCustodyLinks(t *testing.T) {
	request := testDecisionRequestWithHops(t, []verifierHop{
		testUnchangedHop(1, custodyOrigin),
		testUnchangedHop(2, "ordinary"),
	})

	if _, err := decodeVerifierProjection(request); err != nil {
		t.Fatalf("decodeVerifierProjection() error = %v for valid ordinary chain", err)
	}
}

func TestVerifierProjectionAcceptsEvaluatedNextDomainCustody(t *testing.T) {
	request := testDecisionRequestWithHops(t, []verifierHop{
		testUnchangedHop(1, custodyOrigin),
		testUnchangedHop(2, custodyNextDomain),
	})
	request = replaceRequestStringFact(t, request, factCustodyStructure, custodyLinksEvaluated)

	if _, err := decodeVerifierProjection(request); err != nil {
		t.Fatalf("decodeVerifierProjection() error = %v for valid next-domain chain", err)
	}
}

func TestVerifierProjectionAcceptsTerminalCustodyOnlyAtFinalHop(t *testing.T) {
	request := testDecisionRequestWithHops(t, []verifierHop{
		testUnchangedHop(1, custodyOrigin),
		testUnchangedHop(2, custodyOrdinary),
		testUnchangedHop(3, custodyTerminal),
	})
	request = replaceRequestStringFact(t, request, factCustodyStructure, custodyTerminalRequires)

	if _, err := decodeVerifierProjection(request); err != nil {
		t.Fatalf("decodeVerifierProjection() error = %v for valid terminal chain", err)
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
				request := testDecisionRequestWithHops(t, []verifierHop{
					testUnchangedHop(1, custodyOrigin), testUnchangedHop(2, custodyOrdinary),
				})

				return asCurrentProjection(t, request)
			},
		},
		{
			name: "current scope with evaluated history",
			request: func(t *testing.T) pluginapi.DecisionFactRequest {
				return replaceRequestStringFact(t, testDecisionRequest(t, "192.0.2.25"), factScope, scopeCurrent)
			},
		},
		{
			name: "current pass with non-evaluated custody",
			request: func(t *testing.T) pluginapi.DecisionFactRequest {
				request := asCurrentProjection(t, testDecisionRequest(t, "192.0.2.25"))

				return replaceRequestStringFact(t, request, factCustodyStructure, stateNotEvaluated)
			},
		},
		{
			name: "chain scope with partial history",
			request: func(t *testing.T) pluginapi.DecisionFactRequest {
				return replaceRequestStringFact(t, testDecisionRequest(t, "192.0.2.25"), factHistoricalContent, "partial")
			},
		},
		{
			name: "chain scope with non-evaluated protection",
			request: func(t *testing.T) pluginapi.DecisionFactRequest {
				return replaceRequestStringFacts(t, testDecisionRequest(t, "192.0.2.25"), map[string]string{
					factDoNotModifyState:  stateNotEvaluated,
					factDoNotExplodeState: stateNotEvaluated,
				})
			},
		},
		{
			name: "absent custody with next-domain transition",
			request: func(t *testing.T) pluginapi.DecisionFactRequest {
				return testDecisionRequestWithHops(t, []verifierHop{
					testUnchangedHop(1, custodyOrigin), testUnchangedHop(2, custodyNextDomain),
				})
			},
		},
		{
			name: "evaluated links without next-domain transition",
			request: func(t *testing.T) pluginapi.DecisionFactRequest {
				request := testDecisionRequestWithHops(t, []verifierHop{
					testUnchangedHop(1, custodyOrigin), testUnchangedHop(2, custodyOrdinary),
				})

				return replaceRequestStringFact(t, request, factCustodyStructure, custodyLinksEvaluated)
			},
		},
		{
			name: "terminal aggregate without terminal final hop",
			request: func(t *testing.T) pluginapi.DecisionFactRequest {
				request := testDecisionRequestWithHops(t, []verifierHop{
					testUnchangedHop(1, custodyOrigin), testUnchangedHop(2, custodyOrdinary),
				})

				return replaceRequestStringFact(t, request, factCustodyStructure, custodyTerminalRequires)
			},
		},
		{
			name: "terminal transition before final hop",
			request: func(t *testing.T) pluginapi.DecisionFactRequest {
				request := testDecisionRequestWithHops(t, []verifierHop{
					testUnchangedHop(1, custodyOrigin),
					testUnchangedHop(2, custodyTerminal),
					testUnchangedHop(3, custodyOrdinary),
				})

				return replaceRequestStringFact(t, request, factCustodyStructure, custodyTerminalRequires)
			},
		},
		{
			name: "multiple terminal transitions",
			request: func(t *testing.T) pluginapi.DecisionFactRequest {
				request := testDecisionRequestWithHops(t, []verifierHop{
					testUnchangedHop(1, custodyOrigin),
					testUnchangedHop(2, custodyTerminal),
					testUnchangedHop(3, custodyTerminal),
				})

				return replaceRequestStringFact(t, request, factCustodyStructure, custodyTerminalRequires)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeVerifierProjection(test.request(t)); err == nil {
				t.Fatal("decodeVerifierProjection() error = nil for incoherent projection")
			}
		})
	}
}

// asCurrentProjection maps a binding-valid request onto the non-evaluated current-scope aggregate state.
func asCurrentProjection(t *testing.T, request pluginapi.DecisionFactRequest) pluginapi.DecisionFactRequest {
	t.Helper()

	return replaceRequestStringFacts(t, request, map[string]string{
		factScope:                scopeCurrent,
		factHistoricalContent:    stateNotEvaluated,
		factHistoricalSignatures: stateNotEvaluated,
		factDoNotModifyState:     stateNotEvaluated,
		factDoNotExplodeState:    stateNotEvaluated,
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
func testDecisionRequestWithHops(t *testing.T, hops []verifierHop) pluginapi.DecisionFactRequest {
	t.Helper()

	boundHops, projectionBinding := testBoundHops(hops)
	last := boundHops[len(boundHops)-1]
	request := testDecisionRequest(t, "192.0.2.25")
	request = replaceRequestFact(t, request, "resource.dkim2.projection_binding", testBytesValue(t, projectionBinding))
	request = replaceRequestFact(t, request, "resource.dkim2.chain", testChainValue(t, boundHops))
	request = replaceRequestFact(t, request, "resource.dkim2.target_sequence", testIntegerValue(t, last.sequence))
	request = replaceRequestFact(t, request, "resource.dkim2.target_message_instance", testIntegerValue(t, last.messageInstance))
	request = replaceRequestFact(t, request, "resource.dkim2.claimed_hop_count", testIntegerValue(t, int64(len(boundHops))))

	return request
}

// testUnchangedHop returns one deterministic pass hop without Recipe changes or protection flags.
func testUnchangedHop(sequence int64, custodyTransition string) verifierHop {
	return verifierHop{
		signerDomain: "relay.example", signatureAlgorithms: []string{"ed25519-sha256"}, signatureState: "pass",
		custodyTransition: custodyTransition, recipeMode: "unchanged", recipeBodyMode: recipeBodyAbsent,
		changeClasses: []string{}, affectedHeaders: []string{},
		historyHeaderState: historyMatched, historyBodyState: historyMatched, bodyAvailability: "known",
		sequence: sequence, messageInstance: 1,
	}
}

// testBoundHops calculates Recipe, projection, and bound-hop digests in producer order.
func testBoundHops(hops []verifierHop) ([]verifierHop, []byte) {
	result := append([]verifierHop(nil), hops...)
	for index := range result {
		recipe := calculateRecipeDescriptorDigest(result[index])
		result[index].recipeDigest = recipe[:]
	}

	projection := calculateProjectionBinding(result)
	for index := range result {
		binding := calculateBoundHopBinding(projection, result[index])
		result[index].hopBinding = binding[:]
	}

	return result, projection[:]
}
