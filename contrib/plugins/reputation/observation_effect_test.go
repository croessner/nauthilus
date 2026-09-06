package main

import (
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"testing"
)

// TestObservationAdmittedCollectionRetainsPrimaryRoots lets storage repeat expansion without widening the caller's original subjects.
func TestObservationAdmittedCollectionRetainsPrimaryRoots(t *testing.T) {
	cfg := testConfig(t)
	input := testObservation()
	admitted, reason, err := cfg.admitObservation(t.Context(), cfg.apiSources["ScanWriter"], input, input.observedAt, testTagger(t), nil)
	requireNoError(t, err)

	if reason != reasonValid {
		t.Fatal("valid evidence rejected")
	}

	primaries := 0

	for _, subject := range admitted.subjects {
		record, err := admittedSubjectRecord(subject)
		requireNoError(t, err)

		present := false

		for _, field := range record.Fields() {
			if field.Name() != "primary" {
				continue
			}

			value, ok := field.Value().Value().Boolean()
			if !ok {
				t.Fatal("primary marker is not typed")
			}

			present = true

			if value {
				primaries++
			}
		}

		if !present {
			t.Fatal("admitted collection loses original-subject boundary")
		}
	}

	if primaries != len(input.subjects) {
		t.Fatal("derived subjects were promoted to primary inputs")
	}
}

// TestObservationStorageEffectDeclaresExactReplayBoundary binds replay-safe learning to the caller's stable event identifier.
func TestObservationStorageEffectDeclaresExactReplayBoundary(t *testing.T) {
	descriptor := (observationStorageProvider{}).Descriptor()
	requireNoError(t, pluginapi.ValidateDecisionEffectProviderDescriptor(descriptor))

	if descriptor.Namespace != pluginName || descriptor.Name != "storage" || len(descriptor.Effects) != 1 {
		t.Fatal("unexpected storage effect identity")
	}

	effect := descriptor.Effects[0]
	if effect.Name != "store_observation" || effect.Execution != pluginapi.DecisionEffectExecutionHostSync ||
		effect.ReplaySafety != pluginapi.DecisionEffectReplayIdempotent || effect.IdempotencyKey != observationPrefix+fieldEventID ||
		len(effect.Targets) != 1 || effect.Targets[0] != observeTarget {
		t.Fatal("storage replay contract is not exact")
	}
}

// testObservationEffectRequest freezes caller metadata and protected provider output under one host-owned effect identity.
func testObservationEffectRequest(t *testing.T, admitted admittedObservation, principal string) pluginapi.DecisionEffectRequest {
	t.Helper()
	facts := testObservationFacts(t, admitted.input)
	result, err := observationResult(admitted, reasonValid)
	requireNoError(t, err)

	for _, output := range result.Facts {
		fact, err := pluginapi.NewDecisionFactView(pluginapi.DecisionFactViewInput{ID: "plugin.reputation." + output.Name, Category: pluginapi.DecisionFactCategoryResource, Value: output.Value})
		requireNoError(t, err)

		facts = append(facts, fact)
	}

	caller, err := pluginapi.NewDecisionCallerView(pluginapi.DecisionCallerViewInput{Principal: principal, AuthenticationKind: "basic"})
	requireNoError(t, err)
	identity, err := pluginapi.NewExecutionIdentityView(pluginName, componentStorage, "decision_effect", effectStoreObservation, observeTarget)
	requireNoError(t, err)
	request, err := pluginapi.NewDecisionEffectRequest(pluginapi.DecisionEffectRequestInput{Target: observeTarget, Caller: caller, Effect: effectStoreObservation, ExecutionIdentity: identity, Facts: facts})
	requireNoError(t, err)

	return request
}

// TestObservationEffectDecodesOnlyProtectedPrimaryRoots validates the effect boundary without a storage dependency.
func TestObservationEffectDecodesOnlyProtectedPrimaryRoots(t *testing.T) {
	cfg := testConfig(t)
	input := testObservation()
	admitted, reason, err := cfg.admitObservation(t.Context(), cfg.apiSources["ScanWriter"], input, input.observedAt, manifestTestTagger(t, false), nil)
	requireNoError(t, err)

	if reason != reasonValid {
		t.Fatal(reason)
	}

	request := testObservationEffectRequest(t, admitted, "ScanWriter")
	decoded, frozen, err := decodeObservationEffectFacts(request.Facts(), pluginName)
	requireNoError(t, err)

	if len(decoded.subjects) != len(input.subjects) || len(frozen) != len(admitted.subjects) {
		t.Fatal("protected root boundary was lost")
	}
}
