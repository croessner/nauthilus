package dkim2projection

import (
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"testing"
)

// TestVerifierProjectionAcceptsOnlyDeclaredOptionalDSNPropagation preserves the shipped optional wire fact without widening vocabulary.
func TestVerifierProjectionAcceptsOnlyDeclaredOptionalDSNPropagation(t *testing.T) {
	for _, state := range []string{"not_applicable", "eligible", "terminal_origin", "not_failure", "forbidden_null_previous_sender", "unsupported_chain", "not_reconstructable", "not_evaluated", "unknown"} {
		request := appendRequestFact(t, testDecisionRequest(t, "192.0.2.25"), testFact(t, "resource.dkim2.received_dsn_propagation", pluginapi.DecisionFactCategoryResource, testStringValue(t, state)))

		_, err := Decode(request)
		if (err == nil) != (state != "unknown") {
			t.Fatalf("optional DSN %s: %v", state, err)
		}
	}
}

// TestVerifierProjectionRejectsMalformedOptionalDSN preserves the declared type and host-assigned category.
func TestVerifierProjectionRejectsMalformedOptionalDSN(t *testing.T) {
	for _, tc := range []struct {
		name     string
		category pluginapi.DecisionFactCategory
		value    pluginapi.DecisionValue
	}{
		{"wrong category", pluginapi.DecisionFactCategoryEnvironment, testStringValue(t, "eligible")},
		{"wrong type", pluginapi.DecisionFactCategoryResource, testBooleanValue(t, true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := appendRequestFact(t, testDecisionRequest(t, "192.0.2.25"), testFact(t, "resource.dkim2.received_dsn_propagation", tc.category, tc.value))
			if _, err := Decode(request); err == nil {
				t.Fatal("malformed optional DSN accepted")
			}
		})
	}
}
