package pluginruntime

import (
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"strings"
	"testing"
)

// TestNativeReplayKeyRequiresPresentNonEmptyValue prevents callbacks without an admitted replay value.
func TestNativeReplayKeyRequiresPresentNonEmptyValue(t *testing.T) {
	for _, test := range []struct {
		name, key string
		facts     decision.FactSet
		valid     bool
	}{
		{"unsafe", "", decision.FactSet{}, true},
		{"present", "resource.id", nativeDecisionFacts(t), true},
		{"missing", "resource.workflow.event_id", nativeDecisionFacts(t), false},
		{"absent", "resource.id", decision.FactSet{}, false},
		{"empty", "resource.id", nativeDecisionFactsWithValue(t, ""), false},
		{"oversized", "resource.id", nativeDecisionFactsWithValue(t, strings.Repeat("x", 129)), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateNativeReplayKey(test.key, test.facts); (err == nil) != test.valid {
				t.Fatalf("valid=%t, want %t: %v", err == nil, test.valid, err)
			}
		})
	}
}
