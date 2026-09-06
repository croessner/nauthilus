package pluginapi

import "testing"

// TestDecisionEffectRequiresReplaySafety rejects effects with an unspecified replay contract.
func TestDecisionEffectRequiresReplaySafety(t *testing.T) {
	descriptor := validDecisionEffectProviderDescriptor()
	descriptor.Effects[0].ReplaySafety = ""

	if err := ValidateDecisionEffectProviderDescriptor(descriptor); err == nil {
		t.Fatal("effect with omitted replay safety was accepted")
	}
}

// TestDecisionEffectReplaySafetyContract validates the closed per-effect declaration.
func TestDecisionEffectReplaySafetyContract(t *testing.T) {
	for _, test := range []struct {
		safety DecisionEffectReplaySafety
		key    string
		valid  bool
	}{
		{DecisionEffectReplayUnsafe, "", true},
		{DecisionEffectReplayUnsafe, "resource.workflow.event_id", false},
		{DecisionEffectReplayIdempotent, "resource.workflow.event_id", true},
		{DecisionEffectReplayIdempotent, "", false},
		{DecisionEffectReplayIdempotent, "${event}", false},
		{"automatic", "resource.workflow.event_id", false},
	} {
		descriptor := validDecisionEffectProviderDescriptor()
		descriptor.Namespace = "workflow"
		descriptor.Effects[0].Targets = []DecisionTargetSelector{{Namespace: "workflow", Action: "approve"}}
		descriptor.Effects[0].ReplaySafety = test.safety
		descriptor.Effects[0].IdempotencyKey = test.key

		if err := ValidateDecisionEffectProviderDescriptor(descriptor); (err == nil) != test.valid {
			t.Fatalf("safety=%s key=%s valid=%t: %v", test.safety, test.key, test.valid, err)
		}
	}
}
