package pluginapi

import "testing"

// TestExecutionIdentityViewsAreImmutable preserves exact host ownership across all callback requests.
func TestExecutionIdentityViewsAreImmutable(t *testing.T) {
	target := DecisionTargetSelector{Namespace: "workflow", Action: "approve"}

	identity, err := NewExecutionIdentityView("worker", "audit", "decision_effect", "store", target)
	if err != nil {
		t.Fatal(err)
	}

	target.Action = "other"
	if identity.Module() != "worker" || identity.Component() != "audit" || identity.ExtensionPoint() != "decision_effect" ||
		identity.Operation() != "store" || identity.Target().Action != "approve" {
		t.Fatal("identity changed or lost registered ownership")
	}

	obligation, err := NewObligationRequest(ObligationRequest{}, identity)
	if err != nil || obligation.ExecutionIdentity() != identity {
		t.Fatalf("obligation identity error: %v", err)
	}

	postAction, err := NewPostActionRequest(PostActionRequest{}, identity)
	if err != nil || postAction.ExecutionIdentity() != identity {
		t.Fatalf("post-action identity error: %v", err)
	}

	if _, err := NewPostActionRequest(PostActionRequest{}, ExecutionIdentityView{}); err == nil {
		t.Fatal("missing execution identity accepted")
	}
}

// TestDecisionEffectIdentityMustMatchSelection rejects absent or mismatched host metadata.
func TestDecisionEffectIdentityMustMatchSelection(t *testing.T) {
	caller, _, target := newDecisionRequestFixture(t)
	otherTarget := DecisionTargetSelector{Namespace: "workflow", Action: "approve"}

	for _, test := range []struct {
		name, operation string
		target          DecisionTargetSelector
	}{
		{"wrong operation", "other", target},
		{"wrong target", "notify", otherTarget},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity, err := NewExecutionIdentityView("worker", "audit", "decision_effect", test.operation, test.target)
			if err != nil {
				t.Fatal(err)
			}

			if _, err = NewDecisionEffectRequest(DecisionEffectRequestInput{Caller: caller, Target: target, Effect: "notify", ExecutionIdentity: identity}); err == nil {
				t.Fatal("mismatched execution identity accepted")
			}
		})
	}

	if _, err := NewDecisionEffectRequest(DecisionEffectRequestInput{Caller: caller, Target: target, Effect: "notify"}); err == nil {
		t.Fatal("missing execution identity accepted")
	}
}
