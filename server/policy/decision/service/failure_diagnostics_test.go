package service

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

// TestReplayProtectionPreservesFailureCause keeps the original failure visible in bounded diagnostics.
func TestReplayProtectionPreservesFailureCause(t *testing.T) {
	catalog, target := decisionRuntimeCatalog(t, decision.EffectPermit, registry.NoMatchDeny, nil, nil, nil)
	compiled, _ := catalog.Lookup(target)

	request, err := decision.NewDecisionRequest(decision.DecisionRequestInput{
		Version: decision.ContractVersion, RequestID: "request-failure", Target: target,
		Options: decision.EvaluationOptions{IncludeDiagnostics: true},
	}, mustAuthorityCaller(t, true))
	if err != nil {
		t.Fatal(err)
	}

	facts, _ := decision.NewFactSet(nil)
	checkpoint, _ := decision.NewCheckpoint(decision.CheckpointFinalDecision, facts)
	runtime := &checkpointRuntime{}

	outcome := runtime.indeterminate(checkpointEvaluation{request: request, checkpoint: checkpoint, generation: 1},
		compiled, "decision-failure", "request-failure", decision.StatusCodeEffectAcceptanceRejected,
		runtimeReport{replayUnsafe: true})
	if outcome.response.Status().Code() != decision.StatusCodeEffectReplayUnsafe {
		t.Fatal("replay protection changed")
	}

	value, ok := outcome.response.Diagnostics().Entries().Get("failure.cause")

	got, _ := value.Any()
	if !ok || got != string(decision.StatusCodeEffectAcceptanceRejected) {
		t.Fatalf("failure cause=%v, present=%t", got, ok)
	}
}
