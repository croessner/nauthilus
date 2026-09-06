package service

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
)

// TestSessionPreservesProviderFactsAcrossCheckpoints reproduces lost GeoIP evidence.
func TestSessionPreservesProviderFactsAcrossCheckpoints(t *testing.T) {
	country := "DE"
	value, _ := decision.NewValue(decision.ValueInput{String: &country})
	provenance, _ := decision.NewProvenance(decision.FactSourcePlugin, "geoip", "environment")

	fact, err := decision.NewFact("plugin.geoip.country_iso", decision.FactCategoryEnvironment, value, provenance)
	if err != nil {
		t.Fatal(err)
	}

	facts, _ := decision.NewFactSet([]decision.Fact{fact})
	outcome := mustRuntimeEvaluation(t, 7, "country-provider")
	outcome.report.runtime.providerFacts = facts
	evaluator := &recordingCheckpointEvaluator{outcome: outcome}
	generation := mustRuntimeGeneration(t, 7,
		&recordingCallerAuthenticator{caller: mustAuthorityCaller(t, true)},
		&recordingAdmissionAuthority{}, evaluator)
	service := mustDecisionService(t, &replaceableGenerationSource{generation: generation})

	err = service.WithSession(t.Context(), mustAuthorityInvocation(t, true), func(session DecisionSession) error {
		evaluateSessionCheckpoints(t, session, []string{"pre_auth"})

		view, ok := session.(AuthnProviderFactSession)
		if !ok {
			t.Fatal("provider facts are unavailable to the next host checkpoint")
		}

		if _, exists := view.AuthnProviderFacts().Get("plugin.geoip.country_iso"); !exists {
			t.Fatal("the host checkpoint lost the pre-authentication GeoIP country")
		}

		evaluateSessionCheckpoints(t, session, []string{"auth_decision"})

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, exists := evaluator.providerFacts.Get("plugin.geoip.country_iso"); !exists {
		t.Fatal("the final checkpoint lost the pre-authentication GeoIP country")
	}
}

// TestRuntimeRefreshesCarriedProviderEvidence prevents stale values and duplicate ownership.
func TestRuntimeRefreshesCarriedProviderEvidence(t *testing.T) {
	fixture := newAuthnLuaNativeParityFixture(t)

	request, err := decision.NewDecisionRequest(decision.DecisionRequestInput{
		Version: decision.ContractVersion, RequestID: "provider-continuity", Target: fixture.target,
	}, mustAuthorityCaller(t, false))
	if err != nil {
		t.Fatal(err)
	}

	checkpoint, _ := decision.NewCheckpoint(decision.CheckpointFinalDecision, decision.FactSet{})

	input := checkpointEvaluation{
		request: request, checkpoint: checkpoint, supervisor: &recordingEffectAcceptor{}, generation: 1,
		finalization: decision.NewEvaluationFinalization(effectsupervisor.BoundaryGRPCUnaryReturn),
	}
	for range 2 {
		outcome, evaluationErr := fixture.evaluator.Evaluate(t.Context(), input)
		if evaluationErr != nil || outcome.response.Effect() != decision.EffectPermit {
			t.Fatalf("provider refresh failed: %v / %s", evaluationErr, outcome.response.Effect())
		}

		input.providerFacts = outcome.report.runtime.providerFacts
		if input.providerFacts.Len() != 3 {
			t.Fatalf("captured provider facts = %d, want 3", input.providerFacts.Len())
		}
	}
}
