package policyhttp

import (
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"testing"
)

// TestReplayOutcomeHTTPProjection preserves the exact runtime status in generated response bindings.
func TestReplayOutcomeHTTPProjection(t *testing.T) {
	for _, code := range []decision.StatusCode{decision.StatusCodeEffectOutcomeUnknown, decision.StatusCodeEffectOutcomeUnknownReplaySafe, decision.StatusCodeEvaluationFailed} {
		t.Run(string(code), func(t *testing.T) {
			status, err := decision.NewStatus(code, "effect result", nil)
			if err != nil {
				t.Fatal(err)
			}

			response, err := decision.NewDecisionResponse(decision.DecisionResponseInput{
				RequestID: "workflow-request", DecisionID: "workflow-decision", Effect: decision.EffectIndeterminate,
				Status: status, Policy: testResponse(t).Policy(),
			})
			if err != nil {
				t.Fatal(err)
			}

			dto, err := responseDTO(response)
			if err != nil {
				t.Fatal(err)
			}

			if dto.Status.Code != string(code) || dto.Status.Retryable != (code != decision.StatusCodeEffectOutcomeUnknown) {
				t.Fatalf("HTTP status=%#v", dto.Status)
			}
		})
	}
}
