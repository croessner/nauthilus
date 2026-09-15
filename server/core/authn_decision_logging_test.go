package core

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"reflect"
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

// TestAuthnDecisionFailureLogsStructuredDiagnostics checks the actual JSON log boundary.
func TestAuthnDecisionFailureLogsStructuredDiagnostics(t *testing.T) {
	var output bytes.Buffer

	execution := &authnCandidateExecution{auth: &AuthState{deps: AuthDeps{
		Logger: slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}}}
	text := "auth_decision"
	count := int64(8)

	checkpoint, err := decision.NewValue(decision.ValueInput{String: &text})
	if err != nil {
		t.Fatal(err)
	}

	generation, err := decision.NewValue(decision.ValueInput{Integer: &count})
	if err != nil {
		t.Fatal(err)
	}

	diagnostics, err := decision.NewDiagnostics(map[string]decision.Value{"checkpoint": checkpoint, "runtime.generation": generation})
	if err != nil {
		t.Fatal(err)
	}

	status, err := decision.NewStatus(decision.StatusCodeEffectReplayUnsafe, "Cannot repeat safely.", nil)
	if err != nil {
		t.Fatal(err)
	}

	metadata, err := decision.NewPolicyMetadata("authn/configured", "1.0.0", "standard_auth_success", 8)
	if err != nil {
		t.Fatal(err)
	}

	response, err := decision.NewDecisionResponse(decision.DecisionResponseInput{
		RequestID: "request-log", DecisionID: "decision-log", Effect: decision.EffectIndeterminate,
		Status: status, Policy: metadata, Diagnostics: &diagnostics,
	})
	if err != nil {
		t.Fatal(err)
	}

	logAuthnDecisionFailure(execution, text, response)

	var record map[string]any

	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatal(err)
	}

	if want := (map[string]any{"checkpoint": text, "runtime.generation": float64(count)}); !reflect.DeepEqual(want, record["diagnostics"]) {
		t.Fatalf("diagnostics=%v, want %v", record["diagnostics"], want)
	}
}
