package core

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

// TestNativeObligationFailureRetainsItsBoundary identifies host failures before generic replay protection.
func TestNativeObligationFailureRetainsItsBoundary(t *testing.T) {
	var output bytes.Buffer

	auth, ginCtx, _ := newCurrentBehaviorAuthState(t, newCurrentBehaviorConfig(t))
	auth.deps.Logger = slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	auth.deps.NativeRuntime = nil
	execution := &authnCandidateExecution{auth: auth, ginCtx: ginCtx}
	program := &authnNativeObligationTestProgram{id: authnNativeObligationTestID}
	execution.ExecuteAuthnNativeObligation(t.Context(), program, newAuthnNativeTestExecution(t, authnNativeObligationTestID))
	logAuthnDecisionFailure(execution, "auth_decision", mustAuthnDecisionResponse(t, decision.EffectIndeterminate))

	if !strings.Contains(output.String(), `"native_effect_failure":"authn_native_obligation_capture"`) {
		t.Fatalf("missing host failure boundary: %s", output.String())
	}
}
