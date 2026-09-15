package pluginruntime

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// TestAuthenticationAdmissionRejectionIsObservable preserves rejection without losing its operational cause.
func TestAuthenticationAdmissionRejectionIsObservable(t *testing.T) {
	var output bytes.Buffer

	observer := NewOperationalObserver(slog.New(slog.NewJSONHandler(&output, nil)), WithOperationalObserverMetrics(nil))
	target := &recordingAuthnObligationTarget{name: "learn_outcome"}

	admission := newCallbackAdmission(pluginapi.CallbackAdmissionLimits{RequestsPerSecond: 10, MaxConcurrency: 2})
	for range 2 {
		if err := admission.acquire(t.Context()); err != nil {
			t.Fatal("could not occupy admission capacity")
		}
		defer admission.release()
	}

	provider := &nativeAuthnObligationProvider{target: target, admission: admission,
		call: newNativeAuthnComponentCall(observer, "reputation", "learn_outcome", "obligation", "Execute")}

	result, err := provider.ExecuteObligation(t.Context(), forgedObligationRequest(t), authenticationEffectTestTarget(t))
	if !errors.Is(err, errCallbackAdmissionLimited) || !result.Temporary || target.calls != 0 {
		t.Fatalf("rejection = %+v, %v, calls=%d", result, err, target.calls)
	}

	if !strings.Contains(output.String(), `"plugin_result":"admission_limited"`) {
		t.Fatalf("admission rejection lacks bounded cause: %s", output.String())
	}

	if !strings.Contains(output.String(), `"plugin_admission_limit":"concurrency"`) {
		t.Fatalf("admission rejection lacks its specific limit: %s", output.String())
	}
}
