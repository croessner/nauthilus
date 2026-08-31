// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package observability

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/registry"

	"github.com/prometheus/client_golang/prometheus"
)

func TestTracerScopeIsPolicy(t *testing.T) {
	if TracerScope != "nauthilus/policy" {
		t.Fatalf("TracerScope = %q, want nauthilus/policy", TracerScope)
	}

	if NewTracer() == nil {
		t.Fatal("NewTracer returned nil")
	}
}

func TestDebugFieldsIncludeValidatedComponent(t *testing.T) {
	fields, err := DebugFields(ComponentCompiler, "operation", string(policy.OperationAuthenticate))
	if err != nil {
		t.Fatalf("DebugFields returned error: %v", err)
	}

	if !fieldPairExists(fields, KeyComponent, string(ComponentCompiler)) {
		t.Fatalf("debug fields do not contain %s=%s: %#v", KeyComponent, ComponentCompiler, fields)
	}

	if _, err := DebugFields(Component("unknown")); err == nil {
		t.Fatal("unknown component was accepted")
	}
}

func TestDecisionLogFieldsUseSafeKeysOnly(t *testing.T) {
	fields := DecisionLogFields(DecisionLogEntry{
		Mode:               "enforce",
		Set:                registry.BuiltinStandardAuthPolicySet,
		Name:               "standard_auth_success",
		Operation:          policy.OperationAuthenticate,
		Stage:              policy.StageAuthDecision,
		Decision:           policy.DecisionPermit,
		Reason:             "authenticated",
		ResponseMarker:     "auth.response.ok",
		FSMEventMarker:     "auth.fsm.event.auth_permit",
		SnapshotGeneration: 7,
		ObserveMismatch:    false,
	})

	forbidden := map[string]struct{}{
		"username":         {},
		"client_ip":        {},
		"response_message": {},
		"attribute_detail": {},
	}

	for i := 0; i < len(fields)-1; i += 2 {
		key, ok := fields[i].(string)
		if !ok {
			t.Fatalf("field key at %d is %T, want string", i, fields[i])
		}

		if _, found := forbidden[key]; found {
			t.Fatalf("unsafe log key %q present in %#v", key, fields)
		}
	}

	if !fieldPairExists(fields, "policy_name", "standard_auth_success") {
		t.Fatalf("policy_name missing from %#v", fields)
	}

	if !fieldPairExistsValue(fields, "snapshot_generation", uint64(7)) {
		t.Fatalf("snapshot_generation missing from %#v", fields)
	}
}

func TestDKIM2DecisionLogFieldsDoNotLeakRequestIdentities(t *testing.T) {
	const (
		smtpPeerIP   = "203.0.113.77"
		signerDomain = "sensitive-signer.example"
	)

	for _, outcome := range []policy.Decision{policy.DecisionPermit, policy.DecisionDeny} {
		fields := DecisionLogFields(DecisionLogEntry{
			Mode: "enforce", Set: "dkim2_verifier", Name: "final_decision",
			Operation: policy.OperationAuthenticate, Stage: policy.StageAuthDecision, Decision: outcome,
		})
		serialized := fmt.Sprint(fields)

		for _, secret := range []string{smtpPeerIP, signerDomain} {
			if strings.Contains(serialized, secret) {
				t.Fatalf("%s log fields leak %q: %s", outcome, secret, serialized)
			}
		}
	}
}

func TestSafeRecorderIsNoopForNil(_ *testing.T) {
	recorder := SafeRecorder(nil)
	recorder.RecordSnapshotBuild(context.Background(), SnapshotBuildMeasurement{
		Duration:   time.Millisecond,
		Result:     ResultSuccess,
		Generation: 1,
	})
	recorder.RecordDecision(context.Background(), DecisionMeasurement{
		Mode:           "enforce",
		Operation:      policy.OperationAuthenticate,
		Stage:          policy.StageAuthDecision,
		Decision:       policy.DecisionPermit,
		PolicyName:     "standard_auth_success",
		ResponseMarker: "auth.response.ok",
		FSMEventMarker: "auth.fsm.event.auth_permit",
	})
	recorder.RecordReloadFailure(context.Background(), ReloadFailureMeasurement{ReasonCode: "compile_error"})
	recorder.RecordStageEvaluation(context.Background(), StageMeasurement{
		Duration:  time.Millisecond,
		Mode:      "enforce",
		Operation: policy.OperationAuthenticate,
		Stage:     policy.StagePreAuth,
	})
	recorder.RecordRequireCheck(context.Background(), RequireCheckMeasurement{
		Mode:       "enforce",
		PolicyName: "standard_auth_success",
		Check:      "ldap_backend",
		Result:     "satisfied",
		Operation:  policy.OperationAuthenticate,
		Stage:      policy.StageAuthDecision,
	})
	recorder.RecordObserveComparison(context.Background(), ObserveMeasurement{
		Result:       ResultSuccess,
		MismatchType: "none",
		Operation:    policy.OperationAuthenticate,
		Stage:        policy.StageAuthDecision,
	})
	recorder.RecordFSMTransition(context.Background(), FSMMeasurement{
		Result:         ResultSuccess,
		FSMEventMarker: "auth.fsm.event.auth_permit",
		Operation:      policy.OperationAuthenticate,
		Stage:          policy.StageAuthDecision,
	})
	recorder.RecordResponseRender(context.Background(), RendererMeasurement{
		Duration:       time.Millisecond,
		Surface:        "http_json",
		ResponseMarker: "auth.response.ok",
		Result:         ResultSuccess,
	})
	recorder.RecordObligation(context.Background(), ObligationMeasurement{
		Duration:   time.Millisecond,
		Obligation: policy.EffectBruteForceUpdate,
		Result:     ResultSuccess,
	})
	recorder.RecordAdvice(context.Background(), AdviceMeasurement{
		Advice: "auth.advice.audit_reason",
		Result: ResultSuccess,
	})
}

func TestPrometheusRecorderUsesBoundedLabels(t *testing.T) {
	registry := prometheus.NewRegistry()

	recorder, err := NewPrometheusRecorder(registry)
	if err != nil {
		t.Fatalf("NewPrometheusRecorder returned error: %v", err)
	}

	recorder.RecordDecision(context.Background(), DecisionMeasurement{
		Mode:           "enforce",
		Operation:      policy.OperationAuthenticate,
		Stage:          policy.StageAuthDecision,
		Decision:       policy.DecisionPermit,
		PolicyName:     "standard_auth_success",
		ResponseMarker: "auth.response.ok",
		FSMEventMarker: "auth.fsm.event.auth_permit",
	})

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}

	for _, family := range families {
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				switch label.GetName() {
				case "snapshot_generation", "username", "client_ip", "response_message", "attribute_detail":
					t.Fatalf("forbidden label %q found on metric %q", label.GetName(), family.GetName())
				}
			}
		}
	}
}

func TestDKIM2DecisionMetricsDoNotLeakRequestIdentities(t *testing.T) {
	const (
		smtpPeerIP   = "203.0.113.77"
		signerDomain = "sensitive-signer.example"
	)

	metricRegistry := prometheus.NewRegistry()

	recorder, err := NewPrometheusRecorder(metricRegistry)
	if err != nil {
		t.Fatalf("NewPrometheusRecorder returned error: %v", err)
	}

	for _, outcome := range []policy.Decision{policy.DecisionPermit, policy.DecisionDeny} {
		recorder.RecordDecision(context.Background(), DecisionMeasurement{
			Mode: "enforce", Operation: policy.OperationAuthenticate, Stage: policy.StageAuthDecision,
			Decision: outcome, PolicyName: "dkim2_verifier", ResponseMarker: "dkim2.response",
			FSMEventMarker: "dkim2.final",
		})
	}

	families, err := metricRegistry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}

	serialized := fmt.Sprint(families)
	for _, secret := range []string{smtpPeerIP, signerDomain} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("metric labels leak %q: %s", secret, serialized)
		}
	}
}

func fieldPairExists(fields []any, key string, value string) bool {
	return fieldPairExistsValue(fields, key, value)
}

func fieldPairExistsValue(fields []any, key string, value any) bool {
	for i := 0; i < len(fields)-1; i += 2 {
		if fields[i] == key && fields[i+1] == value {
			return true
		}
	}

	return false
}
