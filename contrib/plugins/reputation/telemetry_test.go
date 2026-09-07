package main

import (
	"context"
	"strings"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

func TestReputationMetricsAcceptMaximumConfiguredTarget(t *testing.T) {
	target := pluginapi.DecisionTargetSelector{Namespace: strings.Repeat("n", 64), Action: strings.Repeat("a", 64)}
	if err := pluginapi.ValidateDecisionTargetSelector(target); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig(t)
	cfg.bindings = map[pluginapi.DecisionTargetSelector]targetBindingConfig{target: {}}
	capture := &metricCapture{}
	metrics, err := newReputationTelemetry(cfg, capture)
	requireNoError(t, err)
	metrics.assessment.Add(t.Context(), target.Namespace+"/"+target.Action, kindIP, assessmentMissing, bandUnknown, overrideNone)

	if len(capture.emitted) != 1 {
		t.Fatal("valid maximum-length target lost its assessment metric")
	}
}

func TestObservationMetricsIncludeUnavailablePrerequisites(t *testing.T) {
	for _, test := range []struct {
		name          string
		ready, absent bool
	}{{name: "unready"}, {name: "absent", absent: true}, {name: "invalid ASN evidence", ready: true}} {
		t.Run(test.name, func(t *testing.T) {
			cfg := testASNObservationConfig(t)
			capture := &metricCapture{}
			metrics, err := newReputationTelemetry(cfg, capture)
			requireNoError(t, err)

			state := &stateOwner{config: cfg, telemetry: metrics}
			state.ready.Store(test.ready)

			if test.absent {
				state = nil
			}

			plugin := &Plugin{config: cfg, state: state, telemetry: metrics}
			caller, err := pluginapi.NewDecisionCallerView(pluginapi.DecisionCallerViewInput{Principal: "ScanWriter", AuthenticationKind: "basic"})
			requireNoError(t, err)
			facts := testObservationFacts(t, testObservation())
			value, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{String: stringPointer("invalid")})
			requireNoError(t, err)
			fact, err := pluginapi.NewDecisionFactView(pluginapi.DecisionFactViewInput{ID: cfg.apiSources["ScanWriter"].config.ASNFact,
				Category: pluginapi.DecisionFactCategoryEnvironment, Value: value})
			requireNoError(t, err)
			request, err := pluginapi.NewDecisionFactRequest(observeTarget, caller, append(facts, fact))
			requireNoError(t, err)
			result, err := (observationProvider{plugin: plugin, config: cfg}).Collect(t.Context(), request)
			requireNoError(t, err)

			if result.ErrorClass != pluginapi.DecisionErrorClassUnavailable || len(capture.emitted) != 1 {
				t.Fatal("unavailable prerequisite was not counted exactly once")
			}

			if capture.emitted[0][2].Value != learningUnavailable {
				t.Fatal("unavailable prerequisite produced a different admission reason")
			}
		})
	}
}

type metricCapture struct {
	pluginapi.Metrics
	definitions []pluginapi.MetricDefinition
	emitted     [][]pluginapi.LabelValue
}

// Counter captures the registered vocabulary and routes increments to one detached test sink.
func (m *metricCapture) Counter(definition pluginapi.MetricDefinition) (pluginapi.Counter, error) {
	m.definitions = append(m.definitions, definition)
	return m, nil
}

// Add captures dimensions without storing observations or opaque identifiers.
func (m *metricCapture) Add(_ context.Context, _ float64, labels ...pluginapi.LabelValue) {
	m.emitted = append(m.emitted, append([]pluginapi.LabelValue(nil), labels...))
}

func TestReputationMetricsBoundAllRuntimeDimensions(t *testing.T) {
	capture := &metricCapture{}
	metrics, err := newReputationTelemetry(testConfig(t), capture)
	requireNoError(t, err)

	ctx := context.Background()
	metrics.subject.Add(ctx, kindIP, storageApplied)
	metrics.storage.Add(ctx, scriptManifest, "event_conflict")
	metrics.admission.Add(ctx, "unknown", "unknown", reasonSource)

	if len(capture.emitted) != 3 {
		t.Fatal("valid closed metrics missing")
	}

	for _, raw := range []string{"192.0.2.8", "example.test", "raw-account", "subject-tag", "event-id", "redis:key", "caller-principal"} {
		metrics.subject.Add(ctx, raw, storageApplied)
		metrics.storage.Add(ctx, scriptManifest, raw)
		metrics.admission.Add(ctx, raw, "unknown", reasonSource)
		metrics.admission.Add(ctx, "unknown", raw, reasonSource)
	}

	if len(capture.emitted) != 3 {
		t.Fatal("raw evidence escaped the bounded metric vocabulary")
	}

	if len(capture.definitions) != 5 {
		t.Fatal("reputation metric families incomplete")
	}
}
