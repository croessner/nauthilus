package main

import (
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
)

// TestSourceCapacityPreservesModelAndReachesHostGate prevents higher traffic budgets from resetting score history.
func TestSourceCapacityPreservesModelAndReachesHostGate(t *testing.T) {
	raw := learningConfigMap(t)
	originalConfig, err := decodeConfig(pluginregistry.NewConfigView(raw))
	requireNoError(t, err)
	original, err := compileModel(originalConfig)
	requireNoError(t, err)

	capacities := map[string]any{}

	for name := range originalConfig.raw.Sources {
		capacities[name] = map[string]any{"requests_per_second": 200, "max_concurrency": 32}
	}

	raw["source_admission_capacity"] = capacities
	raw["new_subject_capacity_per_source_hour"] = 1000000
	raw["event_manifest_capacity_per_source"] = 3000000
	raw["subject_seen_capacity_per_subject"] = 3000000
	expandedConfig, err := decodeConfig(pluginregistry.NewConfigView(raw))
	requireNoError(t, err)
	expanded, err := compileModel(expandedConfig)
	requireNoError(t, err)

	if original.fingerprint != expanded.fingerprint {
		t.Fatal("operational capacity changed the scoring model")
	}

	expected := pluginapi.CallbackAdmissionLimits{RequestsPerSecond: 200, MaxConcurrency: 32}
	if expandedConfig.learningAdmissionLimits() != expected {
		t.Fatal("higher admission capacity did not reach the authentication gate")
	}
}

// TestSourceCapacityRejectsUnknownOrReducedGrants keeps all configured expansion inside explicit source and host bounds.
func TestSourceCapacityRejectsUnknownOrReducedGrants(t *testing.T) {
	for _, test := range []struct {
		name              string
		rate, concurrency int
	}{
		{"unknown", 200, 32}, {"scan", 1, 1}, {"scan", 10001, 32}, {"scan", 200, 1025},
	} {
		raw := testConfigMap(t)
		raw["source_admission_capacity"] = map[string]any{
			test.name: map[string]any{"requests_per_second": test.rate, "max_concurrency": test.concurrency},
		}
		_, err := decodeConfig(pluginregistry.NewConfigView(raw))
		requireError(t, err)
	}
}
