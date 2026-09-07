//go:build reputation_integration

package main

import (
	"testing"
)

// TestReputationRedisMetricsFollowActualStorage distinguishes durable application, duplicate and unavailability.
func TestReputationRedisMetricsFollowActualStorage(t *testing.T) {
	_, facade := localReputationRedis(t)
	cfg := testConfig(t)
	tagger := manifestTestTagger(t, false)
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	capture := &metricCapture{}
	owner.telemetry, err = newReputationTelemetry(cfg, capture)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))
	admitted := integrationObservation(t, cfg, tagger, "metric-event")
	for range 2 {
		_, err = owner.ingest(t.Context(), admitted)
		requireNoError(t, err)
	}

	owner.ready.Store(false)
	_, err = owner.ingest(t.Context(), admitted)
	if err == nil {
		t.Fatal("unavailable authority succeeded")
	}

	results := make(map[string]int)
	for _, labels := range capture.emitted {
		if len(labels) == 3 && labels[0].Name == "source_class" && labels[1].Name == "signal" && labels[2].Name == "result" {
			results[labels[2].Value]++
		}
	}

	for _, result := range []string{storageApplied, storageDuplicate, learningUnavailable} {
		if results[result] != 1 {
			t.Fatalf("missing or duplicated ingestion metric %s", result)
		}
	}
}
