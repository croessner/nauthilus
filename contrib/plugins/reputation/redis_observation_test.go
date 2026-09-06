//go:build reputation_integration

package main

import (
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// TestReputationRedisObservationAdmissionNeverAllocatesBeforePolicy keeps validation read-only and preserves exact late retries.
func TestReputationRedisObservationAdmissionNeverAllocatesBeforePolicy(t *testing.T) {
	client, facade := localReputationRedis(t)
	cfg := shortRetentionConfig(t)
	tagger := manifestTestTagger(t, false)
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))

	input := testObservation()
	input.observedAt = time.Now().UTC()
	source := cfg.apiSources["ScanWriter"]
	admitted, reason, err := owner.admitForPolicy(t.Context(), source, input, nil)
	requireNoError(t, err)

	if reason != reasonValid {
		t.Fatal("fresh observation not eligible")
	}

	manifests, err := client.Keys(t.Context(), "test-reputation:reputation:event:*:manifest:*").Result()
	requireNoError(t, err)

	if len(manifests) != 0 {
		t.Fatal("fact provider allocated evidence before Policy selected its effect")
	}

	_, err = owner.ingest(t.Context(), admitted)
	requireNoError(t, err)
	time.Sleep(150 * time.Millisecond)

	_, reason, err = owner.admitForPolicy(t.Context(), source, input, nil)
	requireNoError(t, err)

	if reason != reasonValid {
		t.Fatal("immutable manifest-backed retry was denied by first-admission age")
	}

	changed := input
	changed.subjects = append([]subjectInput(nil), input.subjects...)
	changed.subjects[0].value = "192.0.3.4"
	_, reason, err = owner.admitForPolicy(t.Context(), source, changed, nil)
	requireNoError(t, err)

	if reason != reasonConflict {
		t.Fatal("changed retry did not fail admission")
	}
}

// TestReputationRedisSelectedEffectDeduplicatesAndResumesUnknownOutcome exercises the actual immutable native effect contract.
func TestReputationRedisSelectedEffectDeduplicatesAndResumesUnknownOutcome(t *testing.T) {
	_, facade := localReputationRedis(t)
	cfg := testConfig(t)
	tagger := manifestTestTagger(t, false)
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))
	admitted := integrationObservation(t, cfg, tagger, "effect-retry")
	request := testObservationEffectRequest(t, admitted, "ScanWriter")
	provider := observationStorageProvider{plugin: &Plugin{config: cfg, state: owner, tagger: tagger}}
	owner.redis = interruptRedis(facade, scriptIngestion, true, 1)
	first, err := provider.Execute(t.Context(), request)
	requireNoError(t, err)
	requireNoError(t, pluginapi.ValidateDecisionEffectResult(first))

	if first.Outcome != pluginapi.DecisionEffectOutcomeUnknown {
		t.Fatal("lost write acknowledgment did not retain unknown outcome")
	}

	for range 2 {
		retry, err := provider.Execute(t.Context(), request)
		requireNoError(t, err)

		if retry.Outcome != pluginapi.DecisionEffectOutcomeSucceeded {
			t.Fatal("safe retry or duplicate did not succeed")
		}
	}
}

// TestReputationRedisSelectedEffectRejectsTamperedPlan repeats critical admission before any mutation.
func TestReputationRedisSelectedEffectRejectsTamperedPlan(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*admittedObservation)
		principal string
	}{
		{name: "weight", principal: "ScanWriter", mutate: func(a *admittedObservation) { a.subjects[0].weight++ }},
		{name: "primary boundary", principal: "ScanWriter", mutate: func(a *admittedObservation) { a.subjects[0].primary = false }},
		{name: "wrong principal", principal: "other", mutate: func(*admittedObservation) {}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			client, facade := localReputationRedis(t)
			cfg := testConfig(t)
			tagger := manifestTestTagger(t, false)
			owner, err := newStateOwner(cfg, tagger, facade)
			requireNoError(t, err)
			requireNoError(t, owner.start(t.Context()))
			admitted := integrationObservation(t, cfg, tagger, "tampered-effect")
			tt.mutate(&admitted)

			provider := observationStorageProvider{plugin: &Plugin{config: cfg, state: owner, tagger: tagger}}
			result, err := provider.Execute(t.Context(), testObservationEffectRequest(t, admitted, tt.principal))
			requireNoError(t, err)

			if result.Outcome != pluginapi.DecisionEffectOutcomeFailed {
				t.Fatal("tampered effect plan was accepted")
			}

			keys, err := client.Keys(t.Context(), "test-reputation:reputation:event:*:manifest:*").Result()
			requireNoError(t, err)

			if len(keys) != 0 {
				t.Fatal("invalid effect allocated evidence")
			}
		})
	}
}
