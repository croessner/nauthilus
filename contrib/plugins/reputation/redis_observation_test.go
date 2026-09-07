//go:build reputation_integration

package main

import (
	"context"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// TestReputationRedisVerifiedASNAbsenceReplaysWithoutInventedSubject keeps the committed IP/network plan immutable.
func TestReputationRedisVerifiedASNAbsenceReplaysWithoutInventedSubject(t *testing.T) {
	_, facade := localReputationRedis(t)
	cfg := testASNObservationConfig(t)
	owner, err := newStateOwner(cfg, manifestTestTagger(t, false), facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))
	input := testObservation()
	input.observedAt = time.Now().UTC()
	source := cfg.apiSources["ScanWriter"]
	age := int64(1)
	record, err := recordInputs([]outputInput{stringOutput("ip", "192.0.2.3"), stringOutput("lookup_state", assessmentMissing),
		{name: "data_age_seconds", input: pluginapi.DecisionValueInput{Integer: &age}}})
	requireNoError(t, err)
	resolver := providerASNResolver{source: source, records: []pluginapi.DecisionRecord{record}}
	admitted, reason, err := owner.admitForPolicy(t.Context(), source, input, resolver)
	requireNoError(t, err)
	if reason != reasonValid {
		t.Fatal("verified absence prevented admission")
	}

	first, err := owner.ingest(t.Context(), admitted)
	requireNoError(t, err)
	if first.Applied != 2 {
		t.Fatal("IP and network were not committed exactly once")
	}

	_, reason, err = owner.admitForPolicy(t.Context(), source, input, changingASNFixture{})
	requireNoError(t, err)
	if reason != reasonConflict {
		t.Fatal("changed ASN attribution was not rejected")
	}

	retry, reason, err := owner.admitForPolicy(t.Context(), source, input, resolver)
	requireNoError(t, err)
	if reason != reasonValid {
		t.Fatal("immutable retry was not admitted")
	}

	duplicate, err := owner.ingest(t.Context(), retry)
	requireNoError(t, err)
	if duplicate.Applied != 0 || duplicate.Duplicates != 2 {
		t.Fatal("retry changed the committed no-ASN subject plan")
	}

	if value := owner.assess(t.Context(), subjectInput{kind: kindASN, value: "64501"}, profileOperational); value.State != assessmentMissing {
		t.Fatal("retry invented an ASN observation")
	}
}

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

// TestReputationRedisRetryRejectsChangedASNPlan proves the exact stored plan cannot adopt changed or unavailable provider evidence.
func TestReputationRedisRetryRejectsChangedASNPlan(t *testing.T) {
	_, facade := localReputationRedis(t)
	cfg := testASNObservationConfig(t)
	tagger := manifestTestTagger(t, false)
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))

	input := testObservation()
	input.observedAt = time.Now().UTC()
	source := cfg.apiSources["ScanWriter"]
	initial, reason, err := owner.admitForPolicy(t.Context(), source, input, exactASNFixture{binding: source.config.ASNProvider, ip: input.subjects[0].value})
	requireNoError(t, err)

	if reason != reasonValid {
		t.Fatal("initial ASN plan rejected")
	}

	_, err = owner.ingest(t.Context(), initial)
	requireNoError(t, err)
	_, _, err = owner.admitForPolicy(t.Context(), source, input, nil)
	requireError(t, err)
	_, reason, err = owner.admitForPolicy(t.Context(), source, input, changingASNFixture{})
	requireNoError(t, err)

	if reason != reasonConflict {
		t.Fatal("changed derived ASN was not rejected as event_conflict")
	}

	retry, reason, err := owner.admitForPolicy(t.Context(), source, input, exactASNFixture{binding: source.config.ASNProvider, ip: input.subjects[0].value})
	requireNoError(t, err)

	if reason != reasonValid {
		t.Fatal("exact stored plan could not be resumed")
	}

	result, err := owner.ingest(t.Context(), retry)
	requireNoError(t, err)

	if result.Applied != 0 || result.Duplicates != 3 {
		t.Fatalf("stored plan changed: %+v", result)
	}
}

type changingASNFixture struct{}

// lookupASN simulates a new geographic snapshot mapping the same IP to another ASN.
func (changingASNFixture) lookupASN(context.Context, string, string) (string, error) {
	return "64501", nil
}
