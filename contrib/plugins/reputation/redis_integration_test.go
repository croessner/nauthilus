//go:build reputation_integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/redis/go-redis/v9"
)

// localReputationRedis starts one private socket-only server through the shared test runtime.
func localReputationRedis(t *testing.T) (*redis.Client, pluginapi.Redis) {
	t.Helper()
	directory := privateRedisDirectory(t)
	socket := filepath.Join(directory, "redis.sock")
	startPrivateRedis(t, directory, "--port", "0", "--unixsocket", socket, "--unixsocketperm", "700")
	client := redis.NewClient(&redis.Options{Network: "unix", Addr: socket, MaxRetries: -1})

	t.Cleanup(func() { _ = client.Close() })
	waitPrivateRedis(t, client)

	return client, localRedisFacade(client)
}

// integrationObservation creates fresh independent evidence and retains its immutable admission plan.
func integrationObservation(t *testing.T, cfg *configuration, tagger pluginapi.OpaqueIdentifierTagger, event string) admittedObservation {
	t.Helper()

	input := testObservation()
	input.eventID = event
	input.observedAt = time.Now().UTC()
	admitted, reason, err := cfg.admitObservation(context.Background(), cfg.apiSources["ScanWriter"], input, input.observedAt, tagger, nil)
	requireNoError(t, err)

	if reason != reasonValid {
		t.Fatal("integration observation failed admission")
	}

	return admitted
}

// TestReputationRedisIngestionDeduplicatesAndRejectsPayloadSubstitution exercises actual Redis script semantics.
func TestReputationRedisIngestionDeduplicatesAndRejectsPayloadSubstitution(t *testing.T) {
	client, facade := localReputationRedis(t)
	cfg := testConfig(t)
	tagger := manifestTestTagger(t, false)
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))
	admitted := integrationObservation(t, cfg, tagger, "original-event")
	first, err := owner.ingest(t.Context(), admitted)
	requireNoError(t, err)

	if first.Applied != 2 {
		t.Fatal("complete subject plan was not applied")
	}

	second, err := owner.ingest(t.Context(), admitted)
	requireNoError(t, err)

	if second.Applied != 0 || second.Duplicates != 2 {
		t.Fatal("retry counted evidence again")
	}

	state := owner.keys.subject(admitted.subjects[0].tag, cfg.raw.ModelID).State
	before, err := client.HGetAll(t.Context(), state).Result()
	requireNoError(t, err)

	changed := admitted
	changed.input.magnitude = new(float64)

	_, err = owner.ingest(t.Context(), changed)
	if !errors.Is(err, errEventConflict) {
		t.Fatal("changed payload was not rejected as conflict")
	}

	after, err := client.HGetAll(t.Context(), state).Result()
	requireNoError(t, err)

	if before["fast_mail_filter_samples"] != after["fast_mail_filter_samples"] {
		t.Fatal("conflict altered subject state")
	}
}

// TestReputationRedisManifestTimeIsAuthoritative rejects a fresh host plan whose Redis-time evidence is stale.
func TestReputationRedisManifestTimeIsAuthoritative(t *testing.T) {
	client, facade := localReputationRedis(t)
	cfg := testConfig(t)
	tagger := manifestTestTagger(t, false)
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))
	admitted := integrationObservation(t, cfg, tagger, "stale-event")
	admitted.input.observedAt = admitted.input.observedAt.Add(-48 * time.Hour)

	_, err = owner.ingest(t.Context(), admitted)
	if !errors.Is(err, errEventTime) {
		t.Fatal("host clock admitted stale evidence")
	}

	keys, err := client.Keys(t.Context(), "test-reputation:reputation:event:*:manifest:*").Result()
	requireNoError(t, err)

	if len(keys) != 0 {
		t.Fatal("rejected event left a manifest behind")
	}
}

// TestReputationRedisMalformedStateFailsWithoutRepair rejects corrupted accumulators instead of silently resetting evidence.
func TestReputationRedisMalformedStateFailsWithoutRepair(t *testing.T) {
	cases := []struct {
		name, field, value string
		remove             bool
	}{
		{"missing mass", "fast_mail_filter_trust", "", true},
		{"NaN mass", "fast_mail_filter_trust", "nan", false},
		{"infinite mass", "fast_mail_filter_trust", "inf", false},
		{"overflow mass", "fast_mail_filter_trust", "1000000000", false},
		{"missing clock", "fast_updated_at", "", true},
		{"unknown field", "unexpected", "1", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			client, facade := localReputationRedis(t)
			cfg := testConfig(t)
			tagger := manifestTestTagger(t, false)
			owner, err := newStateOwner(cfg, tagger, facade)
			requireNoError(t, err)
			requireNoError(t, owner.start(t.Context()))
			admitted := integrationObservation(t, cfg, tagger, "first-event")
			_, err = owner.ingest(t.Context(), admitted)
			requireNoError(t, err)

			key := owner.keys.subject(admitted.subjects[0].tag, cfg.raw.ModelID).State
			if tt.remove {
				requireNoError(t, client.HDel(t.Context(), key, tt.field).Err())
			} else {
				requireNoError(t, client.HSet(t.Context(), key, tt.field, tt.value).Err())
			}

			before, err := client.HGetAll(t.Context(), key).Result()
			requireNoError(t, err)
			_, err = owner.ingest(t.Context(), integrationObservation(t, cfg, tagger, "next-event"))
			requireError(t, err)
			after, err := client.HGetAll(t.Context(), key).Result()
			requireNoError(t, err)

			if !reflect.DeepEqual(before, after) {
				t.Fatal("malformed state was rewritten")
			}
		})
	}
}

// TestReputationRedisAllocationMetadataCannotBeSilentlyRepaired protects startup fencing from malformed durable metadata.
func TestReputationRedisAllocationMetadataCannotBeSilentlyRepaired(t *testing.T) {
	client, facade := localReputationRedis(t)
	cfg := testConfig(t)
	tagger := manifestTestTagger(t, false)
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))
	metadata := owner.keys.metadata()[0]
	requireNoError(t, client.HDel(t.Context(), metadata, "retention").Err())
	before, err := client.HGetAll(t.Context(), metadata).Result()
	requireNoError(t, err)
	retry, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireError(t, retry.start(t.Context()))
	after, err := client.HGetAll(t.Context(), metadata).Result()
	requireNoError(t, err)

	if !reflect.DeepEqual(before, after) {
		t.Fatal("malformed allocation metadata was repaired during startup")
	}
}

// TestReputationRedisPartialFanoutResumesTheFrozenPlan counts each independently committed subject only once.
func TestReputationRedisPartialFanoutResumesTheFrozenPlan(t *testing.T) {
	client, facade := localReputationRedis(t)
	cfg := testConfig(t)
	tagger := manifestTestTagger(t, false)
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))
	admitted := integrationObservation(t, cfg, tagger, "partial-event")
	broken := owner.keys.subject(admitted.subjects[1].tag, cfg.raw.ModelID).State
	requireNoError(t, client.Set(t.Context(), broken, "invalid-type", 0).Err())
	partial, err := owner.ingest(t.Context(), admitted)
	requireError(t, err)

	if partial.Applied != 1 {
		t.Fatal("test did not exercise a partially committed fanout")
	}

	requireNoError(t, client.Del(t.Context(), broken).Err())
	resumed, err := owner.ingest(t.Context(), admitted)
	requireNoError(t, err)

	if resumed.Applied != 1 || resumed.Duplicates != 1 {
		t.Fatal("partial retry recounted a committed subject")
	}
}

// TestReputationRedisConcurrentConflictingCreatorsHaveOneWinner prevents mixed subject plans under one event ID.
func TestReputationRedisConcurrentConflictingCreatorsHaveOneWinner(t *testing.T) {
	_, facade := localReputationRedis(t)
	cfg := testConfig(t)
	tagger := manifestTestTagger(t, false)
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))
	first := integrationObservation(t, cfg, tagger, "contended-event")
	second := first
	magnitude := 0.5
	second.input.magnitude = &magnitude
	barrier := make(chan struct{})
	results := make(chan error, 2)

	for _, admitted := range []admittedObservation{first, second} {
		go func(input admittedObservation) {
			<-barrier

			_, err := owner.ingest(context.Background(), input)
			results <- err
		}(admitted)
	}

	close(barrier)

	winners, conflicts := 0, 0

	for range 2 {
		err := <-results
		if err == nil {
			winners++
		} else if errors.Is(err, errEventConflict) {
			conflicts++
		} else {
			t.Fatal("unexpected contention result")
		}
	}

	if winners != 1 || conflicts != 1 {
		t.Fatal("conflicting creators did not resolve to exactly one immutable plan")
	}
}

// TestReputationRedisRotationResumesPreviousPlan uses one stable allocation and never creates parallel active-key evidence.
func TestReputationRedisRotationResumesPreviousPlan(t *testing.T) {
	client, facade := localReputationRedis(t)
	cfg := testConfig(t)
	oldTagger := manifestTestTagger(t, false)
	old, err := newStateOwner(cfg, oldTagger, facade)
	requireNoError(t, err)
	requireNoError(t, old.start(t.Context()))
	admitted := integrationObservation(t, cfg, oldTagger, "rotation-event")
	_, err = old.ingest(t.Context(), admitted)
	requireNoError(t, err)
	rotatedTagger := manifestTestTagger(t, true)
	rotated, err := newStateOwner(cfg, rotatedTagger, facade)
	requireNoError(t, err)
	requireNoError(t, rotated.start(t.Context()))
	retried, err := rotated.ingest(t.Context(), admitted)
	requireNoError(t, err)

	if retried.Applied != 0 || retried.Duplicates != 2 {
		t.Fatal("rotated writer did not resume the previous plan")
	}

	tag, err := rotatedTagger.Tag(t.Context(), pluginapi.OpaqueIdentifierInput{Scope: cfg.raw.SubjectScope, Kind: kindIP, Value: "192.0.2.3"})
	requireNoError(t, err)
	exists, err := client.Exists(t.Context(), rotated.keys.subject(tag.String(), cfg.raw.ModelID).State).Result()
	requireNoError(t, err)

	if exists != 0 {
		t.Fatal("retry duplicated previous history into the active key slot")
	}

	newer := integrationObservation(t, cfg, rotatedTagger, "new-key-event")
	_, err = rotated.ingest(t.Context(), newer)
	requireNoError(t, err)

	_, err = old.ingest(t.Context(), newer)
	if !errors.Is(err, errEventConflict) {
		t.Fatal("older writer accepted an unreproducible new-key plan")
	}
}

// TestReputationRedisModelMismatchRejectsStartup keeps persisted evidence tied to its original ingestion semantics.
func TestReputationRedisModelMismatchRejectsStartup(t *testing.T) {
	client, facade := localReputationRedis(t)
	cfg := testConfig(t)
	tagger := manifestTestTagger(t, false)
	first, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, first.start(t.Context()))
	before, err := client.HGetAll(t.Context(), first.keys.metadata()[1]).Result()
	requireNoError(t, err)
	raw := testConfigMap(t)
	raw["signals"].(map[string]any)["scan.clean"].(map[string]any)["weight"] = 0.5
	changed, err := decodeConfig(pluginregistry.NewConfigView(raw))
	requireNoError(t, err)
	next, err := newStateOwner(changed, tagger, facade)
	requireNoError(t, err)

	if err := next.start(t.Context()); !errors.Is(err, errModelMismatch) {
		t.Fatal("changed semantics reused a persisted model identity")
	}

	after, err := client.HGetAll(t.Context(), first.keys.metadata()[1]).Result()
	requireNoError(t, err)

	if !reflect.DeepEqual(before, after) {
		t.Fatal("model mismatch rewrote durable registration")
	}
}

// TestReputationRedisMalformedManifestIsIndeterminate rejects structural corruption before any subject update.
func TestReputationRedisMalformedManifestIsIndeterminate(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"missing fingerprint", func(value map[string]any) { delete(value, "fingerprint") }},
		{"malformed payload", func(value map[string]any) { value["payload"] = "not-json" }},
		{"unknown field", func(value map[string]any) { value["unexpected"] = true }},
		{"extended expiry", func(value map[string]any) { value["expires"] = value["expires"].(float64) + 60 }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			client, facade := localReputationRedis(t)
			cfg := testConfig(t)
			tagger := manifestTestTagger(t, false)
			owner, err := newStateOwner(cfg, tagger, facade)
			requireNoError(t, err)
			requireNoError(t, owner.start(t.Context()))
			admitted := integrationObservation(t, cfg, tagger, "damaged-manifest")
			_, err = owner.ingest(t.Context(), admitted)
			requireNoError(t, err)
			plan, err := owner.planner.plan(t.Context(), admitted)
			requireNoError(t, err)

			keys, _ := owner.keys.manifest(plan.AllocationTag, plan.SourceTag)
			raw, err := client.Get(t.Context(), keys[0]).Bytes()
			requireNoError(t, err)

			var envelope map[string]any
			requireNoError(t, json.Unmarshal(raw, &envelope))
			tt.mutate(envelope)
			corrupted, err := json.Marshal(envelope)
			requireNoError(t, err)
			requireNoError(t, client.SetArgs(t.Context(), keys[0], corrupted, redis.SetArgs{KeepTTL: true}).Err())

			_, err = owner.ingest(t.Context(), admitted)
			if !errors.Is(err, errStateUnavailable) {
				t.Fatal("malformed manifest was accepted or classified as an ordinary payload conflict")
			}

			after, err := client.Get(t.Context(), keys[0]).Bytes()
			requireNoError(t, err)

			if !bytes.Equal(corrupted, after) {
				t.Fatal("malformed manifest was rewritten")
			}
		})
	}
}

// shortRetentionConfig keeps real expiry and drain tests short while preserving every retention relationship.
func shortRetentionConfig(t *testing.T) *configuration {
	t.Helper()
	raw := testConfigMap(t)
	raw["retention"] = "5s"
	raw["event_manifest_ttl"] = "1s"
	raw["subject_seen_ttl"] = "1s"
	raw["maximum_retry_horizon"] = "100ms"
	raw["profiles"] = map[string]any{"fast": map[string]any{"half_life": "1s"}, "operational": map[string]any{"half_life": "2s"}, "baseline": map[string]any{"half_life": "3s"}}
	source := raw["sources"].(map[string]any)["scan"].(map[string]any)
	source["maximum_lateness"] = "100ms"
	source["future_clock_skew"] = "0s"
	raw["signals"].(map[string]any)["scan.clean"].(map[string]any)["max_event_age"] = "100ms"
	cfg, err := decodeConfig(pluginregistry.NewConfigView(raw))
	requireNoError(t, err)

	return cfg
}

// TestReputationRedisAllocationKeyRequiresCompletedDrain rejects uncoordinated replacement and fences old writers.
func TestReputationRedisAllocationKeyRequiresCompletedDrain(t *testing.T) {
	_, facade := localReputationRedis(t)
	cfg := shortRetentionConfig(t)
	oldTagger := manifestTestTagger(t, false)
	old, err := newStateOwner(cfg, oldTagger, facade)
	requireNoError(t, err)
	requireNoError(t, old.start(t.Context()))

	otherOld, err := newStateOwner(cfg, oldTagger, facade)
	requireNoError(t, err)
	requireNoError(t, otherOld.start(t.Context()))
	nextTagger := manifestTestTaggerWithAllocation(t, false, "ffeeddccbbaa9988ffeeddccbbaa9988")
	nextCfg := shortRetentionConfig(t)
	nextCfg.raw.AllocationDrainGeneration = 1
	next, err := newStateOwner(nextCfg, nextTagger, facade)
	requireNoError(t, err)

	if err := next.start(t.Context()); !errors.Is(err, errAllocationMismatch) {
		t.Fatal("allocation key changed without a drain")
	}

	requireNoError(t, old.quiesce(t.Context()))

	if err := next.start(t.Context()); !errors.Is(err, errAllocationMismatch) {
		t.Fatal("allocation drain skipped maximum retention")
	}

	_, err = otherOld.ingest(t.Context(), integrationObservation(t, cfg, oldTagger, "quiesced-event"))
	if !errors.Is(err, errAllocationMismatch) {
		t.Fatal("already-ready writer bypassed shard quiescence")
	}

	time.Sleep(1100 * time.Millisecond)
	requireNoError(t, next.start(t.Context()))
	_, err = next.ingest(t.Context(), integrationObservation(t, nextCfg, nextTagger, "new-allocation-event"))
	requireNoError(t, err)

	if err := otherOld.start(t.Context()); !errors.Is(err, errAllocationMismatch) {
		t.Fatal("old writer reopened a drained allocation")
	}
}

// TestReputationRedisExactRetryUsesManifestExpiry preserves valid late retries without refreshing their retention.
func TestReputationRedisExactRetryUsesManifestExpiry(t *testing.T) {
	client, facade := localReputationRedis(t)
	cfg := shortRetentionConfig(t)
	tagger := manifestTestTagger(t, false)
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))
	admitted := integrationObservation(t, cfg, tagger, "late-retry")
	_, err = owner.ingest(t.Context(), admitted)
	requireNoError(t, err)
	plan, err := owner.planner.plan(t.Context(), admitted)
	requireNoError(t, err)

	keys, _ := owner.keys.manifest(plan.AllocationTag, plan.SourceTag)
	before, err := client.PTTL(t.Context(), keys[0]).Result()
	requireNoError(t, err)
	time.Sleep(150 * time.Millisecond)

	retry, err := owner.ingest(t.Context(), admitted)
	requireNoError(t, err)

	if retry.Duplicates != 2 {
		t.Fatal("late exact retry was reclassified as a new event")
	}

	after, err := client.PTTL(t.Context(), keys[0]).Result()
	requireNoError(t, err)

	if after >= before {
		t.Fatal("retry refreshed manifest retention")
	}

	time.Sleep(time.Second)

	_, err = owner.ingest(t.Context(), admitted)
	if !errors.Is(err, errEventTime) {
		t.Fatal("expired retry was admitted as a new event")
	}
}

// TestReputationRedisShadowModelsDeduplicateIndependently preserves active selection and isolated accumulators.
func TestReputationRedisShadowModelsDeduplicateIndependently(t *testing.T) {
	client, facade := localReputationRedis(t)
	raw := testConfigMap(t)
	raw["shadow_model"] = map[string]any{"model_id": "shadow-test", "profiles": raw["profiles"], "source_class_caps": raw["source_class_caps"], "signal_weights": map[string]any{"scan.clean": 0.5}}
	cfg, err := decodeConfig(pluginregistry.NewConfigView(raw))
	requireNoError(t, err)
	tagger := manifestTestTagger(t, false)
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))
	admitted := integrationObservation(t, cfg, tagger, "shadow-event")
	first, err := owner.ingest(t.Context(), admitted)
	requireNoError(t, err)

	if first.Applied != 4 {
		t.Fatal("active and shadow models did not receive independent updates")
	}

	repeat, err := owner.ingest(t.Context(), admitted)
	requireNoError(t, err)

	if repeat.Duplicates != 4 || owner.models[0].id != cfg.raw.ModelID {
		t.Fatal("shadow deduplication changed active selection")
	}

	for _, model := range owner.models {
		key := owner.keys.subject(admitted.subjects[0].tag, model.id)
		count, err := client.ZCard(t.Context(), key.Seen).Result()
		requireNoError(t, err)

		if count != 1 {
			t.Fatal("model seen sets were shared or duplicated")
		}
	}
}

// TestReputationRedisSourceClassesCapMassAndSamples bounds the influence of repeated valid producer events.
func TestReputationRedisSourceClassesCapMassAndSamples(t *testing.T) {
	client, facade := localReputationRedis(t)
	raw := testConfigMap(t)
	caps := raw["source_class_caps"].(map[string]any)["mail_filter"].(map[string]any)
	caps["trust"], caps["samples"] = 0.4, 2.0
	cfg, err := decodeConfig(pluginregistry.NewConfigView(raw))
	requireNoError(t, err)
	tagger := manifestTestTagger(t, false)
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))

	var admitted admittedObservation
	for index := range 4 {
		admitted = integrationObservation(t, cfg, tagger, fmt.Sprintf("capped-event-%d", index))
		_, err = owner.ingest(t.Context(), admitted)
		requireNoError(t, err)
	}

	key := owner.keys.subject(admitted.subjects[0].tag, cfg.raw.ModelID).State
	for field, maximum := range map[string]float64{"fast_mail_filter_trust": 0.4, "fast_mail_filter_samples": 2} {
		value, err := client.HGet(t.Context(), key, field).Float64()
		requireNoError(t, err)

		if value > maximum || value < maximum*0.99 {
			t.Fatal("source class ceiling did not cap the accumulator")
		}
	}
}

// TestReputationRedisSubjectSeenCardinalityIsBounded prevents one hot identity from growing an unbounded replay set.
func TestReputationRedisSubjectSeenCardinalityIsBounded(t *testing.T) {
	client, facade := localReputationRedis(t)
	raw := testConfigMap(t)
	raw["maximum_seen_events_per_subject"] = 1
	cfg, err := decodeConfig(pluginregistry.NewConfigView(raw))
	requireNoError(t, err)
	tagger := manifestTestTagger(t, false)
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))
	admitted := integrationObservation(t, cfg, tagger, "first-seen-event")
	_, err = owner.ingest(t.Context(), admitted)
	requireNoError(t, err)

	_, err = owner.ingest(t.Context(), integrationObservation(t, cfg, tagger, "excess-seen-event"))
	if !errors.Is(err, errQuotaExceeded) {
		t.Fatal("seen cardinality ceiling did not reject excess history")
	}

	count, err := client.ZCard(t.Context(), owner.keys.subject(admitted.subjects[0].tag, cfg.raw.ModelID).Seen).Result()
	requireNoError(t, err)

	if count != 1 {
		t.Fatal("seen set exceeded its configured ceiling")
	}
}

// sameShardObservation finds a producer event sharing the existing opaque allocation shard without guessing Redis keys.
func sameShardObservation(t *testing.T, owner *stateOwner, admitted admittedObservation, changeSubject bool) admittedObservation {
	t.Helper()
	original, err := owner.planner.plan(t.Context(), admitted)
	requireNoError(t, err)

	_, wanted := owner.keys.manifest(original.AllocationTag, original.SourceTag)

	for index := range 1000 {
		input := admitted.input
		input.eventID = fmt.Sprintf("same-shard-%d", index)

		input.subjects = append([]subjectInput(nil), input.subjects...)
		if changeSubject {
			input.subjects[0].value = "192.0.2.4"
		}

		next, reason, err := owner.config.admitObservation(t.Context(), admitted.source, input, input.observedAt, owner.planner.tagger, nil)
		requireNoError(t, err)

		if reason != reasonValid {
			t.Fatal("quota fixture failed admission")
		}

		plan, err := owner.planner.plan(t.Context(), next)
		requireNoError(t, err)

		_, shard := owner.keys.manifest(plan.AllocationTag, plan.SourceTag)
		if shard == wanted {
			return next
		}
	}

	t.Fatal("could not construct bounded shard quota fixture")

	return admittedObservation{}
}

// TestReputationRedisSourceQuotaRejectsBeforeManifestCreation bounds both new identities and event allocations.
func TestReputationRedisSourceQuotaRejectsBeforeManifestCreation(t *testing.T) {
	for _, limit := range []string{"maximum_event_manifests_per_source", "maximum_new_subjects_per_source_hour"} {
		t.Run(limit, func(t *testing.T) {
			client, facade := localReputationRedis(t)
			raw := testConfigMap(t)
			raw[limit] = manifestShardCount
			source := raw["sources"].(map[string]any)["scan"].(map[string]any)
			source["derived_subjects"] = map[string]any{}
			cfg, err := decodeConfig(pluginregistry.NewConfigView(raw))
			requireNoError(t, err)
			tagger := manifestTestTagger(t, false)
			owner, err := newStateOwner(cfg, tagger, facade)
			requireNoError(t, err)
			requireNoError(t, owner.start(t.Context()))
			admitted := integrationObservation(t, cfg, tagger, "quota-event")
			_, err = owner.ingest(t.Context(), admitted)
			requireNoError(t, err)
			next := sameShardObservation(t, owner, admitted, limit == "maximum_new_subjects_per_source_hour")

			_, err = owner.ingest(t.Context(), next)
			if !errors.Is(err, errQuotaExceeded) {
				t.Fatal("source allocation ceiling was not enforced")
			}

			plan, err := owner.planner.plan(t.Context(), next)
			requireNoError(t, err)

			keys, _ := owner.keys.manifest(plan.AllocationTag, plan.SourceTag)
			exists, err := client.Exists(t.Context(), keys[0]).Result()
			requireNoError(t, err)

			if exists != 0 {
				t.Fatal("quota rejection created an event manifest")
			}
		})
	}
}

// TestReputationRedisProducerLocalIDsRemainIndependent scopes deduplication to authenticated source-policy identity.
func TestReputationRedisProducerLocalIDsRemainIndependent(t *testing.T) {
	_, facade := localReputationRedis(t)
	raw := testConfigMap(t)
	other := testConfigMap(t)["sources"].(map[string]any)["scan"].(map[string]any)
	other["source_policy_id"] = "second-source"
	other["binding"].(map[string]any)["caller_principal"] = "SecondWriter"
	raw["sources"].(map[string]any)["second"] = other
	cfg, err := decodeConfig(pluginregistry.NewConfigView(raw))
	requireNoError(t, err)
	tagger := manifestTestTagger(t, false)
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))
	first := integrationObservation(t, cfg, tagger, "shared-local-id")
	second := first

	second.source = cfg.apiSources["SecondWriter"]
	for _, admitted := range []admittedObservation{first, second} {
		result, err := owner.ingest(t.Context(), admitted)
		requireNoError(t, err)

		if result.Applied != 2 || result.Duplicates != 0 {
			t.Fatal("independent source-local ID was treated as a duplicate")
		}
	}
}
