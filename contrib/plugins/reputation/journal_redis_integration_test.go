//go:build reputation_integration

package main

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/contrib/plugins/internal/telemetry"
	"github.com/redis/go-redis/v9"
)

type capturedJournal struct {
	key     string
	payload manifestPayload
	expiry  float64
}

// enqueue captures exactly the frozen contribution passed to durable transport.
func (c *capturedJournal) enqueue(_ context.Context, key string, payload manifestPayload, expiry float64) error {
	c.key, c.payload, c.expiry = key, payload, expiry
	return nil
}

// TestReputationRedisJournalPartialReplay preserves score history across a failed multi-subject delivery.
func TestReputationRedisJournalPartialReplay(t *testing.T) {
	client, facade := localReputationRedis(t)
	cfg := testConfig(t)
	tagger := manifestTestTagger(t, false)
	state, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, state.start(t.Context()))

	captured := &capturedJournal{}
	state.journal = captured
	admitted := integrationObservation(t, cfg, tagger, "journal-partial")
	result, err := state.ingest(t.Context(), admitted)
	requireNoError(t, err)

	if !result.Queued || result.Applied != 0 {
		t.Fatal("durable acceptance was confused with score application")
	}

	model := captured.payload.Models[0]
	duplicate, err := state.updateSubject(t.Context(), captured.payload, model, model.Subjects[0], captured.expiry)
	requireNoError(t, err)

	if duplicate {
		t.Fatal("first partial contribution was already seen")
	}

	frozen, err := json.Marshal(captured.payload)
	requireNoError(t, err)

	codec := journalCodec{tagger: tagger, scope: cfg.raw.ManifestScope, topic: "reputation.test"}
	record, err := codec.encode(t.Context(), captured.key, string(frozen), captured.expiry)
	requireNoError(t, err)
	counter, err := telemetry.RegisterCounter(&metricCapture{}, "journal_total", "Journal test outcomes.",
		telemetry.Dimension{Name: metricResult, Values: []string{storageApplied, storageDuplicate}})
	requireNoError(t, err)

	consumer := &journalRuntime{state: state, codec: codec, metrics: &journalTelemetry{outcome: counter}}
	requireNoError(t, consumer.apply(t.Context(), captured.key, record))
	requireNoError(t, consumer.apply(t.Context(), captured.key, record))
	assertJournalSampleCounts(t, client, state, model)

	after, err := state.applyManifest(t.Context(), captured.payload, captured.expiry)
	requireNoError(t, err)

	if after.Applied != 0 || after.Duplicates != 2 {
		t.Fatal("partial replay did not retain exact same-subject deduplication")
	}
}

// assertJournalSampleCounts proves redelivery did not increase any decayed sample accumulator.
func assertJournalSampleCounts(t *testing.T, client *redis.Client, state *stateOwner, model manifestModel) {
	t.Helper()

	for _, subject := range model.Subjects {
		fields, err := client.HGetAll(t.Context(), state.keys.subject(subject.Tag, model.ID).State).Result()
		requireNoError(t, err)

		observed := 0

		for field, text := range fields {
			if !strings.HasSuffix(field, "_samples") {
				continue
			}

			samples, err := strconv.ParseFloat(text, 64)
			requireNoError(t, err)

			observed++

			if samples <= 0 || samples > 1.001 {
				t.Fatal("duplicate Kafka delivery increased the sample count")
			}
		}

		if observed == 0 {
			t.Fatal("journal delivery did not produce a sample accumulator")
		}
	}
}
