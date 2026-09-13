//go:build reputation_integration

package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// TestReputationRedisExpiryCleanupIsBounded reproduces an unbounded hot-subject cleanup in the shared Redis event loop.
func TestReputationRedisExpiryCleanupIsBounded(t *testing.T) {
	client, facade := localReputationRedis(t)
	cfg := testConfig(t)
	cfg.raw.SubjectSeenCapacityPerSubject = 20000
	tagger := manifestTestTagger(t, false)
	state, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, state.start(t.Context()))
	admitted := integrationObservation(t, cfg, tagger, "before-expiry-wave")
	_, err = state.ingest(t.Context(), admitted)
	requireNoError(t, err)

	keys := state.keys.subject(admitted.subjects[0].tag, cfg.raw.ModelID)
	members := make([]redis.Z, 1500)

	for index := range members {
		members[index] = redis.Z{Score: float64(time.Now().Add(-time.Minute).Unix()), Member: fmt.Sprintf("expired-%d", index)}
	}

	requireNoError(t, client.ZAdd(t.Context(), keys.Seen, members...).Err())
	next := integrationObservation(t, cfg, tagger, "after-expiry-wave")
	_, err = state.ingest(t.Context(), next)
	requireNoError(t, err)
	remaining, err := client.ZCard(t.Context(), keys.Seen).Result()
	requireNoError(t, err)

	if remaining < 900 || remaining > 1100 {
		t.Fatalf("one update removed an unbounded expiry wave: remaining=%d", remaining)
	}
}
