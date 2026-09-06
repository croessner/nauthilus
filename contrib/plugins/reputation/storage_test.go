package main

import (
	"errors"
	"testing"

	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/go-redis/redismock/v9"
)

// TestIngestionRequiresReadyWriter rejects evidence before any manifest or subject access.
func TestIngestionRequiresReadyWriter(t *testing.T) {
	owner := &stateOwner{}

	result, err := owner.ingest(t.Context(), admittedObservation{})
	if !errors.Is(err, errStateUnavailable) || result != (ingestionResult{}) {
		t.Fatal("unready writer accepted evidence")
	}
}

// TestRedisDrainFailureClosesLocalWriter preserves local fencing when durable quiescence is unavailable.
func TestRedisDrainFailureClosesLocalWriter(t *testing.T) {
	client, mock := redismock.NewClientMock()

	t.Cleanup(func() { requireNoError(t, mock.ExpectationsWereMet()); _ = client.Close() })
	cfg := testConfig(t)
	owner, err := newStateOwner(cfg, manifestTestTagger(t, false), pluginruntime.NewRedisFacade(rediscli.NewTestClient(client)))
	requireNoError(t, err)
	owner.ready.Store(true)
	// No script was uploaded, so the host registry rejects before accessing Redis.
	if !errors.Is(owner.quiesce(t.Context()), errStateUnavailable) || owner.ready.Load() {
		t.Fatal("failed drain retained local writer readiness")
	}
}

// TestRedisShardBudgetsNeverExceedGlobalCeiling covers uneven division and budgets below shard count.
func TestRedisShardBudgetsNeverExceedGlobalCeiling(t *testing.T) {
	for _, total := range []int{1, 15, 16, 17, 10000, 100000} {
		sum := 0
		for shard := range manifestShardCount {
			sum += shardBudget(total, shard)
		}

		if sum != total {
			t.Fatal("distributed quota changed the global ceiling")
		}
	}
}
