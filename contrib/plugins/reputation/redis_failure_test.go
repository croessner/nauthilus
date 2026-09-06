//go:build reputation_integration

package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

type interruptedRedis struct {
	pluginapi.Redis
	registry *interruptedScripts
}

// Scripts substitutes one bounded transport failure while preserving the real host registry.
func (r interruptedRedis) Scripts() pluginapi.RedisScriptRegistry { return r.registry }

type interruptedScripts struct {
	pluginapi.RedisScriptRegistry
	name      string
	after     bool
	remaining atomic.Int32
}

// Run loses exactly one request or acknowledgment at the selected script boundary.
func (s *interruptedScripts) Run(ctx context.Context, name string, keys []string, args ...any) (any, error) {
	if name != s.name || s.remaining.Add(-1) != 0 {
		return s.RedisScriptRegistry.Run(ctx, name, keys, args...)
	}

	if s.after {
		if _, err := s.RedisScriptRegistry.Run(ctx, name, keys, args...); err != nil {
			return nil, err
		}
	}

	return nil, context.DeadlineExceeded
}

// interruptRedis wraps an owned connection without introducing retries or alternate storage paths.
func interruptRedis(facade pluginapi.Redis, name string, after bool, occurrence int32) pluginapi.Redis {
	registry := &interruptedScripts{RedisScriptRegistry: facade.Scripts(), name: name, after: after}
	registry.remaining.Store(occurrence)

	return interruptedRedis{Redis: facade, registry: registry}
}

// TestReputationRedisInterruptedWritesResumeExactlyOnce covers lost requests and acknowledgments for both write boundaries.
func TestReputationRedisInterruptedWritesResumeExactlyOnce(t *testing.T) {
	cases := []struct {
		name       string
		script     string
		after      bool
		duplicates int
	}{
		{"manifest request", scriptManifest, false, 0},
		{"manifest acknowledgment", scriptManifest, true, 0},
		{"subject request", scriptIngestion, false, 0},
		{"subject acknowledgment", scriptIngestion, true, 1},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			client, facade := localReputationRedis(t)
			cfg := testConfig(t)
			tagger := manifestTestTagger(t, false)
			owner, err := newStateOwner(cfg, tagger, interruptRedis(facade, tt.script, tt.after, 1))
			requireNoError(t, err)
			requireNoError(t, owner.start(t.Context()))
			admitted := integrationObservation(t, cfg, tagger, "interrupted-event")

			_, err = owner.ingest(t.Context(), admitted)
			if !errors.Is(err, errStateUnavailable) {
				t.Fatal("transport uncertainty was hidden")
			}

			if tt.script == scriptManifest {
				keys, err := client.Keys(t.Context(), "test-reputation:reputation:*:state:*").Result()
				requireNoError(t, err)

				if len(keys) != 0 {
					t.Fatal("subject write preceded acknowledged manifest admission")
				}
			}

			retried, err := owner.ingest(t.Context(), admitted)
			requireNoError(t, err)

			if retried.Duplicates != tt.duplicates || retried.Applied != 2-tt.duplicates {
				t.Fatal("retry failed to resume exact frozen work")
			}

			final, err := owner.ingest(t.Context(), admitted)
			requireNoError(t, err)

			if final.Applied != 0 || final.Duplicates != 2 {
				t.Fatal("completed retry counted evidence twice")
			}
		})
	}
}

// TestReputationRedisAllocationActivationResumesAfterPartialShards preserves the predecessor fence across startup retries.
func TestReputationRedisAllocationActivationResumesAfterPartialShards(t *testing.T) {
	_, facade := localReputationRedis(t)
	cfg := shortRetentionConfig(t)
	old, err := newStateOwner(cfg, manifestTestTagger(t, false), facade)
	requireNoError(t, err)
	requireNoError(t, old.start(t.Context()))
	requireNoError(t, old.quiesce(t.Context()))
	time.Sleep(1100 * time.Millisecond)

	cfg.raw.AllocationDrainGeneration = 1
	nextTagger := manifestTestTaggerWithAllocation(t, false, "ffeeddccbbaa9988ffeeddccbbaa9988")
	next, err := newStateOwner(cfg, nextTagger, interruptRedis(facade, scriptControl, true, 4))
	requireNoError(t, err)
	requireError(t, next.start(t.Context()))

	if next.ready.Load() {
		t.Fatal("partial shard activation published readiness")
	}

	restarted, err := newStateOwner(cfg, nextTagger, facade)
	requireNoError(t, err)
	requireNoError(t, restarted.start(t.Context()))
	_, err = restarted.ingest(t.Context(), integrationObservation(t, cfg, nextTagger, "recovered-allocation"))
	requireNoError(t, err)
}

// TestReputationRedisConcurrentRotationAllocatesOnePlan fences competing writer generations at one shared manifest.
func TestReputationRedisConcurrentRotationAllocatesOnePlan(t *testing.T) {
	client, facade := localReputationRedis(t)
	cfg := testConfig(t)
	oldTagger, nextTagger := manifestTestTagger(t, false), manifestTestTagger(t, true)
	old, err := newStateOwner(cfg, oldTagger, facade)
	requireNoError(t, err)
	next, err := newStateOwner(cfg, nextTagger, facade)
	requireNoError(t, err)
	requireNoError(t, old.start(t.Context()))
	requireNoError(t, next.start(t.Context()))
	admitted := integrationObservation(t, cfg, oldTagger, "concurrent-rotation")

	type outcome struct {
		result ingestionResult
		err    error
	}

	gate := make(chan struct{})
	outcomes := make(chan outcome, 2)

	for _, owner := range []*stateOwner{old, next} {
		go func() {
			<-gate

			result, err := owner.ingest(t.Context(), admitted)
			outcomes <- outcome{result: result, err: err}
		}()
	}

	close(gate)

	applied := 0

	for range 2 {
		outcome := <-outcomes
		if outcome.err != nil && !errors.Is(outcome.err, errEventConflict) {
			t.Fatal(outcome.err)
		}

		applied += outcome.result.Applied
	}

	if applied != 2 {
		t.Fatal("competing generations mixed or duplicated their subject plans")
	}

	manifests, err := client.Keys(t.Context(), "test-reputation:reputation:event:*:manifest:*").Result()
	requireNoError(t, err)

	if len(manifests) != 1 {
		t.Fatal("rotation allocated multiple manifests")
	}

	retried, err := next.ingest(t.Context(), admitted)
	requireNoError(t, err)

	if retried.Applied != 0 || retried.Duplicates != 2 {
		t.Fatal("new generation cannot resume winning plan")
	}
}
