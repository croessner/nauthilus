//go:build reputation_integration

package main

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	"github.com/redis/go-redis/v9"
)

type laggingReplicaHost struct {
	integrationRedisHost
	replica redis.UniversalClient
}

// GetReadHandle exposes a deliberately stale independent server to detect enforcing-path replica routing.
func (h laggingReplicaHost) GetReadHandle() redis.UniversalClient { return h.replica }

// TestReputationRedisLaggingReplicaCannotHidePrimaryOverride proves the next assessment observes a just-written block.
func TestReputationRedisLaggingReplicaCannotHidePrimaryOverride(t *testing.T) {
	primary, _ := localReputationRedis(t)
	replica, _ := localReputationRedis(t)
	facade := pluginruntime.NewRedisFacade(laggingReplicaHost{integrationRedisHost: integrationRedisHost{client: primary}, replica: replica}, pluginruntime.RedisFacadePrefix("test-reputation:"))
	cfg := testConfig(t)
	owner, err := newStateOwner(cfg, manifestTestTagger(t, false), facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))

	subject := subjectInput{kind: kindIP, value: "192.0.2.12"}
	record, err := owner.putOverride(t.Context(), subject, overrideInput{Band: bandBlocked, Reason: "operator.block", Creator: "operator", AuditID: "primary-proof", Origin: "operator"})
	requireNoError(t, err)

	key := owner.keys.subject(record.Tag, cfg.raw.ModelID).Override
	exists, err := facade.Read().Exists(t.Context(), key).Result()
	requireNoError(t, err)

	if exists != 0 {
		t.Fatal("replica fixture unexpectedly contains the block")
	}

	result := owner.assess(t.Context(), subject, profileOperational)
	if result.Band != bandBlocked {
		t.Fatal("lagging replica hid primary block")
	}
}
