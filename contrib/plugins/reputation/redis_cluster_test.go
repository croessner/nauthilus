//go:build reputation_integration

package main

import (
	"strings"
	"testing"
)

// TestReputationRedisClusterUsesHostPrefixAndSameSlotScripts exercises the actual three-master topology.
func TestReputationRedisClusterUsesHostPrefixAndSameSlotScripts(t *testing.T) {
	client, facade := localReputationCluster(t)
	cfg := testConfig(t)
	tagger := manifestTestTagger(t, false)
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))
	admitted := integrationObservation(t, cfg, tagger, "cluster-event")
	plan, err := owner.planner.plan(t.Context(), admitted)
	requireNoError(t, err)

	manifest, _ := owner.keys.manifest(plan.AllocationTag, plan.SourceTag)

	groups := [][]string{owner.keys.metadata(), manifest}
	for _, subject := range admitted.subjects {
		keys := owner.keys.subject(subject.tag, cfg.raw.ModelID)
		groups = append(groups, []string{keys.State, keys.Seen, keys.Override})
	}

	for _, keys := range groups {
		slot := -1

		for _, key := range keys {
			if !strings.HasPrefix(key, "test-reputation:") {
				t.Fatal("host key prefix bypassed")
			}

			got, err := client.ClusterKeySlot(t.Context(), key).Result()
			requireNoError(t, err)

			if slot >= 0 && slot != int(got) {
				t.Fatal("script keys cross Cluster slots")
			}

			slot = int(got)
		}
	}

	first, err := owner.ingest(t.Context(), admitted)
	requireNoError(t, err)

	if first.Applied != 2 {
		t.Fatal("Cluster did not apply complete subject plan")
	}

	requireNoError(t, client.ScriptFlush(t.Context()).Err())
	retried, err := owner.ingest(t.Context(), admitted)
	requireNoError(t, err)

	if retried.Duplicates != 2 {
		t.Fatal("Cluster NOSCRIPT recovery lost idempotency")
	}
}
