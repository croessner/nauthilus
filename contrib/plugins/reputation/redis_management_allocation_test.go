//go:build reputation_integration

package main

import "testing"

func TestReputationRedisManagementAllocationRecoveryKeepsWritersFenced(t *testing.T) {
	_, facade := localReputationRedis(t)
	cfg := shortRetentionConfig(t)
	tagger := manifestTestTagger(t, false)
	owner, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))
	audit := allocationAudit{Reason: "key_rotation", Origin: "operator", AuditID: "rotation-one", Creator: "verified-admin"}
	requireNoError(t, owner.quiesceAudited(t.Context(), &audit))
	if owner.ready.Load() {
		t.Fatal("drained writer remained ready")
	}
	first, err := owner.allocationStatus(t.Context())
	requireNoError(t, err)
	if first.FencedShards != manifestShardCount || first.DrainedAt <= 0 || first.Audit == nil || first.Audit.AuditID != audit.AuditID {
		t.Fatal("drain lacks verified fences and audit")
	}
	cfg.raw.AllocationMaintenance = true
	recovered, err := newStateOwner(cfg, tagger, facade)
	requireNoError(t, err)
	requireNoError(t, recovered.start(t.Context()))
	if recovered.ready.Load() {
		t.Fatal("maintenance startup reopened writers")
	}
	requireNoError(t, recovered.quiesceAudited(t.Context(), &audit))
	second, err := recovered.allocationStatus(t.Context())
	requireNoError(t, err)
	if second.DrainedAt != first.DrainedAt {
		t.Fatal("retry reset the retention clock")
	}
	audit.AuditID = "different-change"
	if recovered.quiesceAudited(t.Context(), &audit) == nil {
		t.Fatal("different operator change replaced in-progress drain audit")
	}
}

func TestReputationRedisManagementAllocationResumesInterruptedFences(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "request", true: "acknowledgment"}[after], func(t *testing.T) {
			_, facade := localReputationRedis(t)
			cfg := shortRetentionConfig(t)
			tagger := manifestTestTagger(t, false)
			owner, err := newStateOwner(cfg, tagger, facade)
			requireNoError(t, err)
			requireNoError(t, owner.start(t.Context()))
			owner.redis = interruptRedis(facade, scriptControl, after, 4)
			audit := allocationAudit{Reason: "key_rotation", Origin: "operator", AuditID: "partial-drain", Creator: "verified-admin"}
			requireError(t, owner.quiesceAudited(t.Context(), &audit))
			cfg.raw.AllocationMaintenance = true
			recovered, err := newStateOwner(cfg, tagger, facade)
			requireNoError(t, err)
			requireNoError(t, recovered.start(t.Context()))
			status, err := recovered.allocationStatus(t.Context())
			requireNoError(t, err)
			if status.DrainedAt != 0 || status.FencedShards == manifestShardCount || recovered.ready.Load() {
				t.Fatal("partial drain was mistaken for completed quiescence")
			}
			requireNoError(t, recovered.quiesceAudited(t.Context(), &audit))
			status, err = recovered.allocationStatus(t.Context())
			requireNoError(t, err)
			if status.DrainedAt <= 0 || status.FencedShards != manifestShardCount {
				t.Fatal("recovery failed to verify all fences")
			}
		})
	}
}

func TestReputationRedisManagementAllocationRejectsMissingFenceSchema(t *testing.T) {
	client, facade := localReputationRedis(t)
	cfg := testConfig(t)
	owner, err := newStateOwner(cfg, manifestTestTagger(t, false), facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))
	requireNoError(t, client.HDel(t.Context(), owner.keys.control(0), "schema").Err())
	if _, err := owner.allocationStatus(t.Context()); err == nil {
		t.Fatal("schema-less fence was accepted as verified state")
	}
}
