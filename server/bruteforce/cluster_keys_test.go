package bruteforce

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
)

func extractHashTag(t *testing.T, key string) string {
	t.Helper()

	start := strings.IndexByte(key, '{')
	end := strings.IndexByte(key, '}')
	if start == -1 || end == -1 || end <= start+1 {
		t.Fatalf("key has no valid hash-tag: %q", key)
	}

	return key[start+1 : end]
}

func TestRedisClusterHashTags(t *testing.T) {
	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())
	config.SetTestFile(&config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{Prefix: "nt_"},
		},
		BruteForce: &config.BruteForceSection{
			Buckets: []config.BruteForceRule{
				{
					Name:           "r1",
					Period:         time.Minute,
					CIDR:           24,
					IPv4:           true,
					FailedRequests: 5,
				},
				{
					Name:           "r2",
					Period:         2 * time.Minute,
					CIDR:           16,
					IPv4:           true,
					FailedRequests: 10,
				},
			},
		},
	})

	bm := NewBucketManagerWithDeps(context.Background(), "test", "10.0.1.2", BucketManagerDeps{
		Cfg: config.GetFile(),
	}).
		WithAccountName("acc").
		WithUsername("user").
		WithProtocol("imap").
		WithOIDCCID("cid123")
	impl, ok := bm.(*bucketManagerImpl)
	if !ok {
		t.Fatalf("unexpected bucket manager implementation: %T", bm)
	}

	// Bucket counters are MGETed together; all keys must share the same hash slot in Redis Cluster.
	rules := config.GetFile().GetBruteForceRules()
	k1 := impl.GetBruteForceBucketRedisKey(&rules[0])
	k2 := impl.GetBruteForceBucketRedisKey(&rules[1])

	// Bucket keys must use a bucket-specific hash tag (network scope) so that the keys can be
	// distributed across the cluster. Reads are performed via pipelined GETs.
	if extractHashTag(t, k1) != "10.0.1.0/24" {
		t.Fatalf("unexpected bucket hash-tag for r1: %q", k1)
	}
	if extractHashTag(t, k2) != "10.0.0.0/16" {
		t.Fatalf("unexpected bucket hash-tag for r2: %q", k2)
	}

	// PW_HIST Lua gate is executed with keys; they must share the same hash slot.
	h := impl.getPasswordHistoryRedisSetKey(true)
	total := impl.getPasswordHistoryTotalRedisKey(true)

	if extractHashTag(t, h) != extractHashTag(t, total) {
		t.Fatalf("PW_HIST keys must share hash-tag: %q vs %q", h, total)
	}
}
