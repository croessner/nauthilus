package rediscli

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log"
	"github.com/redis/go-redis/v9"
)

// TestRedisClientsUseUnpublishedCandidate protects standalone workers and off-side runtime construction.
func TestRedisClientsUseUnpublishedCandidate(t *testing.T) {
	var previous config.File

	if config.IsFileLoaded() {
		previous = config.GetFile()
	}

	config.SetTestFile(nil)
	t.Cleanup(func() { config.SetTestFile(previous) })
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	cfg := redisReadOnlyTraceConfig()
	cases := []struct {
		name  string
		build func() redis.UniversalClient
	}{
		{"standalone", func() redis.UniversalClient {
			return newRedisClient(cfg, log.GetLogger(), &cfg.Server.Redis, "127.0.0.1:6379", nil)
		}},
		{"cluster", func() redis.UniversalClient {
			return newRedisClusterClient(cfg, log.GetLogger(), &cfg.Server.Redis, nil)
		}},
		{"replica", func() redis.UniversalClient {
			return newRedisClusterClientReadOnly(cfg, log.GetLogger(), &cfg.Server.Redis, nil)
		}},
		{"sentinel", func() redis.UniversalClient {
			return newRedisFailoverClient(cfg, log.GetLogger(), &cfg.Server.Redis, false, nil)
		}},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			client := test.build()

			t.Cleanup(func() { _ = client.Close() })

			if config.IsFileLoaded() {
				t.Fatal("client construction published ambient configuration")
			}

			if cluster, ok := client.(*redis.ClusterClient); ok && countClusterOnNewNodeCallbacks(cluster) < 2 {
				t.Fatal("candidate Redis tracing was not installed")
			}
		})
	}
}
