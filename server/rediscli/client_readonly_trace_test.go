package rediscli

import (
	"reflect"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log"
)

func TestClusterReadOnlyTracingInstrumentationAndBatchingHook(t *testing.T) {
	cfg := redisReadOnlyTraceConfig()
	config.SetTestFile(cfg)
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	client := newRedisClusterClientReadOnly(cfg, log.GetLogger(), &cfg.GetServer().Redis)

	t.Cleanup(func() { _ = client.Close() })

	if !client.Options().ReadOnly {
		t.Fatal("read-only cluster client must force ReadOnly")
	}

	if got := countClusterOnNewNodeCallbacks(client); got < 2 {
		t.Fatalf("read-only cluster client has %d OnNewNode callbacks, want tracing plus maintenance callbacks", got)
	}

	if got := countRedisClientHooks(client); got < 1 {
		t.Fatalf("read-only cluster client has %d hooks, want batching hook preserved", got)
	}
}

// redisReadOnlyTraceConfig returns a minimal config that enables Redis tracing and batching.
func redisReadOnlyTraceConfig() *config.FileSettings {
	return &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				Cluster: config.Cluster{
					Addresses: []string{"127.0.0.1:6379"},
				},
				Batching: config.RedisBatching{
					Enabled:      true,
					MaxBatchSize: 4,
					MaxWait:      time.Millisecond,
				},
			},
			Insights: config.Insights{
				Tracing: config.Tracing{
					Enabled:     true,
					EnableRedis: true,
				},
			},
		},
	}
}

// countClusterOnNewNodeCallbacks reports how many callbacks are registered for new cluster nodes.
func countClusterOnNewNodeCallbacks(client any) int {
	value := reflect.ValueOf(client).Elem()
	nodes := value.FieldByName("nodes")

	if nodes.IsNil() {
		return 0
	}

	return nodes.Elem().FieldByName("onNewNode").Len()
}

// countRedisClientHooks reports how many hooks are registered directly on a go-redis client.
func countRedisClientHooks(client any) int {
	value := reflect.ValueOf(client).Elem()
	hooksMixin := value.FieldByName("hooksMixin")

	return hooksMixin.FieldByName("slice").Len()
}
