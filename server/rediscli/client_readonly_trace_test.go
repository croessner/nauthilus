package rediscli

import (
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log"
)

func TestClusterReadOnlyTracingInstrumentationAndBatchingHook(t *testing.T) {
	cfg := redisReadOnlyTraceConfig()
	config.SetTestFile(cfg)
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	client := newRedisClusterClientReadOnly(cfg, log.GetLogger(), &cfg.GetServer().Redis, nil)

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
	if hooks := hooksMixin.FieldByName("slice"); hooks.IsValid() {
		return hooks.Len()
	}

	state := hooksMixin.FieldByName("state")
	if !state.IsValid() || state.IsNil() || !state.CanAddr() {
		return 0
	}

	readableState := reflect.NewAt(state.Type(), unsafe.Pointer(state.UnsafeAddr())).Elem()
	load := readableState.MethodByName("Load")

	if !load.IsValid() {
		return 0
	}

	result := load.Call(nil)
	if len(result) != 1 || result[0].IsNil() {
		return 0
	}

	hooks := result[0].Elem().FieldByName("slice")
	if !hooks.IsValid() {
		return 0
	}

	return hooks.Len()
}
