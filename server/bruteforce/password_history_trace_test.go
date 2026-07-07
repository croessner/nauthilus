package bruteforce

import (
	"context"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/croessner/nauthilus/v3/server/testing/tracetest"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/trace"
)

func TestLoadAllPasswordHistoriesPropagatesTraceContextToRedisReads(t *testing.T) {
	collector := tracetest.Setup(t)
	cfg := passwordHistoryTraceConfig()
	config.SetTestFile(cfg)
	util.SetDefaultConfigFile(cfg)
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	readHandle := &passwordHistoryTraceReadHandle{}
	redisClient := &passwordHistoryTestRedisClient{readHandle: readHandle}

	bm := NewBucketManagerWithDeps(context.Background(), "trace-guid", "1.2.3.4", BucketManagerDeps{
		Cfg:   cfg,
		Redis: redisClient,
	}).
		WithAccountName("account").
		WithUsername("account").
		WithPassword(secret.New("password"))

	bm.LoadAllPasswordHistories()

	assertRedisReadsUsePasswordHistorySpanContext(t, collector, readHandle)
}

func TestLoadAllPasswordHistoriesRestoresPreviousContext(t *testing.T) {
	tracetest.Setup(t)

	cfg := passwordHistoryTraceConfig()
	config.SetTestFile(cfg)
	util.SetDefaultConfigFile(cfg)

	readHandle := &passwordHistoryTraceReadHandle{}
	redisClient := &passwordHistoryTestRedisClient{readHandle: readHandle}
	baseCtx := context.WithValue(context.Background(), passwordHistoryTraceContextKey{}, "original")

	bm := NewBucketManagerWithDeps(baseCtx, "trace-guid", "1.2.3.4", BucketManagerDeps{
		Cfg:   cfg,
		Redis: redisClient,
	}).
		WithAccountName("account").
		WithUsername("account")

	impl, ok := bm.(*bucketManagerImpl)
	if !ok {
		t.Fatalf("unexpected bucket manager implementation: %T", bm)
	}

	bm.LoadAllPasswordHistories()

	if impl.ctx != baseCtx {
		t.Fatal("bucket manager context was not restored after loading password histories")
	}
}

func TestLoadAllPasswordHistoriesSkipsWhenBruteForceControlDisabled(t *testing.T) {
	cfg := passwordHistoryTraceConfigWithoutBruteForce()
	config.SetTestFile(cfg)
	util.SetDefaultConfigFile(cfg)

	readHandle := &passwordHistoryTraceReadHandle{}
	redisClient := &passwordHistoryTestRedisClient{readHandle: readHandle}

	bm := NewBucketManagerWithDeps(context.Background(), "trace-guid", "1.2.3.4", BucketManagerDeps{
		Cfg:   cfg,
		Redis: redisClient,
	}).
		WithAccountName("account").
		WithUsername("account").
		WithPassword(secret.New("password"))

	bm.LoadAllPasswordHistories()

	if len(readHandle.spanContexts) != 0 {
		t.Fatalf("disabled brute-force control recorded %d Redis read contexts", len(readHandle.spanContexts))
	}
}

// passwordHistoryTraceConfig returns the minimal config needed by password-history Redis reads.
func passwordHistoryTraceConfig() config.File {
	runtimeModule := config.RuntimeModule{}
	if err := runtimeModule.Set(definitions.ControlBruteForce); err != nil {
		panic(err)
	}

	return &config.FileSettings{
		Server: &config.ServerSection{
			RuntimeModules: []*config.RuntimeModule{&runtimeModule},
			Redis: config.Redis{
				Prefix:        "nt_",
				PasswordNonce: secret.New("0123456789abcdef"),
			},
			Insights: config.Insights{
				Tracing: config.Tracing{
					Enabled:     true,
					EnableRedis: true,
				},
			},
		},
		BruteForce: &config.BruteForceSection{
			Buckets: []config.BruteForceRule{
				{
					Name:           "tracebucket",
					Period:         time.Minute,
					CIDR:           32,
					IPv4:           true,
					FailedRequests: 5,
				},
			},
		},
	}
}

// passwordHistoryTraceConfigWithoutBruteForce returns a config with no brute-force runtime module.
func passwordHistoryTraceConfigWithoutBruteForce() config.File {
	cfg := passwordHistoryTraceConfig().(*config.FileSettings)
	cfg.Server.RuntimeModules = nil

	return cfg
}

// assertRedisReadsUsePasswordHistorySpanContext verifies Redis reads inherit the active password-history span.
func assertRedisReadsUsePasswordHistorySpanContext(t *testing.T, collector *tracetest.Collector, readHandle *passwordHistoryTraceReadHandle) {
	t.Helper()

	spans := collector.Spans()

	passwordSpan, found := tracetest.FindByNameAndAttributes(spans, "bruteforce.load_all_password_histories")
	if !found {
		t.Fatalf("password-history span not exported: %#v", spans)
	}

	if len(readHandle.spanContexts) == 0 {
		t.Fatal("no Redis read contexts were recorded")
	}

	for _, spanCtx := range readHandle.spanContexts {
		if !spanCtx.IsValid() {
			t.Fatalf("Redis read context has no valid active span: %#v", readHandle.spanContexts)
		}

		if spanCtx.SpanID() != passwordSpan.SpanContext().SpanID() {
			t.Fatalf("Redis read context span = %s, want password-history span %s", spanCtx.SpanID(), passwordSpan.SpanContext().SpanID())
		}
	}
}

type passwordHistoryTraceContextKey struct{}

type passwordHistoryTraceReadHandle struct {
	redis.UniversalClient

	spanContexts []trace.SpanContext
}

// SCard records the command context and returns an empty set count.
func (h *passwordHistoryTraceReadHandle) SCard(ctx context.Context, _ string) *redis.IntCmd {
	h.record(ctx)

	return redis.NewIntResult(0, nil)
}

// Get records the command context and returns a Redis nil miss.
func (h *passwordHistoryTraceReadHandle) Get(ctx context.Context, _ string) *redis.StringCmd {
	h.record(ctx)

	return redis.NewStringResult("", redis.Nil)
}

// SIsMember records the command context and returns a non-member result.
func (h *passwordHistoryTraceReadHandle) SIsMember(ctx context.Context, _ string, _ any) *redis.BoolCmd {
	h.record(ctx)

	return redis.NewBoolResult(false, nil)
}

// record stores the active span context seen by a Redis read command.
func (h *passwordHistoryTraceReadHandle) record(ctx context.Context) {
	h.spanContexts = append(h.spanContexts, trace.SpanContextFromContext(ctx))
}
