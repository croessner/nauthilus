package bruteforce

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/log"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/redis/go-redis/v9"
)

// TestFractionalBucketPeriodsRetainBothWindows preserves current and previous window storage at Redis precision.
func TestFractionalBucketPeriodsRetainBothWindows(t *testing.T) {
	for _, tc := range []struct{ period, retention time.Duration }{
		{100 * time.Millisecond, 2 * time.Second},
		{1600 * time.Millisecond, 4 * time.Second},
		{2 * time.Second, 4 * time.Second},
	} {
		t.Run(tc.period.String(), func(t *testing.T) {
			storage := miniredis.RunT(t)
			client := redis.NewClient(&redis.Options{Addr: storage.Addr()})

			t.Cleanup(func() { _ = client.Close() })

			cfg := passwordHistoryCommandConfig(0)
			rule := config.BruteForceRule{Name: "fractional", CIDR: 32, IPv4: true, Period: tc.period, FailedRequests: 5}
			manager := NewBucketManagerWithDeps(t.Context(), "test", "192.0.2.1", BucketManagerDeps{
				Cfg: cfg, Logger: log.GetLogger(), Redis: rediscli.NewTestClient(client),
			})

			rediscli.ClearScriptCache()
			manager.SaveBruteForceBucketCounterToRedis(&rule)

			keys := storage.Keys()
			if len(keys) != 1 {
				t.Fatalf("counter keys %d, want one retained window", len(keys))
			}

			if got := storage.TTL(keys[0]); got != tc.retention {
				t.Fatalf("counter retention %s, want %s", got, tc.retention)
			}
		})
	}
}
