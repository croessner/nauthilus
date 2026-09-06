package rediscli

import (
	"context"
	"fmt"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// TestRWPCountsDistinctFailures distinguishes a repeated password from a new candidate.
func TestRWPCountsDistinctFailures(t *testing.T) {
	srv := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: srv.Addr()})
	closeRedisTestClient(t, client)

	ctx := context.Background()

	for i := range 12 {
		hash := fmt.Sprintf("candidate-%02d", i)

		result, err := client.Eval(ctx, LuaScripts["RWPSlidingWindowCheck"], []string{"rwp:test"}, hash, 1000, 900, 3, "legacy-"+hash).Int64()
		if err != nil || result != 0 {
			t.Errorf("new candidate %d precheck=%d err=%v; must count", i, result, err)
		}
	}

	for i := range 12 {
		hash := fmt.Sprintf("candidate-%02d", i)

		result, err := client.Eval(ctx, LuaScripts["RWPSlidingWindowCommit"], []string{"rwp:test"}, hash, 1000+i, 900, 3, "legacy-"+hash).Int64()
		if err != nil || result != 0 {
			t.Errorf("new candidate %d commit=%d err=%v; must count", i, result, err)
		}
	}

	result, err := client.Eval(ctx, LuaScripts["RWPSlidingWindowCommit"], []string{"rwp:test"}, "candidate-11", 1013, 900, 3, "legacy-candidate-11").Int64()
	if err != nil || result != 1 {
		t.Errorf("stored repeat=%d err=%v; want allowance", result, err)
	}
}
