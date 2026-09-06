package core

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/redis/go-redis/v9"
)

// TestMFAAttemptBudgetIsAtomicAndExpires preserves a fixed account budget across concurrent verifications.
func TestMFAAttemptBudgetIsAtomicAndExpires(t *testing.T) {
	srv := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: srv.Addr()})

	t.Cleanup(func() { _ = client.Close() })
	deps := AuthDeps{Cfg: hardCutBruteForceConfig(t), Redis: rediscli.NewTestClient(client)}

	var (
		allowed atomic.Int32
		wg      sync.WaitGroup
	)
	for range 32 {
		wg.Go(func() {
			err := ConsumeMFAAttempt(context.Background(), deps, "stable-identity")
			if err == nil {
				allowed.Add(1)
			} else if !errors.Is(err, ErrMFAAttemptLimit) {
				t.Error(err)
			}
		})
	}

	wg.Wait()

	if allowed.Load() != mfaAttemptLimit {
		t.Fatalf("admitted %d, want %d", allowed.Load(), mfaAttemptLimit)
	}

	if err := ConsumeMFAAttempt(context.Background(), deps, "another-identity"); err != nil {
		t.Fatal(err)
	}

	srv.FastForward(mfaAttemptWindow)

	if err := ConsumeMFAAttempt(context.Background(), deps, "stable-identity"); err != nil {
		t.Fatal(err)
	}

	if err := ConsumeMFAAttempt(context.Background(), AuthDeps{}, "stable-identity"); err == nil {
		t.Fatal("missing storage admitted verification")
	}
}
