package core_test

import (
	corepkg "github.com/croessner/nauthilus/server/core"
	_ "github.com/croessner/nauthilus/server/core/auth"

	"testing"
)

func TestWaitDelayMonotonicAndBounded(t *testing.T) {
	svc := corepkg.GetBruteForceService()
	if svc == nil {
		t.Fatal("brute force service not registered")
	}

	maxDelay := uint(100)

	prev := -1
	for i := uint(0); i < 200; i++ {
		val := svc.WaitDelay(maxDelay, i)

		if val < 0 {
			t.Fatalf("wait delay must be non-negative, got %d for attempt %d", val, i)
		}

		if val > int(maxDelay) {
			t.Fatalf("wait delay must be <= max (%d), got %d for attempt %d", maxDelay, val, i)
		}

		if int(i) == 0 && val != 0 {
			t.Fatalf("wait delay at attempt 0 must be 0, got %d", val)
		}

		if prev >= 0 && val < prev {
			t.Fatalf("wait delay must be monotonic: attempt %d -> %d decreased from %d", i, val, prev)
		}

		prev = val
	}

	// Saturation check: large attempts approach max
	v := svc.WaitDelay(maxDelay, 5000)
	if v < int(maxDelay)-1 { // allow off-by-one due to tanh rounding
		t.Fatalf("wait delay should approach max (%d) for large attempts, got %d", maxDelay, v)
	}
}
