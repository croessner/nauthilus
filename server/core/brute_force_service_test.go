package core

import "testing"

func TestWaitDelayMonotonicAndBounded(t *testing.T) {
	var s DefaultBruteForceService
	max := uint(100)

	prev := -1
	for i := uint(0); i < 200; i++ {
		val := s.WaitDelay(max, i)

		if val < 0 {
			t.Fatalf("wait delay must be non-negative, got %d for attempt %d", val, i)
		}

		if val > int(max) {
			t.Fatalf("wait delay must be <= max (%d), got %d for attempt %d", max, val, i)
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
	v := s.WaitDelay(max, 5000)
	if v < int(max)-1 { // allow off-by-one due to tanh rounding
		t.Fatalf("wait delay should approach max (%d) for large attempts, got %d", max, v)
	}
}
