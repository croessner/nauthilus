// Copyright (C) 2024 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

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
	for i := range uint(200) {
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
