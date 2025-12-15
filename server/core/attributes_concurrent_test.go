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

package core

import (
	"runtime"
	"sync"
	"testing"

	"github.com/croessner/nauthilus/server/backend/bktype"
)

// TestAuthState_Attributes_Concurrent exercises concurrent deletes and conditional sets
// on AuthState.Attributes to ensure we do not hit fatal "concurrent map writes" panics.
// Run with: go test -race -run TestAuthState_Attributes_Concurrent ./server/core -v
func TestAuthState_Attributes_Concurrent(t *testing.T) {
	t.Parallel()

	a := &AuthState{}

	// Pre-populate Attributes with a few keys
	a.attributesMu.Lock()
	a.Attributes = make(bktype.AttributeMapping)

	for i := 0; i < 16; i++ {
		key := testKeyName(i)
		a.Attributes[key] = []any{i}
	}

	a.attributesMu.Unlock()

	workers := 64
	iters := 500

	if testing.Short() {
		workers = 32
		iters = 200
	}

	// Increase parallelism to make races more likely
	runtime.GOMAXPROCS(runtime.NumCPU())

	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		w := w

		go func() {
			defer wg.Done()

			for i := 0; i < iters; i++ {
				key := testKeyName((w + i) % 32)

				if w%2 == 0 {
					a.DeleteAttribute(key)
				} else {
					a.SetAttributeIfAbsent(key, i)
				}
			}
		}()
	}

	wg.Wait()

	// Basic sanity: verify map invariants under read lock
	a.attributesMu.RLock()
	for k, v := range a.Attributes {
		if k == "" {
			t.Fatalf("empty key found")
		}

		if v == nil {
			t.Fatalf("nil value slice for key %q", k)
		}
	}

	a.attributesMu.RUnlock()
}

func testKeyName(i int) string {
	return "k" + string(rune('a'+(i%26)))
}
