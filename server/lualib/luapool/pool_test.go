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

package luapool

import (
	"sync"
	"sync/atomic"
	"testing"

	lua "github.com/yuin/gopher-lua"
)

// testPool is a simplified version of luaStatePool for testing
var testPool = sync.Pool{
	New: func() any {
		return lua.NewState()
	},
}

// GetForTest returns a Lua state from the test pool
func GetForTest() *lua.LState {
	return testPool.Get().(*lua.LState)
}

// PutForTest resets the Lua state and returns it to the test pool
func PutForTest(L *lua.LState) {
	if L == nil {
		return
	}

	// Simplified reset for testing
	L.SetTop(0)

	testPool.Put(L)
}

// TestFixedLuaStatePool is a simplified version of FixedLuaStatePool for testing
type TestFixedLuaStatePool struct {
	states      chan *lua.LState // Channel of available Lua states
	size        int              // Maximum size of the pool
	minAvail    int              // Minimum number of states that should be available
	created     int64            // Total number of states created (for metrics)
	mu          sync.Mutex       // Mutex for thread-safe operations
	replenisher *sync.Once       // Used to ensure only one replenishment happens at a time
}

// NewTestFixedLuaStatePool creates a new fixed-size pool of Lua states for testing
func NewTestFixedLuaStatePool(size, minAvail int) *TestFixedLuaStatePool {
	if size <= 0 {
		size = 100 // Default size
	}

	if minAvail <= 0 || minAvail > size {
		minAvail = size / 5 // Default to 20% of size
	}

	pool := &TestFixedLuaStatePool{
		states:      make(chan *lua.LState, size),
		size:        size,
		minAvail:    minAvail,
		replenisher: &sync.Once{},
	}

	// Pre-create states
	pool.replenishPool(size)

	return pool
}

// GetState returns a Lua state from the pool
func (p *TestFixedLuaStatePool) GetState() *lua.LState {
	// Get a state from the channel
	select {
	case state := <-p.states:
		// Check if we need to replenish the pool
		if len(p.states) < p.minAvail {
			p.triggerReplenishment()
		}
		return state
	default:
		// If no states are available, create a new one
		atomic.AddInt64(&p.created, 1)
		return lua.NewState()
	}
}

// triggerReplenishment starts the pool replenishment process in a separate goroutine
func (p *TestFixedLuaStatePool) triggerReplenishment() {
	// Use sync.Once to ensure only one replenishment happens at a time
	once := p.replenisher
	go func() {
		once.Do(func() {
			p.mu.Lock()
			// Create a new sync.Once for next time
			p.replenisher = &sync.Once{}
			p.mu.Unlock()

			// Calculate how many states to add
			toAdd := p.size - len(p.states)
			if toAdd > 0 {
				p.replenishPool(toAdd)
			}
		})
	}()
}

// replenishPool adds the specified number of new Lua states to the pool
func (p *TestFixedLuaStatePool) replenishPool(count int) {
	for range count {
		select {
		case p.states <- lua.NewState():
			atomic.AddInt64(&p.created, 1)
		default:
			// Pool is full, stop adding
			return
		}
	}
}

// BenchmarkSyncPool benchmarks the performance of the sync.Pool-based implementation.
func BenchmarkSyncPool(b *testing.B) {
	b.ReportAllocs()

	// Reset the timer to exclude setup time
	b.ResetTimer()

	// Run the benchmark
	for i := 0; i < b.N; i++ {
		// Get a Lua state from the pool
		L := GetForTest()

		// Do some minimal work with the state
		L.SetTop(0)

		// Return the state to the pool
		PutForTest(L)
	}
}

// BenchmarkFixedPool benchmarks the performance of the fixed-size pool implementation.
func BenchmarkFixedPool(b *testing.B) {
	// Create a smaller pool for benchmarking
	pool := NewTestFixedLuaStatePool(50, 10)

	b.ReportAllocs()

	// Reset the timer to exclude setup time
	b.ResetTimer()

	// Run the benchmark
	for i := 0; i < b.N; i++ {
		// Get a Lua state from the pool
		L := pool.GetState()

		// Do some minimal work with the state
		L.SetTop(0)

		// Note: We don't return the state to the pool in this implementation
	}
}

// BenchmarkSyncPoolParallel benchmarks the sync.Pool implementation with concurrent access.
func BenchmarkSyncPoolParallel(b *testing.B) {
	b.ReportAllocs()

	// Reset the timer to exclude setup time
	b.ResetTimer()

	// Run the benchmark with multiple goroutines
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Get a Lua state from the pool
			L := GetForTest()

			// Do some minimal work with the state
			L.SetTop(0)

			// Return the state to the pool
			PutForTest(L)
		}
	})
}

// BenchmarkFixedPoolParallel benchmarks the fixed-size pool implementation with concurrent access.
func BenchmarkFixedPoolParallel(b *testing.B) {
	// Create a pool for benchmarking
	pool := NewTestFixedLuaStatePool(100, 20)

	b.ReportAllocs()

	// Reset the timer to exclude setup time
	b.ResetTimer()

	// Run the benchmark with multiple goroutines
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Get a Lua state from the pool
			L := pool.GetState()

			// Do some minimal work with the state
			L.SetTop(0)

			// Note: We don't return the state to the pool in this implementation
		}
	})
}

// BenchmarkRealWorldScenario simulates a more realistic usage pattern
// where Lua states are used for a longer period and with more operations.
func BenchmarkRealWorldScenario(b *testing.B) {
	b.Run("SyncPool", func(b *testing.B) {
		b.ReportAllocs()

		var wg sync.WaitGroup

		// Simulate 10 concurrent requests
		for range 10 {
			wg.Go(func() {
				for j := 0; j < b.N/10; j++ {
					// Get a Lua state from the pool
					L := GetForTest()

					// Simulate more realistic work
					L.SetTop(0)
					table := L.NewTable()
					table.RawSetString("name", lua.LString("test"))
					table.RawSetString("value", lua.LNumber(42))
					table.RawSetString("enabled", lua.LBool(true))
					L.Push(table)

					// Return the state to the pool
					PutForTest(L)
				}
			})
		}

		wg.Wait()
	})

	b.Run("FixedPool", func(b *testing.B) {
		b.ReportAllocs()

		pool := NewTestFixedLuaStatePool(100, 20)
		var wg sync.WaitGroup

		// Simulate 10 concurrent requests
		for range 10 {
			wg.Go(func() {
				for j := 0; j < b.N/10; j++ {
					// Get a Lua state from the pool
					L := pool.GetState()

					// Simulate more realistic work
					L.SetTop(0)
					table := L.NewTable()
					table.RawSetString("name", lua.LString("test"))
					table.RawSetString("value", lua.LNumber(42))
					table.RawSetString("enabled", lua.LBool(true))
					L.Push(table)

					// Note: We don't return the state to the pool in this implementation
				}
			})
		}

		wg.Wait()
	})
}
