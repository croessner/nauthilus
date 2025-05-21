package luapool

import (
	"sync"
	"sync/atomic"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/util"
	lua "github.com/yuin/gopher-lua"
)

// FixedLuaStatePool is a pool of pre-created Lua states.
// Unlike the standard sync.Pool-based implementation, this pool:
// - Pre-creates a fixed number of Lua states
// - Does not require states to be returned after use
// - Automatically replenishes the pool when it gets low
type FixedLuaStatePool struct {
	states      chan *lua.LState // Channel of available Lua states
	size        int              // Maximum size of the pool
	minAvail    int              // Minimum number of states that should be available
	created     int64            // Total number of states created (for metrics)
	mu          sync.Mutex       // Mutex for thread-safe operations
	replenisher *sync.Once       // Used to ensure only one replenishment happens at a time
}

// NewFixedLuaStatePool creates a new fixed-size pool of Lua states.
// size: Maximum number of states in the pool
// minAvail: Minimum number of states that should be available before replenishment
func NewFixedLuaStatePool(size, minAvail int) *FixedLuaStatePool {
	if size <= 0 {
		size = 100 // Default size
	}

	if minAvail <= 0 || minAvail > size {
		minAvail = size / 5 // Default to 20% of size
	}

	pool := &FixedLuaStatePool{
		states:      make(chan *lua.LState, size),
		size:        size,
		minAvail:    minAvail,
		replenisher: &sync.Once{},
	}

	// Pre-create states
	pool.replenishPool(size)

	return pool
}

// GetState returns a Lua state from the pool.
// If the pool is running low, it will trigger replenishment.
func (p *FixedLuaStatePool) GetState() *lua.LState {
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
		util.DebugModule(
			definitions.DbgLua,
			definitions.LogKeyMsg, "Creating new Lua state (pool exhausted)",
		)
		atomic.AddInt64(&p.created, 1)

		return lua.NewState()
	}
}

// triggerReplenishment starts the pool replenishment process in a separate goroutine.
func (p *FixedLuaStatePool) triggerReplenishment() {
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
				util.DebugModule(
					definitions.DbgLua,
					definitions.LogKeyMsg, "Replenishing Lua state pool",
					"adding", toAdd,
				)
				p.replenishPool(toAdd)
			}
		})
	}()
}

// replenishPool adds the specified number of new Lua states to the pool.
func (p *FixedLuaStatePool) replenishPool(count int) {
	for i := 0; i < count; i++ {
		select {
		case p.states <- lua.NewState():
			atomic.AddInt64(&p.created, 1)
		default:
			// Pool is full, stop adding
			return
		}
	}
}

// Size returns the current number of available states in the pool.
func (p *FixedLuaStatePool) Size() int {
	return len(p.states)
}

// TotalCreated returns the total number of Lua states created by this pool.
func (p *FixedLuaStatePool) TotalCreated() int64 {
	return atomic.LoadInt64(&p.created)
}

// DefaultFixedPool is the default fixed-size Lua state pool.
var DefaultFixedPool = NewFixedLuaStatePool(100, 20)

// GetFixed returns a Lua state from the default fixed-size pool.
func GetFixed() *lua.LState {
	return DefaultFixedPool.GetState()
}
