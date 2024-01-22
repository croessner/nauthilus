package lualib

import (
	"sync"

	"github.com/tengattack/gluacrypto"
	libs "github.com/vadv/gopher-lua-libs"
	lua "github.com/yuin/gopher-lua"
)

// LStateProvider is a function type that returns a pointer to a lua.LState.
// It represents a provider function that can be used to create new lua.LState instances.
type LStateProvider func() *lua.LState

// LuaBaseStatePool is an interface for managing a pool of Lua state instances.
// If there are no available states in the pool, a new state is created.
type LuaBaseStatePool interface {
	// Get retrieves a Lua state from the pool.
	Get() *lua.LState

	// Put returns a Lua state to the pool.
	Put(L *lua.LState)

	// Shutdown closes all the Lua states in the pool.
	Shutdown()
}

// LuaStatePool is a type for managing a pool of Lua state instances.
// The pool uses a sync.Mutex to ensure safe concurrent access.
// The saved field is a slice of *lua.LState, which holds the available Lua states in the pool.
// The New field is an LStateProvider function, which is used to create new Lua states when the pool is empty.
type LuaStatePool struct {
	mu    sync.Mutex
	saved []*lua.LState
	New   LStateProvider
}

// NewLuaStatePool initializes a new Lua state pool.
// It creates a new instance of LuaStatePool with the New function set to NewLStateWithDefaultLibraries.
// It then calls InitializeStatePool to initialize the pool and return the initialized pool.
// Usage:
// luaPool := NewLuaStatePool()
func NewLuaStatePool() LuaBaseStatePool {
	lp := &LuaStatePool{New: NewLStateWithDefaultLibraries}

	return lp.InitializeStatePool()
}

// NewLStateWithDefaultLibraries initializes a new Lua state with default libraries.
// It creates a new instance of *lua.LState using lua.NewState().
// It then loads the libraries using libs.Preload() and gluacrypto.Preload().
// Finally, it returns the initialized Lua state.
// Usage:
// L := NewLStateWithDefaultLibraries()
// Note: The returned Lua state is not thread-safe.
// It is recommended to use a state pool for managing Lua states in a concurrent environment.
func NewLStateWithDefaultLibraries() *lua.LState {
	L := lua.NewState()

	libs.Preload(L)
	gluacrypto.Preload(L)

	return L
}

// Get returns a Lua state from the pool.
// It locks the mutex of the LuaStatePool to ensure thread safety.
// If there are no saved Lua states in the pool, it calls the New function of the LuaStatePool to create a new Lua state.
// Otherwise, it retrieves the last saved Lua state from the pool and removes it from the slice.
// Finally, it returns the retrieved Lua state.
func (pl *LuaStatePool) Get() *lua.LState {
	pl.mu.Lock()

	defer pl.mu.Unlock()

	n := len(pl.saved)
	if n == 0 {
		return pl.New()
	}

	x := pl.saved[n-1]
	pl.saved = pl.saved[0 : n-1]

	return x
}

// Put adds a new Lua state to the pool.
// It is thread-safe and uses mutex locking to ensure that
// the shared 'saved' slice is not accessed concurrently.
//
// Parameters:
//
//	L: The *lua.LState instance to be added to the pool.
//
// Returns:
//
//	None
func (pl *LuaStatePool) Put(L *lua.LState) {
	pl.mu.Lock()

	defer pl.mu.Unlock()

	pl.saved = append(pl.saved, L)
}

// InitializeStatePool initializes the state pool.
// If the pool is nil, it returns nil.
// It creates a new slice with a capacity of 4 for storing Lua states.
// It updates the saved field of the pool with the new slice.
// Finally, it returns the pool.
func (pl *LuaStatePool) InitializeStatePool() *LuaStatePool {
	if pl == nil {
		return nil
	}

	pl.saved = make([]*lua.LState, 0, 4)

	return pl
}

// Shutdown closes all the saved Lua states in the pool.
// It iterates over each saved Lua state in the slice and calls its Close method to close it.
func (pl *LuaStatePool) Shutdown() {
	for _, L := range pl.saved {
		L.Close()
	}
}
