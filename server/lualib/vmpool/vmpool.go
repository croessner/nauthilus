// Copyright (C) 2025 Christian Rößner
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

// Package vmpool provides per-key (backend/category) pools of reusable Lua VMs.
// The pool is bounded and enforces backpressure via Acquire with context.
// Each VM is reset between uses to avoid cross-request/global residue.
package vmpool

import (
	"context"
	stdhttp "net/http"
	"sync"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib/luapool"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	lua "github.com/yuin/gopher-lua"
)

// PoolKey identifies a VM pool, e.g. "backend:default", "action:default", "hook:clickhouse".
type PoolKey string

// PoolOptions controls the size of a VM pool.
type PoolOptions struct {
	MaxVMs int // maximum number of VMs in the pool
}

// Pool implements a bounded pool of *lua.LState.
type Pool struct {
	key    PoolKey
	opts   PoolOptions
	states chan *lua.LState
	mu     sync.Mutex
	// httpClient is used by luapool.NewLuaState to preload glua_http once per VM.
	httpClient *stdhttp.Client
}

func newPool(key PoolKey, opts PoolOptions) *Pool {
	if opts.MaxVMs <= 0 {
		opts.MaxVMs = 8
	}

	p := &Pool{
		key:    key,
		opts:   opts,
		states: make(chan *lua.LState, opts.MaxVMs),
		// Create a dedicated HTTP client for this pool's VMs.
		httpClient: util.NewHTTPClient(),
	}

	for i := 0; i < opts.MaxVMs; i++ {
		// Create Lua states using the new runtime helper with base/request env markers
		// and stateless preloads. The httpClient enables glua_http preloading.
		p.states <- luapool.NewLuaState(p.httpClient)
	}

	// initialize gauge to 0 in use
	stats.GetMetrics().GetLuaVMInUse().WithLabelValues(string(key)).Set(0)

	return p
}

// Acquire borrows a VM from the pool, respecting the provided context for deadline/cancellation.
func (p *Pool) Acquire(ctx context.Context) (*lua.LState, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case st := <-p.states:
		// update in-use gauge
		inUse := float64(p.opts.MaxVMs - len(p.states))

		stats.GetMetrics().GetLuaVMInUse().WithLabelValues(string(p.key)).Set(inUse)

		return st, nil
	}
}

// Release returns the VM to the pool after a lightweight reset to avoid residue.
func (p *Pool) Release(L *lua.LState) {
	if L == nil {
		return
	}

	resetLuaState(L)

	select {
	case p.states <- L:
	default:
		// Pool unexpectedly full; close the VM to avoid leak
		L.Close()

		level.Warn(log.Logger).Log(definitions.LogKeyMsg, "lua_vm_pool_overflow_close", "key", string(p.key))
	}

	inUse := float64(p.opts.MaxVMs - len(p.states))

	stats.GetMetrics().GetLuaVMInUse().WithLabelValues(string(p.key)).Set(inUse)
}

// Replace discards a broken VM and replaces it with a fresh one.
func (p *Pool) Replace(L *lua.LState) {
	if L != nil {
		L.Close()
	}

	stats.GetMetrics().GetLuaVMReplacedTotal().WithLabelValues(string(p.key)).Inc()
	select {
	case p.states <- luapool.NewLuaState(p.httpClient):
	default:
		// Should not happen; drop
	}

	inUse := float64(p.opts.MaxVMs - len(p.states))

	stats.GetMetrics().GetLuaVMInUse().WithLabelValues(string(p.key)).Set(inUse)
}

// Manager provides global access to per-key pools.
type Manager struct {
	mu    sync.Mutex
	pools map[PoolKey]*Pool
}

var (
	mgr     *Manager
	mgrOnce sync.Once
)

// GetManager returns the singleton Manager.
func GetManager() *Manager {
	mgrOnce.Do(func() {
		mgr = &Manager{pools: make(map[PoolKey]*Pool)}
	})

	return mgr
}

// GetOrCreate returns (and creates if needed) a pool for the given key.
func (m *Manager) GetOrCreate(key PoolKey, opts PoolOptions) *Pool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if p, ok := m.pools[key]; ok {
		return p
	}

	p := newPool(key, opts)
	m.pools[key] = p

	return p
}

// Delegate to the proven deep reset from luapool to avoid cross-request residue.
func resetLuaState(L *lua.LState) {
	luapool.ResetLuaState(L)
}
