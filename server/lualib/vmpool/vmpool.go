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
	"sync/atomic"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib/luapool"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/svcctx"
	"github.com/croessner/nauthilus/server/util"

	lua "github.com/yuin/gopher-lua"
	"go.opentelemetry.io/otel/attribute"
)

// PoolKey identifies a VM pool, e.g. "backend:default", "action:default", "hook:clickhouse".
type PoolKey string

// PoolOptions controls the size of a VM pool.
type PoolOptions struct {
	MaxVMs int // maximum number of VMs in the pool
	Config config.File
}

// Pool implements a bounded pool of *lua.LState.
type Pool struct {
	key    PoolKey
	opts   PoolOptions
	states chan *lua.LState
	mu     sync.Mutex
	// httpClient is used by luapool.NewLuaState to preload glua_http once per VM.
	httpClient *stdhttp.Client
	// inUse tracks the number of VMs currently checked out from the pool.
	inUse int64
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
		httpClient: util.NewHTTPClientWithCfg(opts.Config),
	}

	for i := 0; i < opts.MaxVMs; i++ {
		// Create Lua states using the new runtime helper with base/request env markers
		// and stateless preloads. The httpClient enables glua_http preloading.
		p.states <- luapool.NewLuaState(p.httpClient, opts.Config)
	}

	// Initialize gauge to 0 in-use
	stats.GetMetrics().GetLuaVMInUse().WithLabelValues(string(key)).Set(0)

	return p
}

// Acquire borrows a VM from the pool, respecting the provided context for deadline/cancellation.
func (p *Pool) Acquire(ctx context.Context) (*lua.LState, error) {
	// Trace acquisition attempt
	tr := monittrace.New("nauthilus/vmpool")
	actx, asp := tr.Start(ctx, "vmpool.acquire",
		attribute.String("key", string(p.key)),
		attribute.Int("capacity", p.opts.MaxVMs),
		attribute.Int64("in_use_before", atomic.LoadInt64(&p.inUse)),
	)

	_ = actx

	defer asp.End()

	select {
	case <-ctx.Done():
		asp.RecordError(ctx.Err())

		return nil, ctx.Err()
	case st := <-p.states:
		// Increment in-use counter and update gauge. Using an explicit counter avoids
		// race-y observations based on len(chan) under heavy concurrency.
		n := atomic.AddInt64(&p.inUse, 1)

		stats.GetMetrics().GetLuaVMInUse().WithLabelValues(string(p.key)).Set(float64(n))
		asp.SetAttributes(attribute.Int64("in_use_after", n))

		return st, nil
	}
}

// Release returns the VM to the pool after a lightweight reset to avoid residue.
func (p *Pool) Release(L *lua.LState) {
	// Service-scoped tracing for releases
	tr := monittrace.New("nauthilus/vmpool")
	rctx, rsp := tr.Start(svcctx.Get(), "vmpool.release",
		attribute.String("key", string(p.key)),
		attribute.Int("capacity", p.opts.MaxVMs),
		attribute.Int64("in_use_before", atomic.LoadInt64(&p.inUse)),
	)

	_ = rctx

	defer rsp.End()

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
		rsp.SetAttributes(attribute.Bool("overflow_close", true))
	}

	// Decrement in-use counter and update gauge
	n := atomic.AddInt64(&p.inUse, -1)
	if n < 0 {
		// Should not happen; self-heal to zero
		atomic.StoreInt64(&p.inUse, 0)
		n = 0
	}

	stats.GetMetrics().GetLuaVMInUse().WithLabelValues(string(p.key)).Set(float64(n))
	rsp.SetAttributes(attribute.Int64("in_use_after", n))
}

// Replace discards a broken VM and replaces it with a fresh one.
func (p *Pool) Replace(L *lua.LState) {
	// Service-scoped tracing for replacements
	tr := monittrace.New("nauthilus/vmpool")
	xctx, xsp := tr.Start(svcctx.Get(), "vmpool.replace",
		attribute.String("key", string(p.key)),
		attribute.Int("capacity", p.opts.MaxVMs),
		attribute.Int64("in_use_before", atomic.LoadInt64(&p.inUse)),
	)

	_ = xctx

	defer func() {
		xsp.End()
	}()

	if L != nil {
		L.Close()
	}

	stats.GetMetrics().GetLuaVMReplacedTotal().WithLabelValues(string(p.key)).Inc()
	select {
	case p.states <- luapool.NewLuaState(p.httpClient, p.opts.Config):
	default:
		// Should not happen; drop
	}

	// A replaced VM ends the in-use phase just like Release
	n := atomic.AddInt64(&p.inUse, -1)
	if n < 0 {
		atomic.StoreInt64(&p.inUse, 0)
		n = 0
	}

	stats.GetMetrics().GetLuaVMInUse().WithLabelValues(string(p.key)).Set(float64(n))
	xsp.SetAttributes(attribute.Int64("in_use_after", n))
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
