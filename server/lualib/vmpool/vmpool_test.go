// Copyright (C) 2026 Christian Rößner
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

package vmpool

import (
	"context"
	"strings"
	"testing"

	lua "github.com/yuin/gopher-lua"
)

func TestLeaseReleaseRecoveringOnErrorDropsPoisonedRequireState(t *testing.T) {
	pool := newTestPool(t)

	lease, err := pool.AcquireLease(context.Background())
	if err != nil {
		t.Fatalf("AcquireLease() error = %v", err)
	}

	poisoned := lease.State()

	luaErr := poisoned.DoString(`
		package.preload.nauthilus_util = function()
			error("simulated loader failure")
		end

		require("nauthilus_util")
	`)
	if luaErr == nil {
		t.Fatal("expected loader failure to poison Lua state")
	}

	assertRequireSentinelPresent(t, poisoned)

	lease.ReleaseRecoveringOnError(&luaErr)

	nextLease, err := pool.AcquireLease(context.Background())
	if err != nil {
		t.Fatalf("AcquireLease() after replace error = %v", err)
	}
	defer nextLease.Release()

	if nextLease.State() == poisoned {
		t.Fatal("expected poisoned Lua state to be replaced")
	}

	assertNoRequireSentinel(t, nextLease.State())
}

func TestLeaseReleaseRecoveringOnErrorDropsRequireStateAfterContextCancel(t *testing.T) {
	pool := newTestPool(t)

	lease, err := pool.AcquireLease(context.Background())
	if err != nil {
		t.Fatalf("AcquireLease() error = %v", err)
	}

	poisoned := lease.State()
	luaCtx, cancel := context.WithCancel(context.Background())
	poisoned.SetContext(luaCtx)
	poisoned.SetGlobal("cancel_lua_context", poisoned.NewFunction(func(_ *lua.LState) int {
		cancel()

		return 0
	}))

	luaErr := poisoned.DoString(`
		package.preload.nauthilus_util = function()
			cancel_lua_context()

			local value = 0
			while true do
				value = value + 1
			end
		end

		require("nauthilus_util")
	`)
	if luaErr == nil {
		t.Fatal("expected context cancellation while loading nauthilus_util")
	}

	if !strings.Contains(luaErr.Error(), context.Canceled.Error()) {
		t.Fatalf("expected context canceled error, got %v", luaErr)
	}

	poisoned.SetContext(context.Background())
	assertRequireSentinelPresent(t, poisoned)

	lease.ReleaseRecoveringOnError(&luaErr)

	nextLease, err := pool.AcquireLease(context.Background())
	if err != nil {
		t.Fatalf("AcquireLease() after replace error = %v", err)
	}
	defer nextLease.Release()

	if nextLease.State() == poisoned {
		t.Fatal("expected context-canceled Lua state to be replaced")
	}

	assertNoRequireSentinel(t, nextLease.State())
}

func TestLeaseReleaseRecoveringReplacesAfterPanic(t *testing.T) {
	pool := newTestPool(t)

	lease, err := pool.AcquireLease(context.Background())
	if err != nil {
		t.Fatalf("AcquireLease() error = %v", err)
	}

	poisoned := lease.State()

	func() {
		defer lease.ReleaseRecoveringOnError(nil)

		panic("simulated Lua VM panic")
	}()

	nextLease, err := pool.AcquireLease(context.Background())
	if err != nil {
		t.Fatalf("AcquireLease() after panic error = %v", err)
	}
	defer nextLease.Release()

	if nextLease.State() == poisoned {
		t.Fatal("expected panicked Lua state to be replaced")
	}
}

func newTestPool(t *testing.T) *Pool {
	t.Helper()

	pool := newPool("test:lease", PoolOptions{MaxVMs: 1})

	t.Cleanup(func() {
		close(pool.states)

		for state := range pool.states {
			state.Close()
		}
	})

	return pool
}

func assertRequireSentinelPresent(t *testing.T, L *lua.LState) {
	t.Helper()

	if err := L.DoString(`
		local ok, err = pcall(require, "nauthilus_util")
		if ok then
			error("test module unexpectedly loaded")
		end
		if not string.find(tostring(err), "loop or previous error loading module", 1, true) then
			error("expected require sentinel, got: " .. tostring(err))
		end
	`); err != nil {
		t.Fatalf("Lua state does not contain expected require sentinel: %v", err)
	}
}

func assertNoRequireSentinel(t *testing.T, L *lua.LState) {
	t.Helper()

	if err := L.DoString(`
		local ok, err = pcall(require, "nauthilus_util")
		if ok then
			error("test module unexpectedly loaded")
		end
		if string.find(tostring(err), "loop or previous error loading module", 1, true) then
			error("require sentinel leaked into replacement VM: " .. tostring(err))
		end
	`); err != nil {
		t.Fatalf("Lua state still looks poisoned: %v", err)
	}
}
