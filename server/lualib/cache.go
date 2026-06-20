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

package lualib

import (
	"context"
	"log/slog"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib/convert"
	"github.com/croessner/nauthilus/v3/server/lualib/luastack"
	"github.com/croessner/nauthilus/v3/server/processcache"

	lua "github.com/yuin/gopher-lua"
)

// CacheManager manages process-wide cache operations for Lua.
type CacheManager struct {
	*BaseManager
}

// NewCacheManager creates a new CacheManager.
func NewCacheManager(ctx context.Context, cfg config.File, logger *slog.Logger) *CacheManager {
	return &CacheManager{
		BaseManager: NewBaseManager(ctx, cfg, logger),
	}
}

// globalLuaCache is a process-wide singleton backing the Lua cache module.
var globalLuaCache = processcache.New(0, 30*time.Second)

// Set implements nauthilus_cache.cache_set(key, value[, ttl_seconds]).
// Parameters: key (string), value (any convertible), ttl_seconds (number|nil|0=no expiry). Returns: "OK", nil.
func (m *CacheManager) Set(L *lua.LState) int {
	stack := luastack.NewManager(L)
	key := stack.CheckString(1)
	val := convert.LuaValueToGo(stack.CheckAny(2))

	var ttl time.Duration

	if stack.GetTop() >= 3 {
		if v := L.Get(3); v != lua.LNil {
			ttl = time.Duration(stack.CheckNumber(3)) * time.Second
		}
	}

	globalLuaCache.Set(key, val, ttl)

	return stack.PushResults(lua.LString("OK"), lua.LNil)
}

// Get implements nauthilus_cache.cache_get(key).
// Returns the stored value or nil if not present or expired.
func (m *CacheManager) Get(L *lua.LState) int {
	stack := luastack.NewManager(L)
	key := stack.CheckString(1)
	val, ok := globalLuaCache.Get(key)

	if !ok {
		return stack.PushResults(lua.LNil, lua.LNil)
	}

	return stack.PushResults(convert.GoToLuaValue(L, val), lua.LNil)
}

// Delete implements nauthilus_cache.cache_delete(key).
// Returns true if the key existed and was removed; otherwise false.
func (m *CacheManager) Delete(L *lua.LState) int {
	stack := luastack.NewManager(L)
	key := stack.CheckString(1)
	ok := globalLuaCache.Delete(key)

	return stack.PushResults(lua.LBool(ok), lua.LNil)
}

// Exists implements nauthilus_cache.cache_exists(key).
// Returns true only if the key exists and has not expired.
func (m *CacheManager) Exists(L *lua.LState) int {
	stack := luastack.NewManager(L)
	key := stack.CheckString(1)

	return stack.PushResults(lua.LBool(globalLuaCache.Exists(key)), lua.LNil)
}

// Update implements nauthilus_cache.cache_update(key, updater_fn).
// Calls updater_fn(old_value) in Lua and stores its return value atomically.
// updater_fn must be synchronous (no yields). Returns the new value.
func (m *CacheManager) Update(L *lua.LState) int {
	stack := luastack.NewManager(L)
	key := stack.CheckString(1)
	fn := stack.L.CheckFunction(2)

	newVal := globalLuaCache.Update(key, func(old any) any {
		// Call Lua updater(old)
		L.Push(fn)
		L.Push(convert.GoToLuaValue(L, old))

		if err := L.PCall(1, 1, nil); err != nil {
			L.RaiseError("cache_update error: %v", err)

			return old
		}

		v := convert.LuaValueToGo(L.Get(-1))

		L.Pop(1)

		return v
	})

	return stack.PushResults(convert.GoToLuaValue(L, newVal), lua.LNil)
}

// Keys implements nauthilus_cache.cache_keys().
// Returns an array (Lua table) with all current non-expired keys.
func (m *CacheManager) Keys(L *lua.LState) int {
	stack := luastack.NewManager(L)
	keys := globalLuaCache.Keys()
	tbl := L.NewTable()

	for _, k := range keys {
		tbl.Append(lua.LString(k))
	}

	return stack.PushResults(tbl, lua.LNil)
}

// Size implements nauthilus_cache.cache_size().
// Returns the number of non-expired entries in the cache.
func (m *CacheManager) Size(L *lua.LState) int {
	stack := luastack.NewManager(L)

	return stack.PushResults(lua.LNumber(globalLuaCache.Size()), lua.LNil)
}

// Flush implements nauthilus_cache.cache_flush().
// Empties the entire cache.
func (m *CacheManager) Flush(_ *lua.LState) int {
	globalLuaCache.Flush()

	return 0
}

// Push implements nauthilus_cache.cache_push(key, value).
// Appends value to the list at key (creating it if needed). Returns the new length.
func (m *CacheManager) Push(L *lua.LState) int {
	stack := luastack.NewManager(L)
	key := stack.CheckString(1)
	val := convert.LuaValueToGo(stack.CheckAny(2))
	n := globalLuaCache.Push(key, val)

	return stack.PushResults(lua.LNumber(n), lua.LNil)
}

// PopAll implements nauthilus_cache.cache_pop_all(key).
// Returns the list at key and clears it; if absent, returns an empty list.
func (m *CacheManager) PopAll(L *lua.LState) int {
	stack := luastack.NewManager(L)
	key := stack.CheckString(1)
	arr := globalLuaCache.PopAll(key)

	return stack.PushResults(convert.GoToLuaValue(L, arr), lua.LNil)
}

// LoaderModCache registers the nauthilus_cache module into a Lua state.
// The module exposes cache_set/get/delete/exists/update/keys/size/flush/push/pop_all.
// The cache is process-wide (no per-request state needed).
func LoaderModCache(ctx context.Context, cfg config.File, logger *slog.Logger) lua.LGFunction {
	return func(L *lua.LState) int {
		manager := NewCacheManager(ctx, cfg, logger)

		return pushLuaModule(L, cacheValueFunctions(manager), cacheListFunctions(manager))
	}
}

// cacheValueFunctions returns Lua cache functions for scalar cache operations.
func cacheValueFunctions(manager *CacheManager) map[string]lua.LGFunction {
	return map[string]lua.LGFunction{
		definitions.LuaFnCacheSet:    manager.Set,
		definitions.LuaFnCacheGet:    manager.Get,
		definitions.LuaFnCacheDelete: manager.Delete,
		definitions.LuaFnCacheExists: manager.Exists,
		definitions.LuaFnCacheUpdate: manager.Update,
	}
}

// cacheListFunctions returns Lua cache functions for cache introspection and list operations.
func cacheListFunctions(manager *CacheManager) map[string]lua.LGFunction {
	return map[string]lua.LGFunction{
		definitions.LuaFnCacheKeys:   manager.Keys,
		definitions.LuaFnCacheSize:   manager.Size,
		definitions.LuaFnCacheFlush:  manager.Flush,
		definitions.LuaFnCachePush:   manager.Push,
		definitions.LuaFnCachePopAll: manager.PopAll,
	}
}

// StopGlobalCache is an optional helper to stop the janitor; can be used by shutdown hooks.
// StopGlobalCache stops the background janitor of the process-wide cache.
// Call this during server shutdown to release goroutines promptly.
func StopGlobalCache() {
	globalLuaCache.Close()
}
