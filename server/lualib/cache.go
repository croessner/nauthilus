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
	"container/list"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/convert"
	lua "github.com/yuin/gopher-lua"
)

// luaCache defines the behavior required by the internal cache that backs the Lua module nauthilus_cache.
// Implementations MUST be thread-safe.
// The cache intentionally does not persist data beyond the process lifetime.
type luaCache interface {
	// Set stores a value under key with an optional TTL (seconds). ttlSeconds<=0 disables expiry.
	Set(key string, value any, ttlSeconds int64)

	// Get returns the value if present and not expired; expired entries are lazily evicted on access.
	Get(key string) (any, bool)

	// Delete removes a key; returns whether it was present.
	Delete(key string) bool

	// Exists is a convenience wrapper using Get semantics (considers TTL).
	Exists(key string) bool

	// Update applies an updater function to the current value (which may be nil) and stores the result atomically; returns the new value.
	Update(key string, updater func(old any) any) any

	// Keys returns only non-expired entries.
	Keys() []string

	// Size returns only non-expired entries.
	Size() int

	// Flush clears the cache.
	Flush()

	// Push appends a value to a list stored at key, creating a list if needed. If the key holds a scalar, it is promoted to a 2-element list.
	Push(key string, value any) int

	// PopAll returns the entire list (or a single-element list if key holds a scalar) and removes the key.
	PopAll(key string) []any

	// Close stops background janitors if any.
	Close()
}

type luaEntry struct {
	value     any
	expiresAt time.Time
	orderElem *list.Element
}

// fifoCache is a simple FIFO-evicting, TTL-aware in-memory cache.
// - Eviction: if maxEntries>0, inserting beyond the limit evicts the oldest inserted keys (FIFO order).
// - TTL: entries may carry an absolute expiry. Expired entries are removed lazily on access and periodically by a janitor.
// - Concurrency: guarded by RWMutex; update() ensures atomic read-modify-write for a single key.
// fifoCache is a thread-safe, in-memory cache implementing luaCache.
// It provides FIFO eviction, TTL handling and helper list operations for batching.
type fifoCache struct {
	mu          sync.RWMutex
	m           map[string]*luaEntry
	order       *list.List
	maxEntries  int
	stopJanitor chan struct{}
}

// newFIFOCache constructs a fifoCache.
// maxEntries <= 0 disables size-based eviction. janitorPeriod <= 0 disables background cleanup.
func newFIFOCache(maxEntries int, janitorPeriod time.Duration) *fifoCache {
	c := &fifoCache{
		m:           make(map[string]*luaEntry),
		order:       list.New(),
		maxEntries:  maxEntries,
		stopJanitor: make(chan struct{}),
	}

	if janitorPeriod > 0 {
		go c.janitor(janitorPeriod)
	}

	return c
}

// Close gracefully shuts down the janitor process by signaling and closing the stopJanitor channel.
func (c *fifoCache) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case <-c.stopJanitor:
		return
	default:
		close(c.stopJanitor)
	}
}

// janitor runs a periodic cleanup process to remove expired cache entries until the stop signal is received.
func (c *fifoCache) janitor(period time.Duration) {
	t := time.NewTicker(period)
	defer t.Stop()

	for {
		select {
		case <-c.stopJanitor:
			return
		case <-t.C:
			c.removeExpired()
		}
	}
}

// removeExpired removes all expired entries from the cache. Locks the cache for exclusive access during the operation.
func (c *fifoCache) removeExpired() {
	now := time.Now()
	c.mu.Lock()

	for k, e := range c.m {
		if !e.expiresAt.IsZero() && now.After(e.expiresAt) {
			c.removeLocked(k)
		}
	}

	c.mu.Unlock()
}

// Set stores a value under key with an optional TTL in seconds.
// A ttlSeconds <= 0 stores the entry without expiration.
func (c *fifoCache) Set(key string, value any, ttlSeconds int64) {
	var exp time.Time

	if ttlSeconds > 0 {
		exp = time.Now().Add(time.Duration(ttlSeconds) * time.Second)
	}

	c.mu.Lock()

	if e, ok := c.m[key]; ok {
		e.value = value
		e.expiresAt = exp
	} else {
		e := &luaEntry{value: value, expiresAt: exp}
		e.orderElem = c.order.PushBack(key)
		c.m[key] = e

		c.enforceLimitLocked()
	}

	c.mu.Unlock()
}

// enforceLimitLocked ensures cache size does not exceed maxEntries by evicting the oldest inserted keys in FIFO order.
func (c *fifoCache) enforceLimitLocked() {
	if c.maxEntries <= 0 {
		return
	}

	for len(c.m) > c.maxEntries {
		front := c.order.Front()
		if front == nil {
			return
		}

		oldestKey := front.Value.(string)

		c.removeLocked(oldestKey)
	}
}

// removeLocked removes the entry corresponding to the given key from the cache, updating both the map and the order list.
func (c *fifoCache) removeLocked(key string) {
	if e, ok := c.m[key]; ok {
		if e.orderElem != nil {
			c.order.Remove(e.orderElem)
		}

		delete(c.m, key)
	}
}

// Get returns the value for key if present and not expired.
// Expired entries are removed lazily and (nil,false) is returned.
func (c *fifoCache) Get(key string) (any, bool) {
	now := time.Now()

	c.mu.RLock()

	e, ok := c.m[key]
	if !ok {
		c.mu.RUnlock()

		return nil, false
	}

	if !e.expiresAt.IsZero() && now.After(e.expiresAt) {
		c.mu.RUnlock()

		c.mu.Lock()
		c.removeLocked(key)
		c.mu.Unlock()

		return nil, false
	}

	val := e.value

	c.mu.RUnlock()

	return val, true
}

// Delete removes key from the cache and returns whether it existed.
func (c *fifoCache) Delete(key string) bool {
	c.mu.Lock()
	_, ok := c.m[key]
	c.removeLocked(key)
	c.mu.Unlock()

	return ok
}

// Exists reports whether key is present and not expired.
func (c *fifoCache) Exists(key string) bool {
	_, ok := c.Get(key)

	return ok
}

// Update applies updater to the current value (or nil if missing/expired) atomically,
// stores the returned value under key, and returns it.
func (c *fifoCache) Update(key string, updater func(old any) any) any {
	if updater == nil {
		return nil
	}

	c.mu.Lock()

	var old any
	if e, ok := c.m[key]; ok {
		if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
			c.removeLocked(key)
			old = nil
		} else {
			old = e.value
		}
	}

	newVal := updater(old)
	if e, ok := c.m[key]; ok {
		e.value = newVal
	} else {
		e := &luaEntry{value: newVal}
		e.orderElem = c.order.PushBack(key)
		c.m[key] = e

		c.enforceLimitLocked()
	}

	c.mu.Unlock()

	return newVal
}

// Keys returns all non-expired keys currently in the cache.
func (c *fifoCache) Keys() []string {
	now := time.Now()

	c.mu.RLock()

	keys := make([]string, 0, len(c.m))
	for k, e := range c.m {
		if e.expiresAt.IsZero() || now.Before(e.expiresAt) {
			keys = append(keys, k)
		}
	}

	c.mu.RUnlock()

	return keys
}

// Size returns the number of non-expired entries currently stored.
func (c *fifoCache) Size() int {
	now := time.Now()

	c.mu.RLock()

	cnt := 0
	for _, e := range c.m {
		if e.expiresAt.IsZero() || now.Before(e.expiresAt) {
			cnt++
		}
	}

	c.mu.RUnlock()

	return cnt
}

// Flush removes all entries from the cache.
func (c *fifoCache) Flush() {
	c.mu.Lock()
	c.m = make(map[string]*luaEntry)
	c.order.Init()
	c.mu.Unlock()
}

// Push appends value to a list at key (creating a list if needed). Returns the new length.
// If key holds a scalar, it is promoted to a 2-element list.
func (c *fifoCache) Push(key string, value any) int {
	c.mu.Lock()

	var arr []any
	if e, ok := c.m[key]; ok {
		if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
			c.removeLocked(key)

			arr = []any{value}
			e = &luaEntry{value: arr}
			e.orderElem = c.order.PushBack(key)
			c.m[key] = e

			c.enforceLimitLocked()
			res := len(arr)

			c.mu.Unlock()

			return res
		}
		switch v := e.value.(type) {
		case []any:
			arr = append(v, value)
			e.value = arr
		default:
			arr = []any{v, value}
			e.value = arr
		}
	} else {
		arr = []any{value}
		e := &luaEntry{value: arr}
		e.orderElem = c.order.PushBack(key)
		c.m[key] = e

		c.enforceLimitLocked()
	}

	res := len(arr)

	c.mu.Unlock()

	return res
}

// PopAll returns the entire list under key and removes the key.
// If the value is a scalar, a single-element list is returned.
func (c *fifoCache) PopAll(key string) []any {
	c.mu.Lock()

	var out []any

	if e, ok := c.m[key]; ok {
		if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
			c.removeLocked(key)

			c.mu.Unlock()

			return []any{}
		}

		switch v := e.value.(type) {
		case []any:
			out = v
		default:
			out = []any{v}
		}

		c.removeLocked(key)
	} else {
		out = []any{}
	}

	c.mu.Unlock()

	return out
}

// globalLuaCache is a process-wide singleton backing the Lua cache module.
var globalLuaCache luaCache = newFIFOCache(0, 30*time.Second)

// LoaderModCache exposes the nauthilus_cache module to Lua.
// Note: no request context is needed; the cache is process-wide and independent from per-request state.
// Explicit Lua-facing functions (no inline lambdas in LoaderModCache)
// luaCacheSet implements nauthilus_cache.cache_set(key, value[, ttl_seconds]).
// Parameters: key (string), value (any convertible), ttl_seconds (number|nil|0=no expiry). Returns: "OK", nil.
func luaCacheSet(L *lua.LState) int {
	key := L.CheckString(1)
	val := convert.LuaValueToGo(L.CheckAny(2))

	var ttl int64
	if L.GetTop() >= 3 {
		if v := L.Get(3); v != lua.LNil {
			ttl = int64(L.CheckNumber(3))
		}
	}

	globalLuaCache.Set(key, val, ttl)
	L.Push(lua.LString("OK"))
	L.Push(lua.LNil)

	return 2
}

// luaCacheGet implements nauthilus_cache.cache_get(key).
// Returns the stored value or nil if not present or expired.
func luaCacheGet(L *lua.LState) int {
	key := L.CheckString(1)
	val, ok := globalLuaCache.Get(key)

	if !ok {
		L.Push(lua.LNil)

		return 1
	}

	L.Push(convert.GoToLuaValue(L, val))

	return 1
}

// luaCacheDelete implements nauthilus_cache.cache_delete(key).
// Returns true if the key existed and was removed; otherwise false.
func luaCacheDelete(L *lua.LState) int {
	key := L.CheckString(1)
	ok := globalLuaCache.Delete(key)

	L.Push(lua.LBool(ok))

	return 1
}

// luaCacheExists implements nauthilus_cache.cache_exists(key).
// Returns true only if the key exists and has not expired.
func luaCacheExists(L *lua.LState) int {
	key := L.CheckString(1)

	L.Push(lua.LBool(globalLuaCache.Exists(key)))

	return 1
}

// luaCacheUpdate implements nauthilus_cache.cache_update(key, updater_fn).
// Calls updater_fn(old_value) in Lua and stores its return value atomically.
// updater_fn must be synchronous (no yields). Returns the new value.
func luaCacheUpdate(L *lua.LState) int {
	key := L.CheckString(1)
	fn := L.CheckFunction(2)

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

	L.Push(convert.GoToLuaValue(L, newVal))

	return 1
}

// luaCacheKeys implements nauthilus_cache.cache_keys().
// Returns an array (Lua table) with all current non-expired keys.
func luaCacheKeys(L *lua.LState) int {
	keys := globalLuaCache.Keys()
	tbl := L.NewTable()

	for _, k := range keys {
		tbl.Append(lua.LString(k))
	}

	L.Push(tbl)

	return 1
}

// luaCacheSize implements nauthilus_cache.cache_size().
// Returns the number of non-expired entries in the cache.
func luaCacheSize(L *lua.LState) int {
	L.Push(lua.LNumber(globalLuaCache.Size()))

	return 1
}

// luaCacheFlush implements nauthilus_cache.cache_flush().
// Empties the entire cache.
func luaCacheFlush(_ *lua.LState) int {
	globalLuaCache.Flush()

	return 0
}

// luaCachePush implements nauthilus_cache.cache_push(key, value).
// Appends value to the list at key (creating it if needed). Returns the new length.
func luaCachePush(L *lua.LState) int {
	key := L.CheckString(1)
	val := convert.LuaValueToGo(L.CheckAny(2))
	n := globalLuaCache.Push(key, val)

	L.Push(lua.LNumber(n))

	return 1
}

// luaCachePopAll implements nauthilus_cache.cache_pop_all(key).
// Returns the list at key and clears it; if absent, returns an empty list.
func luaCachePopAll(L *lua.LState) int {
	key := L.CheckString(1)
	arr := globalLuaCache.PopAll(key)

	L.Push(convert.GoToLuaValue(L, arr))

	return 1
}

// LoaderModCache registers the nauthilus_cache module into a Lua state.
// The module exposes cache_set/get/delete/exists/update/keys/size/flush/push/pop_all.
// The cache is process-wide (no per-request state needed).
func LoaderModCache() lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnCacheSet:    luaCacheSet,
			definitions.LuaFnCacheGet:    luaCacheGet,
			definitions.LuaFnCacheDelete: luaCacheDelete,
			definitions.LuaFnCacheExists: luaCacheExists,
			definitions.LuaFnCacheUpdate: luaCacheUpdate,
			definitions.LuaFnCacheKeys:   luaCacheKeys,
			definitions.LuaFnCacheSize:   luaCacheSize,
			definitions.LuaFnCacheFlush:  luaCacheFlush,
			definitions.LuaFnCachePush:   luaCachePush,
			definitions.LuaFnCachePopAll: luaCachePopAll,
		})

		L.Push(mod)

		return 1
	}
}

// StopGlobalCache is an optional helper to stop the janitor; can be used by shutdown hooks.
// StopGlobalCache stops the background janitor of the process-wide cache.
// Call this during server shutdown to release goroutines promptly.
func StopGlobalCache() {
	globalLuaCache.Close()
}
