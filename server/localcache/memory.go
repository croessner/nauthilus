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

package localcache

import (
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/objpool"
	"github.com/croessner/nauthilus/server/stats"

	"github.com/cespare/xxhash/v2"
)

// Item represents a cached item with expiration time
type Item struct {
	Object     any
	Expiration int64
}

// MemoryCacheShard represents a single shard of the memory cache
type MemoryCacheShard struct {
	items map[string]Item
	mu    sync.RWMutex
}

// MemoryShardedCache is a cache that is split into multiple shards to reduce mutex contention
type MemoryShardedCache struct {
	shards            []*MemoryCacheShard
	numShards         int
	defaultExpiration time.Duration
	cleanupInterval   time.Duration
	janitor           *janitor
}

// Cache is a custom in-memory cache implementation (kept for backward compatibility)
//
// Deprecated: Use MemoryShardedCache instead.
type Cache struct {
	*MemoryShardedCache
}

// janitor cleans up expired items from the cache
type janitor struct {
	Interval time.Duration
	stop     chan bool
}

// NewMemoryShardedCache creates a new sharded cache with the specified number of shards
func NewMemoryShardedCache(numShards int, defaultExpiration, cleanupInterval time.Duration) *MemoryShardedCache {
	shards := make([]*MemoryCacheShard, numShards)
	for i := 0; i < numShards; i++ {
		shards[i] = &MemoryCacheShard{
			items: make(map[string]Item),
		}
	}

	cache := &MemoryShardedCache{
		shards:            shards,
		numShards:         numShards,
		defaultExpiration: defaultExpiration,
		cleanupInterval:   cleanupInterval,
	}

	// Start the janitor if cleanup interval is greater than 0
	if cleanupInterval > 0 {
		j := &janitor{
			Interval: cleanupInterval,
			stop:     make(chan bool),
		}
		cache.janitor = j

		go cache.startJanitor()
	}

	return cache
}

// getShard returns the shard for the given key
func (sc *MemoryShardedCache) getShard(key string) *MemoryCacheShard {
	// Use xxhash to determine the shard
	h := xxhash.Sum64String(key)

	return sc.shards[h%uint64(sc.numShards)]
}

// NewCache creates a new cache with the given default expiration and cleanup interval
// For backward compatibility, it now returns a MemoryShardedCache wrapped in a Cache struct
//
// Deprecated: Use NewMemoryShardedCache instead.
func NewCache(defaultExpiration, cleanupInterval time.Duration) *Cache {
	// Use 32 shards as a reasonable default for most systems
	return &Cache{
		MemoryShardedCache: NewMemoryShardedCache(32, defaultExpiration, cleanupInterval),
	}
}

// startJanitor starts the cleanup process for MemoryShardedCache
func (sc *MemoryShardedCache) startJanitor() {
	ticker := time.NewTicker(sc.janitor.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sc.DeleteExpired()
		case <-sc.janitor.stop:
			return
		}
	}
}

// Stop stops the background janitor if it is running.
// It is safe to call multiple times.
func (sc *MemoryShardedCache) Stop() {
	if sc == nil || sc.janitor == nil {
		return
	}

	// Non-blocking stop signal; janitor goroutine exits on receipt
	select {
	case sc.janitor.stop <- true:
	default:
		// already signaled or drained
	}
}

// Set adds an item to the MemoryShardedCache with the given expiration duration
func (sc *MemoryShardedCache) Set(k string, x any, d time.Duration) {
	var exp int64

	if d == 0 {
		d = sc.defaultExpiration
	}

	if d > 0 {
		exp = time.Now().Add(d).UnixNano()
	}

	shard := sc.getShard(k)

	shard.mu.Lock()
	shard.items[k] = Item{
		Object:     x,
		Expiration: exp,
	}
	shard.mu.Unlock()
}

// Get retrieves an item from the MemoryShardedCache
func (sc *MemoryShardedCache) Get(k string) (any, bool) {
	shard := sc.getShard(k)

	shard.mu.RLock()
	item, found := shard.items[k]
	shard.mu.RUnlock()

	if !found {
		return nil, false
	}

	// Check if the item has expired
	if item.Expiration > 0 && time.Now().UnixNano() > item.Expiration {
		return nil, false
	}

	return item.Object, true
}

// Delete removes an item from the MemoryShardedCache
func (sc *MemoryShardedCache) Delete(k string) {
	shard := sc.getShard(k)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	// Check if the item is a PassDBResult before deleting
	if item, found := shard.items[k]; found {
		sc.resetAndReturnToPoolIfPassDBResult(item.Object)
	}

	delete(shard.items, k)
}

// DeleteExpired removes all expired items from the MemoryShardedCache
func (sc *MemoryShardedCache) DeleteExpired() {
	now := time.Now().UnixNano()

	// Iterate through all shards
	for _, shard := range sc.shards {
		shard.mu.Lock()

		// Iterate through all items in the shard
		for k, item := range shard.items {
			if item.Expiration > 0 && now > item.Expiration {
				sc.resetAndReturnToPoolIfPassDBResult(item.Object)
				delete(shard.items, k)
				// eviction due to TTL expiration (shared cache)
				stats.GetMetrics().GetLdapCacheEvictionsTotal().WithLabelValues("shared", "ttl").Inc()
			}
		}

		shard.mu.Unlock()
	}
}

// resetAndReturnToPoolIfPassDBResult checks if an object has a Reset method
// and if so, calls it and returns the object to the pool if it's a PassDBResult
func (sc *MemoryShardedCache) resetAndReturnToPoolIfPassDBResult(obj any) {
	if obj == nil {
		return
	}

	// Try to cast the object to a type with a Reset method
	// This uses a type assertion to check if the object has a Reset method
	// without needing to know the concrete type
	if resettable, ok := obj.(interface{ Reset() }); ok {
		// Call the Reset method
		resettable.Reset()
	}

	// Check if it's a PassDBResult by checking if it has the IsPassDBResult method
	// This avoids using reflection and direct dependency on the core package
	if passDBResult, ok := obj.(interface{ IsPassDBResult() bool }); ok && passDBResult.IsPassDBResult() {
		// Return the object to the pool using the global PassDBResultPool instance
		objpool.GetPassDBResultPool().Put(obj)
	}
}

// startJanitor delegates to MemoryShardedCache.startJanitor
func (c *Cache) startJanitor() {
	c.MemoryShardedCache.startJanitor()
}

// Stop stops the background janitor on the underlying sharded cache, if any.
func (c *Cache) Stop() { c.MemoryShardedCache.Stop() }

// Set delegates to MemoryShardedCache.Set
func (c *Cache) Set(k string, x any, d time.Duration) {
	c.MemoryShardedCache.Set(k, x, d)
}

// Get delegates to MemoryShardedCache.Get
func (c *Cache) Get(k string) (any, bool) {
	return c.MemoryShardedCache.Get(k)
}

// Delete delegates to MemoryShardedCache.Delete
func (c *Cache) Delete(k string) {
	c.MemoryShardedCache.Delete(k)
}

// DeleteExpired delegates to MemoryShardedCache.DeleteExpired
func (c *Cache) DeleteExpired() {
	c.MemoryShardedCache.DeleteExpired()
}

// resetAndReturnToPoolIfPassDBResult delegates to MemoryShardedCache.resetAndReturnToPoolIfPassDBResult
func (c *Cache) resetAndReturnToPoolIfPassDBResult(obj any) {
	c.MemoryShardedCache.resetAndReturnToPoolIfPassDBResult(obj)
}

// LocalCache is a cache object with a default expiration duration of 5 minutes.
// Cleanup interval is set to 0 to avoid a globally running janitor. Specific
// subsystems (e.g., LDAP) should manage their own lifecycle-bound janitors.
var LocalCache = NewCache(5*time.Minute, 0)

// Len returns the total number of items currently stored across all shards.
func (sc *MemoryShardedCache) Len() int {
	count := 0

	for _, shard := range sc.shards {
		shard.mu.RLock()
		count += len(shard.items)
		shard.mu.RUnlock()
	}

	return count
}
