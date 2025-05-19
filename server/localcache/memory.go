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
)

// Item represents a cached item with expiration time
type Item struct {
	Object     any
	Expiration int64
}

// Cache is a custom in-memory cache implementation
type Cache struct {
	items             map[string]Item
	mu                sync.RWMutex
	defaultExpiration time.Duration
	cleanupInterval   time.Duration
	janitor           *janitor
}

// janitor cleans up expired items from the cache
type janitor struct {
	Interval time.Duration
	stop     chan bool
}

// NewCache creates a new cache with the given default expiration and cleanup interval
func NewCache(defaultExpiration, cleanupInterval time.Duration) *Cache {
	cache := &Cache{
		items:             make(map[string]Item),
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

// startJanitor starts the cleanup process
func (c *Cache) startJanitor() {
	ticker := time.NewTicker(c.janitor.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.DeleteExpired()
		case <-c.janitor.stop:
			return
		}
	}
}

// Set adds an item to the cache with the given expiration duration
func (c *Cache) Set(k string, x any, d time.Duration) {
	var exp int64

	if d == 0 {
		d = c.defaultExpiration
	}

	if d > 0 {
		exp = time.Now().Add(d).UnixNano()
	}

	c.mu.Lock()
	c.items[k] = Item{
		Object:     x,
		Expiration: exp,
	}
	c.mu.Unlock()
}

// Get retrieves an item from the cache
func (c *Cache) Get(k string) (any, bool) {
	c.mu.RLock()
	item, found := c.items[k]
	c.mu.RUnlock()

	if !found {
		return nil, false
	}

	// Check if the item has expired
	if item.Expiration > 0 && time.Now().UnixNano() > item.Expiration {
		return nil, false
	}

	return item.Object, true
}

// Delete removes an item from the cache
func (c *Cache) Delete(k string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if the item is a PassDBResult before deleting
	if item, found := c.items[k]; found {
		c.resetAndReturnToPoolIfPassDBResult(item.Object)
	}

	delete(c.items, k)
}

// DeleteExpired removes all expired items from the cache
func (c *Cache) DeleteExpired() {
	now := time.Now().UnixNano()

	c.mu.Lock()
	defer c.mu.Unlock()

	for k, item := range c.items {
		if item.Expiration > 0 && now > item.Expiration {
			c.resetAndReturnToPoolIfPassDBResult(item.Object)
			delete(c.items, k)
		}
	}
}

// resetAndReturnToPoolIfPassDBResult checks if an object has a Reset method
// and if so, calls it and returns the object to the pool if it's a PassDBResult
func (c *Cache) resetAndReturnToPoolIfPassDBResult(obj any) {
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

// LocalCache is a cache object with a default expiration duration of 5 minutes
// and a cleanup interval of 10 minutes.
var LocalCache = NewCache(5*time.Minute, 10*time.Minute)
