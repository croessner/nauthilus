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

package localcache

import (
	"container/list"
	"sync"
	"time"
)

// SimpleCache provides the tiny surface needed by callers without tying them to a specific cache impl.
type SimpleCache interface {
	// Set stores a value in the cache with the specified key and an optional time-to-live (TTL) duration.
	Set(key string, value any, ttl time.Duration)

	// Get retrieves the value associated with the specified key from the cache. Returns the value and a boolean indicating presence.
	Get(key string) (any, bool)

	// Delete removes the value associated with the given key from the cache.
	Delete(key string)

	// Len returns the number of items currently stored in the cache.
	Len() int
}

// LRUCache is a small, goroutine-safe LRU cache with per-entry TTL.
type LRUCache struct {
	cap       int
	mu        sync.Mutex
	ll        *list.List
	items     map[string]*list.Element
	evictions int64
}

type lruEntry struct {
	key        string
	val        any
	expiration int64 // unix nano; 0 = no expiry
}

// NewLRU creates a new LRUCache with the given capacity. Capacity <= 0 disables caching.
func NewLRU(capacity int) *LRUCache {
	if capacity <= 0 {
		capacity = 0
	}

	return &LRUCache{
		cap:   capacity,
		ll:    list.New(),
		items: make(map[string]*list.Element),
	}
}

func (c *LRUCache) now() int64 { return time.Now().UnixNano() }

// Set inserts or updates a key with a value and TTL. ttl<=0 means no expiry.
func (c *LRUCache) Set(key string, value any, ttl time.Duration) {
	if c.cap == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var exp int64
	if ttl > 0 {
		exp = time.Now().Add(ttl).UnixNano()
	}

	if ee, ok := c.items[key]; ok {
		ent := ee.Value.(*lruEntry)
		ent.val = value
		ent.expiration = exp

		c.ll.MoveToFront(ee)

		return
	}

	ee := &lruEntry{key: key, val: value, expiration: exp}
	ele := c.ll.PushFront(ee)
	c.items[key] = ele

	for c.cap > 0 && c.ll.Len() > c.cap {
		c.removeOldest()
	}
}

// Get returns the value for key if present and not expired.
func (c *LRUCache) Get(key string) (any, bool) {
	if c.cap == 0 {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if ele, ok := c.items[key]; ok {
		ent := ele.Value.(*lruEntry)
		if ent.expiration > 0 && c.now() > ent.expiration {
			c.removeElement(ele)
			return nil, false
		}

		c.ll.MoveToFront(ele)

		return ent.val, true
	}

	return nil, false
}

// Delete removes a key if present.
func (c *LRUCache) Delete(key string) {
	if c.cap == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if ele, ok := c.items[key]; ok {
		c.removeElement(ele)
	}
}

// Len returns the number of items currently stored in the LRU cache. This method is thread-safe.
func (c *LRUCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.ll.Len()
}

// removeOldest removes the least recently used (oldest) item from the cache if one is present.
func (c *LRUCache) removeOldest() {
	if ele := c.ll.Back(); ele != nil {
		c.removeElement(ele)
	}
}

var _ SimpleCache = (*LRUCache)(nil)

// removeElement removes the specified element from the cache and updates eviction statistics.
func (c *LRUCache) removeElement(e *list.Element) {
	ent := e.Value.(*lruEntry)
	delete(c.items, ent.key)
	c.ll.Remove(e)
	c.evictions++
}
