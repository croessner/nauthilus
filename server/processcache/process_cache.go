// Copyright (C) 2026 Christian Roessner
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

// Package processcache provides dependency-light process-local cache semantics.
package processcache

import (
	"container/list"
	"sync"
	"time"
)

// Cache is a goroutine-safe, process-local cache with TTL and list batching semantics.
type Cache struct {
	mu          sync.RWMutex
	entries     map[string]*entry
	order       *list.List
	maxEntries  int
	stopJanitor chan struct{}
}

type entry struct {
	value     any
	expiresAt time.Time
	orderElem *list.Element
}

// New constructs a process-local cache.
func New(maxEntries int, janitorPeriod time.Duration) *Cache {
	cache := &Cache{
		entries:     make(map[string]*entry),
		order:       list.New(),
		maxEntries:  maxEntries,
		stopJanitor: make(chan struct{}),
	}

	if janitorPeriod > 0 {
		go cache.janitor(janitorPeriod)
	}

	return cache
}

// Set stores value under key with an optional TTL.
func (c *Cache) Set(key string, value any, ttl time.Duration) {
	if c == nil {
		return
	}

	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.entries[key]; ok {
		entry.value = value
		entry.expiresAt = expiresAt

		return
	}

	entry := &entry{value: value, expiresAt: expiresAt}
	entry.orderElem = c.order.PushBack(key)
	c.entries[key] = entry
	c.enforceLimitLocked()
}

// Get returns value when key is present and not expired.
func (c *Cache) Get(key string) (any, bool) {
	if c == nil {
		return nil, false
	}

	now := time.Now()

	c.mu.RLock()

	entry, ok := c.entries[key]
	if !ok {
		c.mu.RUnlock()

		return nil, false
	}

	if expiredAt(entry, now) {
		c.mu.RUnlock()
		c.mu.Lock()
		c.removeLocked(key)
		c.mu.Unlock()

		return nil, false
	}

	value := entry.value

	c.mu.RUnlock()

	return value, true
}

// Delete removes key and reports whether it existed.
func (c *Cache) Delete(key string) bool {
	if c == nil {
		return false
	}

	c.mu.Lock()
	_, ok := c.entries[key]
	c.removeLocked(key)
	c.mu.Unlock()

	return ok
}

// Exists reports whether key is present and not expired.
func (c *Cache) Exists(key string) bool {
	_, ok := c.Get(key)

	return ok
}

// Update stores updater's returned value atomically and returns it.
func (c *Cache) Update(key string, updater func(any) any) any {
	if c == nil || updater == nil {
		return nil
	}

	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	old := c.currentValueLocked(key, now)
	next := updater(old)

	if current, ok := c.entries[key]; ok {
		current.value = next
	} else {
		entry := &entry{value: next}
		entry.orderElem = c.order.PushBack(key)
		c.entries[key] = entry
		c.enforceLimitLocked()
	}

	return next
}

// Keys returns all non-expired keys.
func (c *Cache) Keys() []string {
	if c == nil {
		return nil
	}

	now := time.Now()

	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]string, 0, len(c.entries))
	for key, entry := range c.entries {
		if !expiredAt(entry, now) {
			keys = append(keys, key)
		}
	}

	return keys
}

// Size returns the number of non-expired entries.
func (c *Cache) Size() int {
	if c == nil {
		return 0
	}

	now := time.Now()

	c.mu.RLock()
	defer c.mu.RUnlock()

	count := 0

	for _, entry := range c.entries {
		if !expiredAt(entry, now) {
			count++
		}
	}

	return count
}

// Flush removes every entry.
func (c *Cache) Flush() {
	if c == nil {
		return
	}

	c.mu.Lock()
	c.entries = make(map[string]*entry)
	c.order.Init()
	c.mu.Unlock()
}

// Push appends value to the list at key and returns the new list length.
func (c *Cache) Push(key string, value any) int {
	if c == nil {
		return 0
	}

	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	var values []any

	if entry, ok := c.entries[key]; ok {
		if expiredAt(entry, now) {
			c.removeLocked(key)

			values = []any{value}
			c.setListLocked(key, values)

			return len(values)
		}

		switch current := entry.value.(type) {
		case []any:
			values = append(current, value)
		default:
			values = []any{current, value}
		}

		entry.value = values

		return len(values)
	}

	values = []any{value}
	c.setListLocked(key, values)

	return len(values)
}

// PopAll returns the list at key and removes it.
func (c *Cache) PopAll(key string) []any {
	if c == nil {
		return nil
	}

	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[key]
	if !ok {
		return []any{}
	}

	if expiredAt(entry, now) {
		c.removeLocked(key)

		return []any{}
	}

	var values []any

	switch current := entry.value.(type) {
	case []any:
		values = current
	default:
		values = []any{current}
	}

	c.removeLocked(key)

	return values
}

// Close stops the background janitor.
func (c *Cache) Close() {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case <-c.stopJanitor:
		return
	default:
		close(c.stopJanitor)
	}
}

// currentValueLocked returns the current value or nil after removing an expired entry.
func (c *Cache) currentValueLocked(key string, now time.Time) any {
	entry, ok := c.entries[key]
	if !ok {
		return nil
	}

	if expiredAt(entry, now) {
		c.removeLocked(key)

		return nil
	}

	return entry.value
}

// enforceLimitLocked evicts oldest inserted keys when maxEntries is positive.
func (c *Cache) enforceLimitLocked() {
	if c.maxEntries <= 0 {
		return
	}

	for len(c.entries) > c.maxEntries {
		front := c.order.Front()
		if front == nil {
			return
		}

		key, _ := front.Value.(string)
		c.removeLocked(key)
	}
}

// janitor periodically removes expired entries until Close is called.
func (c *Cache) janitor(period time.Duration) {
	ticker := time.NewTicker(period)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopJanitor:
			return
		case <-ticker.C:
			c.removeExpired()
		}
	}
}

// removeExpired removes expired entries in one exclusive pass.
func (c *Cache) removeExpired() {
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	for key, entry := range c.entries {
		if expiredAt(entry, now) {
			c.removeLocked(key)
		}
	}
}

// removeLocked removes key from the cache and insertion order.
func (c *Cache) removeLocked(key string) {
	if entry, ok := c.entries[key]; ok {
		if entry.orderElem != nil {
			c.order.Remove(entry.orderElem)
		}

		delete(c.entries, key)
	}
}

// setListLocked stores values as a list entry.
func (c *Cache) setListLocked(key string, values []any) {
	entry := &entry{value: values}
	entry.orderElem = c.order.PushBack(key)
	c.entries[key] = entry
	c.enforceLimitLocked()
}

// expiredAt reports whether entry expired before now.
func expiredAt(entry *entry, now time.Time) bool {
	return entry != nil && !entry.expiresAt.IsZero() && now.After(entry.expiresAt)
}
