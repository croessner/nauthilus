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

package pluginruntime

import (
	"context"
	"fmt"
	"sync"
	"time"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/processcache"
)

var _ pluginapi.Cache = (*moduleCache)(nil)

type cacheRegistry struct {
	caches map[string]*processcache.Cache
	mu     sync.Mutex
}

type moduleCache struct {
	cache *processcache.Cache
}

// newCacheRegistry creates isolated process-local caches per plugin module.
func newCacheRegistry() *cacheRegistry {
	return &cacheRegistry{caches: make(map[string]*processcache.Cache)}
}

// Cache returns the isolated cache for scope, creating it on first use.
func (r *cacheRegistry) Cache(scope string) (pluginapi.Cache, error) {
	if err := pluginapi.ValidateModuleName(scope); err != nil {
		return nil, fmt.Errorf("%w: cache scope %q", err, scope)
	}

	if r == nil {
		return nil, fmt.Errorf("plugin cache registry unavailable")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	cache, ok := r.caches[scope]
	if !ok {
		cache = processcache.New(0, 30*time.Second)
		r.caches[scope] = cache
	}

	return &moduleCache{cache: cache}, nil
}

// Set stores value under key with ttl.
func (c *moduleCache) Set(_ context.Context, key string, value any, ttl time.Duration) {
	if c == nil || c.cache == nil {
		return
	}

	c.cache.Set(key, value, ttl)
}

// Get returns the value for key when present and not expired.
func (c *moduleCache) Get(_ context.Context, key string) (any, bool) {
	if c == nil || c.cache == nil {
		return nil, false
	}

	return c.cache.Get(key)
}

// Delete removes key and reports whether it existed.
func (c *moduleCache) Delete(_ context.Context, key string) bool {
	if c == nil || c.cache == nil {
		return false
	}

	return c.cache.Delete(key)
}

// Exists reports whether key is present and not expired.
func (c *moduleCache) Exists(_ context.Context, key string) bool {
	if c == nil || c.cache == nil {
		return false
	}

	return c.cache.Exists(key)
}

// Push appends value to a cached list and returns the new length.
func (c *moduleCache) Push(_ context.Context, key string, value any) int {
	if c == nil || c.cache == nil {
		return 0
	}

	return c.cache.Push(key, value)
}

// PopAll returns all list values and clears key.
func (c *moduleCache) PopAll(_ context.Context, key string) []any {
	if c == nil || c.cache == nil {
		return nil
	}

	return c.cache.PopAll(key)
}

// Clear removes every entry in the module cache.
func (c *moduleCache) Clear(_ context.Context) {
	if c == nil || c.cache == nil {
		return
	}

	c.cache.Flush()
}
