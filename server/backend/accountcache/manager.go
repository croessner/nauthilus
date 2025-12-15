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

package accountcache

import (
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/localcache"
)

// Manager provides an in-process cache for username -> accountName mapping.
// It is intentionally small and sharded to reduce lock contention.
type Manager struct {
	once     sync.Once
	cache    *localcache.MemoryShardedCache
	ttl      time.Duration
	maxItems int
}

var (
	mgr Manager
)

// initCache initializes the underlying cache based on configuration.
func (m *Manager) initCache() {
	m.once.Do(func() {
		cfg := config.GetFile().GetServer().GetRedis().GetAccountLocalCache()
		// If disabled, still create a tiny cache with zero TTL so Get works but never hits.
		shards := cfg.GetShards()
		ttl := cfg.GetTTL()
		cleanup := cfg.GetCleanupInterval()

		m.ttl = ttl
		m.maxItems = cfg.GetMaxItems()
		m.cache = localcache.NewMemoryShardedCache(shards, ttl, cleanup)
	})
}

// GetManager returns the singleton cache manager instance.
func GetManager() *Manager { mgr.initCache(); return &mgr }

// Get returns a cached account name for the given username (if present).
func (m *Manager) Get(username string) (string, bool) {
	if m == nil {
		return "", false
	}
	m.initCache()

	if m.cache == nil {
		return "", false
	}
	if v, ok := m.cache.Get(username); ok {
		if s, ok2 := v.(string); ok2 {
			return s, true
		}
	}

	return "", false
}

// Set stores the mapping with the configured TTL. If disabled, it is a no-op.
func (m *Manager) Set(username, account string) {
	if m == nil {
		return
	}
	m.initCache()

	// Only set when feature is enabled
	if !config.GetFile().GetServer().GetRedis().GetAccountLocalCache().IsEnabled() {
		return
	}

	if m.cache == nil {
		return
	}

	// Optional: enforce max items (best-effort). If MaxItems==0 => unlimited.
	if m.maxItems > 0 && m.cache.Len() >= m.maxItems {
		// Best-effort: do nothing; cache will naturally rotate via TTL.
		// We keep it simple to avoid adding LRU complexity.
	}

	m.cache.Set(username, account, m.ttl)
}
