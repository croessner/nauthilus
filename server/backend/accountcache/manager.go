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

func (m *Manager) initCacheWithCfg(cfg config.File) {
	m.once.Do(func() {
		localCacheCfg := cfg.GetServer().GetRedis().GetAccountLocalCache()
		// If disabled, still create a tiny cache with zero TTL so Get works but never hits.
		shards := localCacheCfg.GetShards()
		ttl := localCacheCfg.GetTTL()
		cleanup := localCacheCfg.GetCleanupInterval()

		m.ttl = ttl
		m.maxItems = localCacheCfg.GetMaxItems()
		m.cache = localcache.NewMemoryShardedCache(shards, ttl, cleanup)
	})
}

// NewManager creates a new Manager instance.
func NewManager(cfg config.File) *Manager {
	m := &Manager{}
	m.initCacheWithCfg(cfg)

	return m
}

func (m *Manager) makeKey(username, protocol, oidcClientID string) string {
	return GetAccountMappingField(username, protocol, oidcClientID)
}

// GetAccountMappingField returns a composite field name for username -> account mapping.
// It combines username, protocol and oidcClientID to allow context-specific mappings.
func GetAccountMappingField(username, protocol, oidcClientID string) string {
	return username + "|" + protocol + "|" + oidcClientID
}

// Get returns a cached account name for the given username (if present).
func (m *Manager) Get(username, protocol, oidcClientID string) (string, bool) {
	if m == nil || m.cache == nil {
		return "", false
	}

	key := m.makeKey(username, protocol, oidcClientID)

	if v, ok := m.cache.Get(key); ok {
		if s, ok2 := v.(string); ok2 {
			return s, true
		}
	}

	return "", false
}

// Set stores the mapping with the configured TTL. If disabled, it is a no-op.
func (m *Manager) Set(cfg config.File, username, protocol, oidcClientID, account string) {
	if m == nil || m.cache == nil {
		return
	}

	// Only set when feature is enabled
	if !cfg.GetServer().GetRedis().GetAccountLocalCache().IsEnabled() {
		return
	}

	// Optional: enforce max items (best-effort). If MaxItems==0 => unlimited.
	if m.maxItems > 0 && m.cache.Len() >= m.maxItems {
		// Best-effort: do nothing; cache will naturally rotate via TTL.
		// We keep it simple to avoid adding LRU complexity.
	}

	key := m.makeKey(username, protocol, oidcClientID)

	m.cache.Set(key, account, m.ttl)
}

// Purge removes all cached account mappings for the given username.
func (m *Manager) Purge(username string) {
	if m == nil || m.cache == nil {
		return
	}

	m.cache.DeleteByPrefix(username + "|")
}
