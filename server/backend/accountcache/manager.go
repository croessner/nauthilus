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

// Package accountcache provides accountcache functionality.
package accountcache

import (
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/localcache"
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
	return username + accountMappingFieldSeparator + protocol + accountMappingFieldSeparator + oidcClientID
}

// accountMappingFieldSeparator joins the parts of an account-mapping field.
const accountMappingFieldSeparator = "|"

// AccountMappingFieldUsername returns the username that owns an account-mapping field.
//
// The protocol and OIDC client ID are trusted, operator-controlled parts, while the username is chosen by
// the client and may itself contain the separator. The field is therefore split at its last two
// separators, so a username such as "alice|x" never owns fields written for "alice" and vice versa.
func AccountMappingFieldUsername(field string) (string, bool) {
	clientSeparator := strings.LastIndex(field, accountMappingFieldSeparator)
	if clientSeparator < 0 {
		return "", false
	}

	protocolSeparator := strings.LastIndex(field[:clientSeparator], accountMappingFieldSeparator)
	if protocolSeparator < 0 {
		return "", false
	}

	return field[:protocolSeparator], true
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

	// Only set when the local cache is enabled
	if !cfg.GetServer().GetRedis().GetAccountLocalCache().IsEnabled() {
		return
	}

	// Optional: enforce max items (best-effort). If MaxItems==0 => unlimited.
	// Note: if maxItems > 0 and cache is full, we rely on TTL-based rotation
	// rather than adding LRU complexity.

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
