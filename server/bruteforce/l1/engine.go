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

package l1

import (
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/localcache"
)

// L1Decision captures a local decision result.
type L1Decision struct {
	Rule    string
	Reason  string
	Allowed bool
	Blocked bool
}

// L1Reputation captures local reputation data for an IP.
type L1Reputation struct {
	Positive int64
	Negative int64
}

// Engine is a dedicated L1 decision engine using an in-memory micro-cache.
type Engine struct {
	cache *localcache.Cache
}

var (
	l1EngineOnce sync.Once
	l1Engine     *Engine
)

// GetEngine returns the singleton instance of the L1 decision engine.
func GetEngine() *Engine {
	l1EngineOnce.Do(func() {
		// Default TTL for micro-decisions is 300ms.
		// Cleanup happens at the same interval.
		ttl := 300 * time.Millisecond
		l1Engine = &Engine{
			cache: localcache.NewCache(ttl, ttl),
		}
	})

	return l1Engine
}

// Get retrieves a decision from the L1 cache for the given key.
func (e *Engine) Get(key string) (L1Decision, bool) {
	if e == nil || e.cache == nil {
		return L1Decision{}, false
	}

	val, ok := e.cache.Get(key)
	if !ok {
		return L1Decision{}, false
	}

	dec, ok := val.(L1Decision)
	return dec, ok
}

// Set stores a decision in the L1 cache for the given key with a specific TTL.
// If ttl is 0, the cache's default TTL is used.
func (e *Engine) Set(key string, decision L1Decision, ttl time.Duration) {
	if e == nil || e.cache == nil {
		return
	}

	e.cache.Set(key, decision, ttl)
}

// GetReputation retrieves reputation data from the L1 cache for the given key.
func (e *Engine) GetReputation(key string) (L1Reputation, bool) {
	if e == nil || e.cache == nil {
		return L1Reputation{}, false
	}

	val, ok := e.cache.Get(key)
	if !ok {
		return L1Reputation{}, false
	}

	rep, ok := val.(L1Reputation)
	return rep, ok
}

// SetReputation stores reputation data in the L1 cache for the given key with a specific TTL.
func (e *Engine) SetReputation(key string, reputation L1Reputation, ttl time.Duration) {
	if e == nil || e.cache == nil {
		return
	}

	e.cache.Set(key, reputation, ttl)
}

// KeyNetwork generates a key for a network-based L1 decision.
func KeyNetwork(network string) string {
	return "net:" + network
}

// KeyBurst generates a key for a user/burst-based L1 decision.
func KeyBurst(burstKey string) string {
	return "bfdec:" + burstKey
}

// KeyWhitelist generates a key for an IP-based whitelist L1 decision.
func KeyWhitelist(ip string) string {
	return "wl:" + ip
}

// KeySoftWhitelist generates a key for a user+IP-based soft whitelist L1 decision.
func KeySoftWhitelist(user, ip string) string {
	return "swl:" + user + ":" + ip
}

// KeyReputation generates a key for an IP-based reputation L1 decision.
func KeyReputation(ip string) string {
	return "rep:" + ip
}

// Clear removes all items from the L1 cache.
func (e *Engine) Clear() {
	if e == nil || e.cache == nil {
		return
	}

	// We use localcache.NewCache to replace the internal cache as a quick clear.
	// Since it's for testing and micro-caching, this is acceptable.
	e.cache = localcache.NewCache(300*time.Millisecond, 300*time.Millisecond)
}
