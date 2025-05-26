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
	"time"
)

// UserAuthCache is a cache for authentication results
// It stores whether a user has been successfully authenticated
// It can be used by both LDAP and Lua backends
type UserAuthCache struct {
	shardedCache *MemoryShardedCache
}

// AuthCache is a global cache instance used to store and manage user authentication states efficiently.
var AuthCache = NewUserAuthCache()

// NewUserAuthCache creates a new UserAuthCache
func NewUserAuthCache() *UserAuthCache {
	// Use 32 shards as a reasonable default for most systems
	// This can be adjusted based on the number of CPU cores and expected load
	return &UserAuthCache{
		shardedCache: NewMemoryShardedCache(32, 1*time.Hour, 10*time.Minute),
	}
}

// Set adds or updates an entry in the cache
func (c *UserAuthCache) Set(username string, authenticated bool) {
	// Store in the sharded cache
	c.shardedCache.Set(username, authenticated, 1*time.Hour)

	// Also store in the main LocalCache with a TTL
	LocalCache.Set(username, authenticated, 1*time.Hour)
}

// Get retrieves an entry from the cache
// Returns the authentication status and whether the entry was found
func (c *UserAuthCache) Get(username string) (bool, bool) {
	// First try the sharded cache
	if value, found := c.shardedCache.Get(username); found {
		if authenticated, ok := value.(bool); ok {
			return authenticated, true
		}
	}

	// Then try the main LocalCache
	if value, found := LocalCache.Get(username); found {
		if authenticated, ok := value.(bool); ok {
			// Update our sharded cache
			c.shardedCache.Set(username, authenticated, 1*time.Hour)
			return authenticated, true
		}
	}

	return false, false
}

// Delete removes an entry from the cache
func (c *UserAuthCache) Delete(username string) {
	// Delete from the sharded cache
	c.shardedCache.Delete(username)

	// Also delete from the main LocalCache
	LocalCache.Delete(username)
}

// Clear removes all entries from the cache
func (c *UserAuthCache) Clear() {
	// Create a new sharded cache to replace the current one
	c.shardedCache = NewMemoryShardedCache(32, 1*time.Hour, 10*time.Minute)
	// We don't clear the main LocalCache as it may contain other data
}

// IsAuthenticated checks if a user is authenticated
// Returns true if the user is in the cache and authenticated
func (c *UserAuthCache) IsAuthenticated(username string) bool {
	authenticated, found := c.Get(username)

	return found && authenticated
}
