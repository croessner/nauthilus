package localcache

import (
	"hash/fnv"
	"sync"
	"time"
)

// ShardedCache is a cache that is split into multiple shards to reduce mutex contention
// Each shard has its own mutex, allowing for better concurrency
type ShardedCache struct {
	shards    []*cacheShard
	numShards int
}

// cacheShard represents a single shard of the cache
type cacheShard struct {
	cache map[string]bool // username -> authenticated
	mutex sync.RWMutex
}

// UserAuthCache is a cache for authentication results
// It stores whether a user has been successfully authenticated
// It can be used by both LDAP and Lua backends
type UserAuthCache struct {
	shardedCache *ShardedCache
}

// AuthCache is a global cache instance used to store and manage user authentication states efficiently.
var AuthCache = NewUserAuthCache()

// NewShardedCache creates a new sharded cache with the specified number of shards
func NewShardedCache(numShards int) *ShardedCache {
	shards := make([]*cacheShard, numShards)
	for i := 0; i < numShards; i++ {
		shards[i] = &cacheShard{
			cache: make(map[string]bool),
		}
	}

	return &ShardedCache{
		shards:    shards,
		numShards: numShards,
	}
}

// getShard returns the shard for the given key
func (sc *ShardedCache) getShard(key string) *cacheShard {
	// Use FNV hash to determine the shard
	h := fnv.New32a()
	h.Write([]byte(key))

	return sc.shards[h.Sum32()%uint32(sc.numShards)]
}

// NewUserAuthCache creates a new UserAuthCache
func NewUserAuthCache() *UserAuthCache {
	// Use 32 shards as a reasonable default for most systems
	// This can be adjusted based on the number of CPU cores and expected load
	return &UserAuthCache{
		shardedCache: NewShardedCache(32),
	}
}

// Set adds or updates an entry in the cache
func (c *UserAuthCache) Set(username string, authenticated bool) {
	shard := c.shardedCache.getShard(username)

	shard.mutex.Lock()
	shard.cache[username] = authenticated
	shard.mutex.Unlock()

	// Also store in the main LocalCache with a TTL
	LocalCache.Set(username, authenticated, 1*time.Hour)
}

// Get retrieves an entry from the cache
// Returns the authentication status and whether the entry was found
func (c *UserAuthCache) Get(username string) (bool, bool) {
	shard := c.shardedCache.getShard(username)

	// First try the in-memory cache
	shard.mutex.RLock()
	authenticated, found := shard.cache[username]
	shard.mutex.RUnlock()

	if found {
		return authenticated, true
	}

	// Then try the main LocalCache
	if value, found := LocalCache.Get(username); found {
		if authenticated, ok := value.(bool); ok {
			// Update our in-memory cache
			shard.mutex.Lock()
			shard.cache[username] = authenticated
			shard.mutex.Unlock()

			return authenticated, true
		}
	}

	return false, false
}

// Delete removes an entry from the cache
func (c *UserAuthCache) Delete(username string) {
	shard := c.shardedCache.getShard(username)

	shard.mutex.Lock()
	delete(shard.cache, username)
	shard.mutex.Unlock()

	LocalCache.Delete(username)
}

// Clear removes all entries from the cache
func (c *UserAuthCache) Clear() {
	for _, shard := range c.shardedCache.shards {
		shard.mutex.Lock()
		shard.cache = make(map[string]bool)
		shard.mutex.Unlock()
	}
	// We don't clear the main LocalCache as it may contain other data
}

// IsAuthenticated checks if a user is authenticated
// Returns true if the user is in the cache and authenticated
func (c *UserAuthCache) IsAuthenticated(username string) bool {
	authenticated, found := c.Get(username)

	return found && authenticated
}
