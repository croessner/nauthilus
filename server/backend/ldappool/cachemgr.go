package ldappool

import (
	"context"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/localcache"
)

// sharedTTLCache holds the LDAP-scoped shared TTL cache. It is created when the
// LDAP main worker starts and stopped when that worker's context is canceled.
var (
	sharedTTLCache     *localcache.Cache
	sharedTTLCacheOnce sync.Once
)

// StartSharedTTLCache initializes the LDAP-scoped shared TTL cache and binds the
// cleanup janitor to the provided context. Calling it multiple times is safe.
func StartSharedTTLCache(ctx context.Context) {
	sharedTTLCacheOnce.Do(func() {
		// Default expiration 5m (per-entry overrides can be shorter/longer),
		// cleanup interval 10m like the previous global default.
		sharedTTLCache = localcache.NewCache(5*time.Minute, 10*time.Minute)

		// Stop janitor when context is done
		go func() {
			<-ctx.Done()
			if sharedTTLCache != nil {
				sharedTTLCache.Stop()
			}
		}()
	})
}

// getSharedTTL returns the LDAP-scoped shared TTL cache. Caller should have
// ensured StartSharedTTLCache was called earlier from the worker.
func getSharedTTL() *localcache.MemoryShardedCache {
	if sharedTTLCache == nil {
		return nil
	}

	return sharedTTLCache.MemoryShardedCache
}
