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
	sharedTTLCache     *localcache.MemoryShardedCache
	sharedTTLCacheOnce sync.Once
)

// StartSharedTTLCache initializes the LDAP-scoped shared TTL cache and binds the
// cleanup janitor to the provided context. Calling it multiple times is safe.
func StartSharedTTLCache(ctx context.Context) {
	sharedTTLCacheOnce.Do(func() {
		// Default expiration 5m (per-entry overrides can be shorter/longer),
		// cleanup interval 10m like the previous global default.
		sharedTTLCache = localcache.NewMemoryShardedCache(32, 5*time.Minute, 10*time.Minute)

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
	return sharedTTLCache
}
