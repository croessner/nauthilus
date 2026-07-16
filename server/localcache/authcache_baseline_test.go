// Copyright (C) 2026 Christian Rößner
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
	"strconv"
	"sync"
	"testing"
)

func TestUserAuthCacheUsesOnlyPrivatePositiveStore(t *testing.T) {
	const username = "baseline-user-auth@example.test"

	cache := NewUserAuthCache()
	defer cache.shardedCache.Stop()

	LocalCache.Delete(username)
	defer LocalCache.Delete(username)

	cache.Set(username, true)
	cache.shardedCache.Delete(username)

	if authenticated, found := cache.Get(username); found || authenticated {
		t.Fatalf("cross-cache fallback returned (%v, %v), want a private-store miss", authenticated, found)
	}
}

func TestUserAuthCacheRejectsNegativeEntries(t *testing.T) {
	cache := NewUserAuthCache()
	defer cache.Close()

	cache.Set("positive@example.test", true)
	cache.Set("positive@example.test", false)

	if authenticated, found := cache.Get("positive@example.test"); found || authenticated {
		t.Fatalf("negative entry returned (%v, %v)", authenticated, found)
	}
}

func TestUserAuthCacheClearPreservesLifecycle(t *testing.T) {
	cache := NewUserAuthCache()
	storage := cache.shardedCache
	cache.Set("clear@example.test", true)
	cache.Clear()

	if cache.shardedCache != storage {
		t.Fatal("Clear replaced the lifecycle-owning storage")
	}

	if _, found := cache.Get("clear@example.test"); found {
		t.Fatal("cleared value survived")
	}

	cache.Close()
	cache.Close()
}

func TestUserAuthCacheConcurrentPositiveLifecycle(_ *testing.T) {
	cache := NewUserAuthCache()
	defer cache.Close()

	start := make(chan struct{})

	var workers sync.WaitGroup

	for worker := range 8 {
		workers.Add(1)
		go func(id int) {
			defer workers.Done()

			<-start

			for iteration := range 100 {
				key := "user-" + strconv.Itoa((id+iteration)%16)
				cache.Set(key, true)
				cache.Get(key)

				if iteration%3 == 0 {
					cache.Delete(key)
				}

				if iteration%31 == 0 {
					cache.Clear()
				}
			}
		}(worker)
	}

	close(start)
	workers.Wait()
}
