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
	"testing"
	"time"
)

func TestMemoryShardedCache_SetGetDelete(t *testing.T) {
	sc := NewMemoryShardedCache(8, 0, 0)
	sc.Set("a", "v", 0)
	if v, ok := sc.Get("a"); !ok || v.(string) != "v" {
		t.Fatalf("unexpected get: %v %v", v, ok)
	}
	sc.Delete("a")
	if _, ok := sc.Get("a"); ok {
		t.Fatalf("expected deleted")
	}
}

func TestMemoryShardedCache_TTL(t *testing.T) {
	sc := NewMemoryShardedCache(8, 0, 0)
	sc.Set("k", 123, 300*time.Millisecond)
	if _, ok := sc.Get("k"); !ok {
		t.Fatalf("expected present before ttl")
	}
	time.Sleep(400 * time.Millisecond)
	if _, ok := sc.Get("k"); ok {
		t.Fatalf("expected expired")
	}
}

func TestAuthCacheBasic(t *testing.T) {
	ac := NewUserAuthCache()
	ac.Set("user1", true)
	if ok := ac.IsAuthenticated("user1"); !ok {
		t.Fatalf("user1 should be authenticated")
	}
	ac.Delete("user1")
	if _, found := ac.Get("user1"); found {
		t.Fatalf("user1 should be removed")
	}
}
