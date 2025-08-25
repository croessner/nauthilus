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
