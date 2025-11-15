package lualib

import (
	"testing"

	lua "github.com/yuin/gopher-lua"
)

func setupCacheModule(L *lua.LState) {
	L.PreloadModule("nauthilus_cache", LoaderModCache)
}

func TestLuaCacheSetGetDelete(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	setupCacheModule(L)

	script := `
	  local cache = require("nauthilus_cache")
	  cache.cache_set("foo", "bar", 0)
	  local v = cache.cache_get("foo")
	  return v
	`
	if err := L.DoString(script); err != nil {
		t.Fatalf("lua error: %v", err)
	}
	ret := L.Get(-1)
	if ret.Type() != lua.LTString || ret.String() != "bar" {
		t.Fatalf("unexpected return: %v", ret)
	}

	L.Pop(1)
	// delete and get nil
	script2 := `
	  local cache = require("nauthilus_cache")
	  cache.cache_delete("foo")
	  local v = cache.cache_get("foo")
	  return v
	`
	if err := L.DoString(script2); err != nil {
		t.Fatalf("lua error: %v", err)
	}
	if L.Get(-1) != lua.LNil {
		t.Fatalf("expected nil, got %v", L.Get(-1))
	}
}

func TestLuaCacheTTLAndUpdate(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	setupCacheModule(L)

	script := `
	  local cache = require("nauthilus_cache")
	  cache.cache_set("k", 1, 1)
	  local v = cache.cache_get("k")
	  return v
	`
	if err := L.DoString(script); err != nil {
		t.Fatalf("lua err: %v", err)
	}
	if L.Get(-1).(lua.LNumber) != lua.LNumber(1) {
		t.Fatalf("expected 1")
	}
	L.Pop(1)

	// update
	script2 := `
	  local cache = require("nauthilus_cache")
	  local nv = cache.cache_update("k", function(old) return (old or 0) + 5 end)
	  return nv
	`
	if err := L.DoString(script2); err != nil {
		t.Fatalf("lua err: %v", err)
	}
	if L.Get(-1).(lua.LNumber) != lua.LNumber(6) {
		t.Fatalf("expected 6, got %v", L.Get(-1))
	}
}

func TestLuaCachePushPopAll(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	setupCacheModule(L)

	script := `
	  local cache = require("nauthilus_cache")
	  cache.cache_push("arr", "a")
	  cache.cache_push("arr", "b")
	  local list = cache.cache_pop_all("arr")
	  return list
	`
	if err := L.DoString(script); err != nil {
		t.Fatalf("lua err: %v", err)
	}
	tbl, ok := L.Get(-1).(*lua.LTable)
	if !ok {
		t.Fatalf("expected table")
	}
	if tbl.Len() != 2 {
		t.Fatalf("expected 2, got %d", tbl.Len())
	}
}
