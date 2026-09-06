package lualib

import (
	"path/filepath"
	"testing"

	lua "github.com/yuin/gopher-lua"
)

// TestReputationNativeWriterHasNoLuaFallback prevents loading a second writer or registering its removed facts.
func TestReputationNativeWriterHasNoLuaFallback(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	if err := L.DoString(`nauthilus_policy = {register_attribute = function(definition)
  assert(not string.find(definition.id, "geoip_reputation", 1, true), "removed reputation attribute registered")
 end}`); err != nil {
		t.Fatal(err)
	}

	if err := L.DoFile(filepath.Join("..", "lua-plugins.d", "policy", "registry.lua")); err != nil {
		t.Fatal(err)
	}

	if chunk, err := L.LoadFile(filepath.Join("..", "lua-plugins.d", "subject", "geoip_reputation.lua")); err == nil || chunk != nil {
		t.Fatal("legacy Lua reputation writer remains loadable")
	}
}
