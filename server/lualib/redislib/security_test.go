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

package redislib

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestRedisSecurity(t *testing.T) {
	testFile := &config.FileSettings{Server: &config.ServerSection{}}
	secretValue := secret.New("testsecret")

	t.Run("EncryptionEnabled", func(t *testing.T) {
		L := newRedisSecurityLuaState(t, testFile, secretValue)
		runRedisSecurityLua(t, L, `local nr = require("nauthilus_redis"); enabled = nr.redis_is_encryption_enabled("default")`)
		assertLuaGlobal(t, L, "enabled", lua.LTrue)
	})

	t.Run("EncryptionDisabled", func(t *testing.T) {
		L := newRedisSecurityLuaState(t, testFile, secret.Value{})
		runRedisSecurityLua(t, L, `local nr = require("nauthilus_redis"); enabled = nr.redis_is_encryption_enabled("default")`)
		assertLuaGlobal(t, L, "enabled", lua.LFalse)
	})

	t.Run("EncryptDecrypt", func(t *testing.T) {
		L := newRedisSecurityLuaState(t, testFile, secretValue)
		runRedisSecurityLua(t, L, `
			local nr = require("nauthilus_redis")
			local plaintext = "hello world"
			local ciphertext, err = nr.redis_encrypt("default", plaintext)
			if err ~= nil then error(err) end

			local decrypted, err2 = nr.redis_decrypt("default", ciphertext)
			if err2 ~= nil then error(err2) end

			final = decrypted
		`)
		assertLuaGlobalString(t, L, "final", "hello world")
	})
}

// newRedisSecurityLuaState creates a Lua state with a security-aware Redis client.
func newRedisSecurityLuaState(t *testing.T, testFile *config.FileSettings, secretValue secret.Value) *lua.LState {
	t.Helper()

	db, _ := redismock.NewClientMock()
	sm := rediscli.NewSecurityManager(secretValue)
	client := rediscli.NewTestClientWithSecurity(db, sm)

	L := lua.NewState()
	t.Cleanup(L.Close)
	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), testFile, client))

	return L
}

// runRedisSecurityLua executes a Lua security snippet.
func runRedisSecurityLua(t *testing.T, L *lua.LState, script string) {
	t.Helper()

	if err := L.DoString(script); err != nil {
		t.Fatalf("Lua failed: %v", err)
	}
}

// assertLuaGlobal compares a Lua global with an expected Lua value.
func assertLuaGlobal(t *testing.T, L *lua.LState, name string, expected lua.LValue) {
	t.Helper()

	if L.GetGlobal(name) != expected {
		t.Errorf("Expected %s to be %v, got %v", name, expected, L.GetGlobal(name))
	}
}

// assertLuaGlobalString compares a Lua global string value.
func assertLuaGlobalString(t *testing.T, L *lua.LState, name string, expected string) {
	t.Helper()

	if L.GetGlobal(name).String() != expected {
		t.Errorf("Expected %q, got %s", expected, L.GetGlobal(name).String())
	}
}
