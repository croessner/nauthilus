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

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestRedisSecurity(t *testing.T) {
	testFile := &config.FileSettings{Server: &config.ServerSection{}}

	secret := "testsecret"

	t.Run("EncryptionEnabled", func(t *testing.T) {
		db, _ := redismock.NewClientMock()
		sm := rediscli.NewSecurityManager(secret)
		client := rediscli.NewTestClientWithSecurity(db, sm)

		L := lua.NewState()
		defer L.Close()
		L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), testFile, client))

		err := L.DoString(`local nr = require("nauthilus_redis"); enabled = nr.redis_is_encryption_enabled("default")`)
		if err != nil {
			t.Fatalf("Lua failed: %v", err)
		}
		if L.GetGlobal("enabled") != lua.LTrue {
			t.Error("Expected encryption to be enabled")
		}
	})

	t.Run("EncryptionDisabled", func(t *testing.T) {
		db, _ := redismock.NewClientMock()
		sm := rediscli.NewSecurityManager("")
		client := rediscli.NewTestClientWithSecurity(db, sm)

		L := lua.NewState()
		defer L.Close()
		L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), testFile, client))

		err := L.DoString(`local nr = require("nauthilus_redis"); enabled = nr.redis_is_encryption_enabled("default")`)
		if err != nil {
			t.Fatalf("Lua failed: %v", err)
		}
		if L.GetGlobal("enabled") != lua.LFalse {
			t.Error("Expected encryption to be disabled")
		}
	})

	t.Run("EncryptDecrypt", func(t *testing.T) {
		db, _ := redismock.NewClientMock()
		sm := rediscli.NewSecurityManager(secret)
		client := rediscli.NewTestClientWithSecurity(db, sm)

		L := lua.NewState()
		defer L.Close()
		L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), testFile, client))

		err := L.DoString(`
			local nr = require("nauthilus_redis")
			local plaintext = "hello world"
			local ciphertext, err = nr.redis_encrypt("default", plaintext)
			if err ~= nil then error(err) end
			
			local decrypted, err2 = nr.redis_decrypt("default", ciphertext)
			if err2 ~= nil then error(err2) end
			
			final = decrypted
		`)
		if err != nil {
			t.Fatalf("Lua failed: %v", err)
		}
		if L.GetGlobal("final").String() != "hello world" {
			t.Errorf("Expected 'hello world', got %s", L.GetGlobal("final").String())
		}
	})
}
