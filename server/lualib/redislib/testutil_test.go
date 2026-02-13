// Copyright (C) 2025 Christian Rößner
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
	"fmt"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/rediscli"

	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

// simpleKeyRedisTest defines a test case for Redis commands that take only a key argument.
type simpleKeyRedisTest struct {
	name             string
	key              string
	expectedResult   lua.LValue
	expectedErr      lua.LValue
	prepareMockRedis func(mock redismock.ClientMock)
}

// runSimpleKeyRedisTests runs a table of simple key-based Redis command tests.
// The luaCmd parameter is the Lua function name (e.g. "redis_incr", "redis_del").
func runSimpleKeyRedisTests(t *testing.T, luaCmd string, tests []simpleKeyRedisTest) {
	t.Helper()

	testFile := &config.FileSettings{Server: &config.ServerSection{}}
	config.SetTestFile(testFile)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock conn.")
			}

			tt.prepareMockRedis(mock)

			client := rediscli.NewTestClient(db)
			SetDefaultClient(client)

			L := lua.NewState()
			defer L.Close()

			L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), testFile, client))
			L.SetGlobal("key", lua.LString(tt.key))

			luaCode := fmt.Sprintf(
				`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.%s("default", key)`,
				luaCmd,
			)

			if err := L.DoString(luaCode); err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			assertLuaValueEqual(t, luaCmd, gotResult, tt.expectedResult)

			gotErr := L.GetGlobal("err")
			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

// multiValueRedisTest defines a test case for Redis commands that take a key and multiple value arguments.
type multiValueRedisTest struct {
	name             string
	key              string
	values           []lua.LValue
	expectedResult   lua.LValue
	expectedErr      lua.LValue
	prepareMockRedis func(mock redismock.ClientMock)
}

// runMultiValueRedisTests runs a table of multi-value Redis command tests.
// The luaCmd parameter is the Lua function name (e.g. "redis_lpush", "redis_sadd").
func runMultiValueRedisTests(t *testing.T, luaCmd string, tests []multiValueRedisTest) {
	t.Helper()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			client := rediscli.NewTestClient(db)
			SetDefaultClient(client)

			L := lua.NewState()
			defer L.Close()

			L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), config.GetFile(), client))
			tt.prepareMockRedis(mock)
			rediscli.NewTestClient(db)

			L.SetGlobal("key", lua.LString(tt.key))

			luaCode := fmt.Sprintf(
				`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.%s("default", key`,
				luaCmd,
			)

			for i, val := range tt.values {
				varName := fmt.Sprintf("value%d", i)
				L.SetGlobal(varName, val)
				luaCode += ", " + varName
			}

			luaCode += ")"

			if err := L.DoString(luaCode); err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			assertLuaValueEqual(t, luaCmd, gotResult, tt.expectedResult)

			gotErr := L.GetGlobal("err")
			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

// assertLuaValueEqual compares two Lua values for equality, supporting both number and string comparison.
func assertLuaValueEqual(t *testing.T, cmdName string, got, expected lua.LValue) {
	t.Helper()

	if got.Type() != expected.Type() || got.String() != expected.String() {
		t.Errorf("nauthilus.%s() gotResult = %v, want %v", cmdName, got, expected)
	}
}
