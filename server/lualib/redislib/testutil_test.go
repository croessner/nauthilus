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
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/util"

	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

const (
	luaRequestEnvKey     = "__NAUTH_REQ_ENV"
	luaRuntimeContextKey = "__NAUTH_REQ_RUNTIME_CONTEXT"
)

func bindRedisRuntimeContextForTest(ctx context.Context, L *lua.LState) {
	reqEnv := L.NewTable()
	L.SetGlobal(luaRequestEnvKey, reqEnv)

	userData := L.NewUserData()
	userData.Value = ctx

	L.SetField(reqEnv, luaRuntimeContextKey, userData)
}

// setupRedisLuaTestConfig installs the minimal config required by Lua Redis tests.
func setupRedisLuaTestConfig() *config.FileSettings {
	testFile := &config.FileSettings{Server: &config.ServerSection{}}
	config.SetTestFile(testFile)
	util.SetDefaultConfigFile(testFile)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	return testFile
}

// newRedisLuaCommandState creates a Lua state wired to a redismock-backed Redis client.
func newRedisLuaCommandState(t *testing.T) (*lua.LState, redismock.ClientMock, *redis.Client) {
	t.Helper()

	testFile := setupRedisLuaTestConfig()

	db, mock := redismock.NewClientMock()
	if db == nil || mock == nil {
		t.Fatalf("Failed to create Redis mock client.")
	}

	client := rediscli.NewTestClient(db)
	SetDefaultClient(client)

	L := lua.NewState()
	t.Cleanup(L.Close)

	bindRedisRuntimeContextForTest(context.Background(), L)
	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), testFile, client))
	rediscli.NewTestClient(db)

	return L, mock, db
}

// assertRedisExpectationsAndClear verifies redismock expectations and resets them.
func assertRedisExpectationsAndClear(t *testing.T, mock redismock.ClientMock) {
	t.Helper()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("mock expectations were not met: %v", err)
	}

	mock.ClearExpect()
}

// redisLuaCommandTest defines a command test that uses explicit Lua globals.
type redisLuaCommandTest struct {
	name             string
	luaGlobals       map[string]lua.LValue
	expectedResult   lua.LValue
	expectedErr      lua.LValue
	prepareMockRedis func(mock redismock.ClientMock)
}

// runRedisLuaCommandTests executes Lua Redis command cases with shared setup and assertions.
func runRedisLuaCommandTests(t *testing.T, luaCmd string, luaCode string, tests []redisLuaCommandTest) {
	t.Helper()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			L, mock, _ := newRedisLuaCommandState(t)

			if tt.prepareMockRedis != nil {
				tt.prepareMockRedis(mock)
			}

			for name, value := range tt.luaGlobals {
				L.SetGlobal(name, value)
			}

			if err := L.DoString(luaCode); err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			assertLuaValueEqual(t, luaCmd, gotResult, tt.expectedResult)

			gotErr := L.GetGlobal("err")
			checkLuaError(t, gotErr, tt.expectedErr)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("mock expectations were not met: %v", err)
			}

			mock.ClearExpect()
		})
	}
}

// simpleKeyRedisTest defines a test case for Redis commands that take only a key argument.
type simpleKeyRedisTest struct {
	name             string
	key              string
	expectedResult   lua.LValue
	expectedErr      lua.LValue
	prepareMockRedis func(mock redismock.ClientMock)
}

// simpleKeyCase builds a simple key-based Redis command test case.
func simpleKeyCase(
	name string,
	key string,
	expectedResult lua.LValue,
	expectedErr lua.LValue,
	prepareMockRedis func(redismock.ClientMock),
) simpleKeyRedisTest {
	return simpleKeyRedisTest{
		name:             name,
		key:              key,
		expectedResult:   expectedResult,
		expectedErr:      expectedErr,
		prepareMockRedis: prepareMockRedis,
	}
}

// runSimpleKeyRedisTests runs a table of simple key-based Redis command tests.
// The luaCmd parameter is the Lua function name (e.g. "redis_incr", "redis_del").
func runSimpleKeyRedisTests(t *testing.T, luaCmd string, tests []simpleKeyRedisTest) {
	t.Helper()

	testFile := &config.FileSettings{Server: &config.ServerSection{}}
	config.SetTestFile(testFile)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			L, mock, _ := newRedisLuaCommandState(t)
			L.SetGlobal("key", lua.LString(tt.key))
			tt.prepareMockRedis(mock)

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
			L, mock, _ := newRedisLuaCommandState(t)
			tt.prepareMockRedis(mock)

			L.SetGlobal("key", lua.LString(tt.key))

			var luaCode strings.Builder
			fmt.Fprintf(&luaCode, `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.%s("default", key`,
				luaCmd)

			for i, val := range tt.values {
				varName := fmt.Sprintf("value%d", i)
				L.SetGlobal(varName, val)
				luaCode.WriteString(", " + varName)
			}

			luaCode.WriteString(")")

			if err := L.DoString(luaCode.String()); err != nil {
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

// keyMemberRedisTest defines a test case for Redis commands that take key and member arguments.
type keyMemberRedisTest struct {
	name             string
	key              string
	member           string
	expectedResult   lua.LValue
	expectedErr      lua.LValue
	prepareMockRedis func(mock redismock.ClientMock, key, member string)
}

// runKeyMemberRedisTests runs key/member command tests with the selected Redis handle expression.
func runKeyMemberRedisTests(t *testing.T, luaCmd string, handleExpr string, customHandle bool, tests []keyMemberRedisTest) {
	t.Helper()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			L, mock, db := newRedisLuaCommandState(t)

			if customHandle {
				ud := L.NewUserData()
				ud.Value = db
				L.SetMetatable(ud, L.GetTypeMetatable("redis_client"))
				L.SetGlobal("custom_handle", ud)
			}

			if tt.prepareMockRedis != nil {
				tt.prepareMockRedis(mock, tt.key, tt.member)
			}

			L.SetGlobal("key", lua.LString(tt.key))
			L.SetGlobal("member", lua.LString(tt.member))

			luaCode := fmt.Sprintf(
				`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.%s(%s, key, member)`,
				luaCmd,
				handleExpr,
			)
			if err := L.DoString(luaCode); err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			assertLuaValueEqual(t, luaCmd, gotResult, tt.expectedResult)

			gotErr := L.GetGlobal("err")
			checkLuaError(t, gotErr, tt.expectedErr)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("mock expectations were not met: %v", err)
			}

			mock.ClearExpect()
		})
	}
}

// assertLuaValueEqual compares two Lua values, including table-valued Redis results.
func assertLuaValueEqual(t *testing.T, cmdName string, got, expected lua.LValue) {
	t.Helper()

	if got.Type() == lua.LTTable && expected.Type() == lua.LTTable {
		if !luaTablesAreEqual(got.(*lua.LTable), expected.(*lua.LTable)) {
			t.Errorf("nauthilus.%s() gotResult = %v, want %v", cmdName, got, expected)
		}

		return
	}

	if got.Type() != expected.Type() || got.String() != expected.String() {
		t.Errorf("nauthilus.%s() gotResult = %v, want %v", cmdName, got, expected)
	}
}
