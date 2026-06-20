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

package redislib

import (
	"errors"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestRedisGet(t *testing.T) {
	runRedisLuaCommandTests(t, "redis_get", redisGetLuaCode(), redisGetCases())
}

// redisGetLuaCode returns the Lua script used by Redis GET cases.
func redisGetLuaCode() string {
	return `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_get("default", key, valueType)`
}

// redisGetCases returns Redis GET behavior cases.
func redisGetCases() []redisLuaCommandTest {
	return []redisLuaCommandTest{
		{
			name: "GetStringValue",
			luaGlobals: map[string]lua.LValue{
				"key":       lua.LString("testKey"),
				"valueType": lua.LString(definitions.TypeString),
			},
			expectedResult: lua.LString("testValue"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectGet("testKey").SetVal("testValue")
			},
		},
		{
			name: "GetValueWithMissingKey",
			luaGlobals: map[string]lua.LValue{
				"key":       lua.LString("missingKey"),
				"valueType": lua.LString(definitions.TypeString),
			},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("redis: nil"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectGet("missingKey").RedisNil()
			},
		},
	}
}

func TestRedisSet(t *testing.T) {
	runRedisLuaCommandTests(t, "redis_set", redisSetLuaCode(), redisSetCases())
}

// redisSetLuaCode returns the Lua script used by Redis SET cases.
func redisSetLuaCode() string {
	return `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_set("default", key, value, expiration)`
}

// redisSetCases returns Redis SET behavior cases.
func redisSetCases() []redisLuaCommandTest {
	return []redisLuaCommandTest{
		{
			name: "SetKeyValue",
			luaGlobals: map[string]lua.LValue{
				"key":        lua.LString("testKey"),
				"value":      lua.LString("testValue"),
				"expiration": lua.LNumber(30),
			},
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectSet("testKey", "testValue", time.Duration(30)*time.Second).SetVal("OK")
			},
		},
		{
			name: "SetKeyValueWithoutExpiration",
			luaGlobals: map[string]lua.LValue{
				"key":        lua.LString("anotherKey"),
				"value":      lua.LString("anotherValue"),
				"expiration": lua.LNumber(0),
			},
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectSet("anotherKey", "anotherValue", 0).SetVal("OK")
			},
		},
		{
			name: "SetKeyValueWithError",
			luaGlobals: map[string]lua.LValue{
				"key":        lua.LString("testKey"),
				"value":      lua.LString("testValue"),
				"expiration": lua.LNumber(30),
			},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectSet("testKey", "testValue", time.Duration(30)*time.Second).SetErr(errors.New("some error"))
			},
		},
	}
}

func TestRedisExpire(t *testing.T) {
	runRedisLuaCommandTests(t, "redis_expire", redisExpireLuaCode(), redisExpireCases())
}

// redisExpireLuaCode returns the Lua script used by Redis EXPIRE cases.
func redisExpireLuaCode() string {
	return `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_expire("default", key, expiration)`
}

// redisExpireCases returns Redis EXPIRE behavior cases.
func redisExpireCases() []redisLuaCommandTest {
	return []redisLuaCommandTest{
		{
			name: "ExpireWithExistingKey",
			luaGlobals: map[string]lua.LValue{
				"key":        lua.LString("testKey"),
				"expiration": lua.LNumber(60),
			},
			expectedResult: lua.LTrue,
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectExpire("testKey", time.Duration(60)*time.Second).SetVal(true)
			},
		},
		{
			name: "ExpireWithNonExistingKey",
			luaGlobals: map[string]lua.LValue{
				"key":        lua.LString("missingKey"),
				"expiration": lua.LNumber(30),
			},
			expectedResult: lua.LFalse,
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectExpire("missingKey", time.Duration(30)*time.Second).SetVal(false)
			},
		},
		{
			name: "ExpireWithError",
			luaGlobals: map[string]lua.LValue{
				"key":        lua.LString("keyWithError"),
				"expiration": lua.LNumber(10),
			},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectExpire("keyWithError", time.Duration(10)*time.Second).SetErr(errors.New("some error"))
			},
		},
	}
}

func TestRedisIncr(t *testing.T) {
	runSimpleKeyRedisTests(t, "redis_incr", []simpleKeyRedisTest{
		simpleKeyCase("IncrementNonExistingKey", "testKey", lua.LNumber(1), lua.LNil, expectIncrMissing),
		simpleKeyCase("IncrementExistingKey", "existingKey", lua.LNumber(2), lua.LNil, expectIncrExisting),
		simpleKeyCase("IncrementKeyWithError", "keyWithError", lua.LNil, lua.LString("some error"), expectIncrError),
	})
}

func TestRedisDel(t *testing.T) {
	runSimpleKeyRedisTests(t, "redis_del", []simpleKeyRedisTest{
		simpleKeyCase("DeleteExistingKey", "existingKey", lua.LNumber(1), lua.LNil, expectDelExisting),
		simpleKeyCase("DeleteNonExistingKey", "nonExistingKey", lua.LNumber(0), lua.LNil, expectDelMissing),
		simpleKeyCase("DeleteWithError", "keyWithError", lua.LNil, lua.LString("some error"), expectDelError),
	})
}

// expectIncrMissing configures INCR for a missing key.
func expectIncrMissing(mock redismock.ClientMock) {
	mock.ExpectIncr("testKey").SetVal(1)
}

// expectIncrExisting configures INCR for an existing key.
func expectIncrExisting(mock redismock.ClientMock) {
	mock.ExpectIncr("existingKey").SetVal(2)
}

// expectIncrError configures a failing INCR expectation.
func expectIncrError(mock redismock.ClientMock) {
	mock.ExpectIncr("keyWithError").SetErr(errors.New("some error"))
}

// expectDelExisting configures DEL for an existing key.
func expectDelExisting(mock redismock.ClientMock) {
	mock.ExpectDel("existingKey").SetVal(1)
}

// expectDelMissing configures DEL for a missing key.
func expectDelMissing(mock redismock.ClientMock) {
	mock.ExpectDel("nonExistingKey").SetVal(0)
}

// expectDelError configures a failing DEL expectation.
func expectDelError(mock redismock.ClientMock) {
	mock.ExpectDel("keyWithError").SetErr(errors.New("some error"))
}

func TestRedisRename(t *testing.T) {
	runRedisLuaCommandTests(t, "redis_rename", redisRenameLuaCode(), redisRenameCases())
}

// redisRenameLuaCode returns the Lua script used by Redis RENAME cases.
func redisRenameLuaCode() string {
	return `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_rename("default", oldKey, newKey)`
}

// redisRenameCases returns Redis RENAME behavior cases.
func redisRenameCases() []redisLuaCommandTest {
	return []redisLuaCommandTest{
		{
			name: "RenameExistingKey",
			luaGlobals: map[string]lua.LValue{
				"oldKey": lua.LString("existingKey"),
				"newKey": lua.LString("newKey"),
			},
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectRename("existingKey", "newKey").SetVal("OK")
			},
		},
		{
			name: "RenameNonExistingKey",
			luaGlobals: map[string]lua.LValue{
				"oldKey": lua.LString("nonExistingKey"),
				"newKey": lua.LString("newKey"),
			},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("redis: nil"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectRename("nonExistingKey", "newKey").RedisNil()
			},
		},
		{
			name: "RenameWithError",
			luaGlobals: map[string]lua.LValue{
				"oldKey": lua.LString("keyWithError"),
				"newKey": lua.LString("newKey"),
			},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectRename("keyWithError", "newKey").SetErr(errors.New("some error"))
			},
		},
	}
}

func TestPing(t *testing.T) {
	runRedisLuaCommandTests(t, "redis_ping", redisPingLuaCode(), redisPingCases())
}

// redisPingLuaCode returns the Lua script used by Redis PING cases.
func redisPingLuaCode() string {
	return `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_ping("default")`
}

// redisPingCases returns Redis PING behavior cases.
func redisPingCases() []redisLuaCommandTest {
	return []redisLuaCommandTest{
		{
			name:           "PingWithSuccess",
			expectedResult: lua.LString("PONG"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectPing().SetVal("PONG")
			},
		},
		{
			name:           "PingWithError",
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectPing().SetErr(errors.New("some error"))
			},
		},
	}
}
