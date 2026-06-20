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

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestRedisLPush(t *testing.T) {
	config.SetTestFile(&config.FileSettings{Server: &config.ServerSection{}})

	runMultiValueRedisTests(t, "redis_lpush", listPushCases(
		"LPush",
		func(mock redismock.ClientMock) {
			mock.ExpectLPush("testList", "value1").SetVal(1)
		},
		func(mock redismock.ClientMock) {
			mock.ExpectLPush("testList", "value1", "value2", "value3").SetVal(3)
		},
		func(mock redismock.ClientMock) {
			mock.ExpectLPush("errorList", "value1").SetErr(errors.New("some error"))
		},
	))
}

func TestRedisRPush(t *testing.T) {
	runMultiValueRedisTests(t, "redis_rpush", listPushCases(
		"RPush",
		func(mock redismock.ClientMock) {
			mock.ExpectRPush("testList", "value1").SetVal(1)
		},
		func(mock redismock.ClientMock) {
			mock.ExpectRPush("testList", "value1", "value2", "value3").SetVal(3)
		},
		func(mock redismock.ClientMock) {
			mock.ExpectRPush("errorList", "value1").SetErr(errors.New("some error"))
		},
	))
}

func TestRedisLPop(t *testing.T) {
	runSimpleKeyRedisTests(t, "redis_lpop", listPopCases(
		"LPop",
		expectLPopValue,
		expectLPopNil,
		expectLPopError,
	))
}

func TestRedisRPop(t *testing.T) {
	runSimpleKeyRedisTests(t, "redis_rpop", listPopCases(
		"RPop",
		expectRPopValue,
		expectRPopNil,
		expectRPopError,
	))
}

func TestRedisLRange(t *testing.T) {
	runRedisLuaCommandTests(t, "redis_lrange", redisLRangeLuaCode(), redisLRangeCases())
}

// redisLRangeLuaCode returns the Lua script used by Redis LRANGE cases.
func redisLRangeLuaCode() string {
	return `
		local nauthilus_redis = require("nauthilus_redis")
		result, err = nauthilus_redis.redis_lrange("default", key, start, stop)
	`
}

// redisLRangeCases returns Redis LRANGE behavior cases.
func redisLRangeCases() []redisLuaCommandTest {
	return []redisLuaCommandTest{
		{
			name: "LRangeFullList",
			luaGlobals: map[string]lua.LValue{
				"key":   lua.LString("testList"),
				"start": lua.LNumber(0),
				"stop":  lua.LNumber(-1),
			},
			expectedResult: createLuaTable([]string{"value1", "value2", "value3"}),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectLRange("testList", 0, -1).SetVal([]string{"value1", "value2", "value3"})
			},
		},
		{
			name: "LRangePartialList",
			luaGlobals: map[string]lua.LValue{
				"key":   lua.LString("testList"),
				"start": lua.LNumber(0),
				"stop":  lua.LNumber(1),
			},
			expectedResult: createLuaTable([]string{"value1", "value2"}),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectLRange("testList", 0, 1).SetVal([]string{"value1", "value2"})
			},
		},
		{
			name: "LRangeEmptyList",
			luaGlobals: map[string]lua.LValue{
				"key":   lua.LString("emptyList"),
				"start": lua.LNumber(0),
				"stop":  lua.LNumber(-1),
			},
			expectedResult: createLuaTable([]string{}),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectLRange("emptyList", 0, -1).SetVal([]string{})
			},
		},
		{
			name: "LRangeWithError",
			luaGlobals: map[string]lua.LValue{
				"key":   lua.LString("errorList"),
				"start": lua.LNumber(0),
				"stop":  lua.LNumber(-1),
			},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectLRange("errorList", 0, -1).SetErr(errors.New("some error"))
			},
		},
	}
}

func TestRedisLLen(t *testing.T) {
	runRedisLuaCommandTests(t, "redis_llen", `
		local nauthilus_redis = require("nauthilus_redis")
		result, err = nauthilus_redis.redis_llen("default", key)
	`, []redisLuaCommandTest{
		{
			name:           "LLenExistingList",
			luaGlobals:     map[string]lua.LValue{"key": lua.LString("testList")},
			expectedResult: lua.LNumber(3),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectLLen("testList").SetVal(3)
			},
		},
		{
			name:           "LLenEmptyList",
			luaGlobals:     map[string]lua.LValue{"key": lua.LString("emptyList")},
			expectedResult: lua.LNumber(0),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectLLen("emptyList").SetVal(0)
			},
		},
		{
			name:           "LLenWithError",
			luaGlobals:     map[string]lua.LValue{"key": lua.LString("errorList")},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectLLen("errorList").SetErr(errors.New("some error"))
			},
		},
	})
}

// listPushCases builds shared list push cases for left and right push commands.
func listPushCases(
	prefix string,
	prepareSingle func(redismock.ClientMock),
	prepareMultiple func(redismock.ClientMock),
	prepareError func(redismock.ClientMock),
) []multiValueRedisTest {
	return []multiValueRedisTest{
		{
			name:             prefix + "SingleValue",
			key:              "testList",
			values:           []lua.LValue{lua.LString("value1")},
			expectedResult:   lua.LNumber(1),
			expectedErr:      lua.LNil,
			prepareMockRedis: prepareSingle,
		},
		{
			name:             prefix + "MultipleValues",
			key:              "testList",
			values:           []lua.LValue{lua.LString("value1"), lua.LString("value2"), lua.LString("value3")},
			expectedResult:   lua.LNumber(3),
			expectedErr:      lua.LNil,
			prepareMockRedis: prepareMultiple,
		},
		{
			name:             prefix + "WithError",
			key:              "errorList",
			values:           []lua.LValue{lua.LString("value1")},
			expectedResult:   lua.LNil,
			expectedErr:      lua.LString("some error"),
			prepareMockRedis: prepareError,
		},
	}
}

// listPopCases builds shared list pop cases for left and right pop commands.
func listPopCases(
	prefix string,
	prepareValue func(redismock.ClientMock),
	prepareNil func(redismock.ClientMock),
	prepareError func(redismock.ClientMock),
) []simpleKeyRedisTest {
	return []simpleKeyRedisTest{
		{
			name:             prefix + "ExistingKey",
			key:              "testList",
			expectedResult:   lua.LString("value1"),
			expectedErr:      lua.LNil,
			prepareMockRedis: prepareValue,
		},
		{
			name:             prefix + "EmptyList",
			key:              "emptyList",
			expectedResult:   lua.LNil,
			expectedErr:      lua.LString("redis: nil"),
			prepareMockRedis: prepareNil,
		},
		{
			name:             prefix + "WithError",
			key:              "errorList",
			expectedResult:   lua.LNil,
			expectedErr:      lua.LString("some error"),
			prepareMockRedis: prepareError,
		},
	}
}

// expectLPopValue configures a successful LPOP expectation.
func expectLPopValue(mock redismock.ClientMock) {
	mock.ExpectLPop("testList").SetVal("value1")
}

// expectLPopNil configures a nil LPOP expectation.
func expectLPopNil(mock redismock.ClientMock) {
	mock.ExpectLPop("emptyList").RedisNil()
}

// expectLPopError configures a failing LPOP expectation.
func expectLPopError(mock redismock.ClientMock) {
	mock.ExpectLPop("errorList").SetErr(errors.New("some error"))
}

// expectRPopValue configures a successful RPOP expectation.
func expectRPopValue(mock redismock.ClientMock) {
	mock.ExpectRPop("testList").SetVal("value1")
}

// expectRPopNil configures a nil RPOP expectation.
func expectRPopNil(mock redismock.ClientMock) {
	mock.ExpectRPop("emptyList").RedisNil()
}

// expectRPopError configures a failing RPOP expectation.
func expectRPopError(mock redismock.ClientMock) {
	mock.ExpectRPop("errorList").SetErr(errors.New("some error"))
}
