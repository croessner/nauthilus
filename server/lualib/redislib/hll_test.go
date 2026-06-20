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
	"errors"
	"testing"

	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestRedisPFAdd(t *testing.T) {
	runHLLRedisTests(t, "redis_pfadd", []hllRedisTest{
		{
			name:    "AddNewElements",
			luaCode: `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_pfadd("default", key, value1, value2)`,
			luaGlobals: map[string]lua.LValue{
				"key":    lua.LString("hll:1"),
				"value1": lua.LString("a"),
				"value2": lua.LString("b"),
			},
			expectedResult: lua.LNumber(1),
			expectedErr:    lua.LNil,
			setupMock: func(m redismock.ClientMock) {
				m.ExpectPFAdd("hll:1", []any{"a", "b"}).SetVal(1)
			},
		},
		{
			name:    "NoChange",
			luaCode: `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_pfadd("default", key, value1)`,
			luaGlobals: map[string]lua.LValue{
				"key":    lua.LString("hll:1"),
				"value1": lua.LString("a"),
			},
			expectedResult: lua.LNumber(0),
			expectedErr:    lua.LNil,
			setupMock: func(m redismock.ClientMock) {
				m.ExpectPFAdd("hll:1", []any{"a"}).SetVal(0)
			},
		},
		{
			name:    "WithError",
			luaCode: `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_pfadd("default", key, value1)`,
			luaGlobals: map[string]lua.LValue{
				"key":    lua.LString("hll:1"),
				"value1": lua.LString("x"),
			},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			setupMock: func(m redismock.ClientMock) {
				m.ExpectPFAdd("hll:1", []any{"x"}).SetErr(errors.New("some error"))
			},
		},
	})
}

func TestRedisPFCount(t *testing.T) {
	runHLLRedisTests(t, "redis_pfcount", []hllRedisTest{
		{
			name:    "SingleKey",
			luaCode: `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_pfcount("default", key1)`,
			luaGlobals: map[string]lua.LValue{
				"key1": lua.LString("hll:1"),
			},
			expectedResult: lua.LNumber(2),
			expectedErr:    lua.LNil,
			setupMock: func(m redismock.ClientMock) {
				m.ExpectPFCount("hll:1").SetVal(2)
			},
		},
		{
			name:    "MultipleKeys",
			luaCode: `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_pfcount("default", key1, key2)`,
			luaGlobals: map[string]lua.LValue{
				"key1": lua.LString("hll:1"),
				"key2": lua.LString("hll:2"),
			},
			expectedResult: lua.LNumber(5),
			expectedErr:    lua.LNil,
			setupMock: func(m redismock.ClientMock) {
				m.ExpectPFCount("hll:1", "hll:2").SetVal(5)
			},
		},
		{
			name:    "WithError",
			luaCode: `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_pfcount("default", key1)`,
			luaGlobals: map[string]lua.LValue{
				"key1": lua.LString("hll:1"),
			},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			setupMock: func(m redismock.ClientMock) {
				m.ExpectPFCount("hll:1").SetErr(errors.New("some error"))
			},
		},
	})
}

func TestRedisPFMerge(t *testing.T) {
	runHLLRedisTests(t, "redis_pfmerge", []hllRedisTest{
		{
			name:    "MergeTwo",
			luaCode: `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_pfmerge("default", dest, source1, source2)`,
			luaGlobals: map[string]lua.LValue{
				"dest":    lua.LString("hll:dst"),
				"source1": lua.LString("hll:1"),
				"source2": lua.LString("hll:2"),
			},
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
			setupMock: func(m redismock.ClientMock) {
				m.ExpectPFMerge("hll:dst", []string{"hll:1", "hll:2"}...).SetVal("OK")
			},
		},
		{
			name:    "WithError",
			luaCode: `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_pfmerge("default", dest, source1)`,
			luaGlobals: map[string]lua.LValue{
				"dest":    lua.LString("hll:dst"),
				"source1": lua.LString("hll:1"),
			},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			setupMock: func(m redismock.ClientMock) {
				m.ExpectPFMerge("hll:dst", []string{"hll:1"}...).SetErr(errors.New("some error"))
			},
		},
	})
}

type hllRedisTest struct {
	name           string
	luaCode        string
	luaGlobals     map[string]lua.LValue
	expectedResult lua.LValue
	expectedErr    lua.LValue
	setupMock      func(m redismock.ClientMock)
}

// runHLLRedisTests runs HyperLogLog command cases with shared Lua setup.
func runHLLRedisTests(t *testing.T, cmdName string, tests []hllRedisTest) {
	t.Helper()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			L, mock, _ := newRedisLuaCommandState(t)
			tt.setupMock(mock)

			for name, value := range tt.luaGlobals {
				L.SetGlobal(name, value)
			}

			if err := L.DoString(tt.luaCode); err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			assertLuaValueEqual(t, cmdName, L.GetGlobal("result"), tt.expectedResult)
			checkLuaError(t, L.GetGlobal("err"), tt.expectedErr)
			mock.ClearExpect()
		})
	}
}
