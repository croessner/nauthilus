//go:build !redislib_oop

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
	"context"
	"errors"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestRedisLPush(t *testing.T) {
	config.SetTestFile(&config.FileSettings{Server: &config.ServerSection{}})

	tests := []struct {
		name             string
		key              string
		values           []lua.LValue
		expectedResult   lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "LPushSingleValue",
			key:            "testList",
			values:         []lua.LValue{lua.LString("value1")},
			expectedResult: lua.LNumber(1),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectLPush("testList", "value1").SetVal(1)
			},
		},
		{
			name:           "LPushMultipleValues",
			key:            "testList",
			values:         []lua.LValue{lua.LString("value1"), lua.LString("value2"), lua.LString("value3")},
			expectedResult: lua.LNumber(3),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectLPush("testList", "value1", "value2", "value3").SetVal(3)
			},
		},
		{
			name:           "LPushWithError",
			key:            "errorList",
			values:         []lua.LValue{lua.LString("value1")},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectLPush("errorList", "value1").SetErr(errors.New("some error"))
			},
		},
	}

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

			// Set up the Lua code to call redis_lpush with the key and values
			luaCode := `
				local nauthilus_redis = require("nauthilus_redis")
				result, err = nauthilus_redis.redis_lpush("default", key`

			// Add each value as a global variable and append to the Lua code
			for i, val := range tt.values {
				varName := "value" + string(rune('0'+i))
				L.SetGlobal(varName, val)
				luaCode += ", " + varName
			}

			luaCode += ")"

			err := L.DoString(luaCode)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedResult.Type() || lua.LVAsNumber(gotResult) != lua.LVAsNumber(tt.expectedResult) {
				t.Errorf("nauthilus.redis_lpush() gotResult = %v, want %v", gotResult, tt.expectedResult)
			}

			gotErr := L.GetGlobal("err")
			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisRPush(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		values           []lua.LValue
		expectedResult   lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "RPushSingleValue",
			key:            "testList",
			values:         []lua.LValue{lua.LString("value1")},
			expectedResult: lua.LNumber(1),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectRPush("testList", "value1").SetVal(1)
			},
		},
		{
			name:           "RPushMultipleValues",
			key:            "testList",
			values:         []lua.LValue{lua.LString("value1"), lua.LString("value2"), lua.LString("value3")},
			expectedResult: lua.LNumber(3),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectRPush("testList", "value1", "value2", "value3").SetVal(3)
			},
		},
		{
			name:           "RPushWithError",
			key:            "errorList",
			values:         []lua.LValue{lua.LString("value1")},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectRPush("errorList", "value1").SetErr(errors.New("some error"))
			},
		},
	}

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

			// Set up the Lua code to call redis_rpush with the key and values
			luaCode := `
				local nauthilus_redis = require("nauthilus_redis")
				result, err = nauthilus_redis.redis_rpush("default", key`

			// Add each value as a global variable and append to the Lua code
			for i, val := range tt.values {
				varName := "value" + string(rune('0'+i))
				L.SetGlobal(varName, val)
				luaCode += ", " + varName
			}

			luaCode += ")"

			err := L.DoString(luaCode)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedResult.Type() || lua.LVAsNumber(gotResult) != lua.LVAsNumber(tt.expectedResult) {
				t.Errorf("nauthilus.redis_rpush() gotResult = %v, want %v", gotResult, tt.expectedResult)
			}

			gotErr := L.GetGlobal("err")
			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisLPop(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		expectedResult   lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "LPopExistingKey",
			key:            "testList",
			expectedResult: lua.LString("value1"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectLPop("testList").SetVal("value1")
			},
		},
		{
			name:           "LPopEmptyList",
			key:            "emptyList",
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("redis: nil"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectLPop("emptyList").RedisNil()
			},
		},
		{
			name:           "LPopWithError",
			key:            "errorList",
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectLPop("errorList").SetErr(errors.New("some error"))
			},
		},
	}

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

			err := L.DoString(`
				local nauthilus_redis = require("nauthilus_redis")
				result, err = nauthilus_redis.redis_lpop("default", key)
			`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedResult.Type() || gotResult.String() != tt.expectedResult.String() {
				t.Errorf("nauthilus.redis_lpop() gotResult = %v, want %v", gotResult, tt.expectedResult)
			}

			gotErr := L.GetGlobal("err")
			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisRPop(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		expectedResult   lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "RPopExistingKey",
			key:            "testList",
			expectedResult: lua.LString("value1"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectRPop("testList").SetVal("value1")
			},
		},
		{
			name:           "RPopEmptyList",
			key:            "emptyList",
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("redis: nil"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectRPop("emptyList").RedisNil()
			},
		},
		{
			name:           "RPopWithError",
			key:            "errorList",
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectRPop("errorList").SetErr(errors.New("some error"))
			},
		},
	}

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

			err := L.DoString(`
				local nauthilus_redis = require("nauthilus_redis")
				result, err = nauthilus_redis.redis_rpop("default", key)
			`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedResult.Type() || gotResult.String() != tt.expectedResult.String() {
				t.Errorf("nauthilus.redis_rpop() gotResult = %v, want %v", gotResult, tt.expectedResult)
			}

			gotErr := L.GetGlobal("err")
			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisLRange(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		start            int64
		stop             int64
		expectedResult   []string
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "LRangeFullList",
			key:            "testList",
			start:          0,
			stop:           -1,
			expectedResult: []string{"value1", "value2", "value3"},
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectLRange("testList", 0, -1).SetVal([]string{"value1", "value2", "value3"})
			},
		},
		{
			name:           "LRangePartialList",
			key:            "testList",
			start:          0,
			stop:           1,
			expectedResult: []string{"value1", "value2"},
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectLRange("testList", 0, 1).SetVal([]string{"value1", "value2"})
			},
		},
		{
			name:           "LRangeEmptyList",
			key:            "emptyList",
			start:          0,
			stop:           -1,
			expectedResult: []string{},
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectLRange("emptyList", 0, -1).SetVal([]string{})
			},
		},
		{
			name:           "LRangeWithError",
			key:            "errorList",
			start:          0,
			stop:           -1,
			expectedResult: nil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectLRange("errorList", 0, -1).SetErr(errors.New("some error"))
			},
		},
	}

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
			L.SetGlobal("start", lua.LNumber(tt.start))
			L.SetGlobal("stop", lua.LNumber(tt.stop))

			err := L.DoString(`
				local nauthilus_redis = require("nauthilus_redis")
				result, err = nauthilus_redis.redis_lrange("default", key, start, stop)
			`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			gotErr := L.GetGlobal("err")

			if tt.expectedErr == lua.LNil {
				if gotResult.Type() != lua.LTTable {
					t.Errorf("Expected table result, got %v", gotResult.Type())
				} else {
					expectedTable := createLuaTable(tt.expectedResult)
					if !luaTablesAreEqual(gotResult.(*lua.LTable), expectedTable) {
						t.Errorf("nauthilus.redis_lrange() gotResult = %v, want %v", gotResult, expectedTable)
					}
				}
			}

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisLLen(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		expectedResult   lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "LLenExistingList",
			key:            "testList",
			expectedResult: lua.LNumber(3),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectLLen("testList").SetVal(3)
			},
		},
		{
			name:           "LLenEmptyList",
			key:            "emptyList",
			expectedResult: lua.LNumber(0),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectLLen("emptyList").SetVal(0)
			},
		},
		{
			name:           "LLenWithError",
			key:            "errorList",
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectLLen("errorList").SetErr(errors.New("some error"))
			},
		},
	}

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

			err := L.DoString(`
				local nauthilus_redis = require("nauthilus_redis")
				result, err = nauthilus_redis.redis_llen("default", key)
			`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedResult.Type() || lua.LVAsNumber(gotResult) != lua.LVAsNumber(tt.expectedResult) {
				t.Errorf("nauthilus.redis_llen() gotResult = %v, want %v", gotResult, tt.expectedResult)
			}

			gotErr := L.GetGlobal("err")
			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}
