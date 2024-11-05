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

	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestRedisGet(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		valueType        string
		expectedVal      lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:        "GetStringValue",
			key:         "testKey",
			valueType:   global.TypeString,
			expectedVal: lua.LString("testValue"),
			expectedErr: lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectGet("testKey").SetVal("testValue")
			},
		},
		{
			name:        "GetValueWithMissingKey",
			key:         "missingKey",
			valueType:   global.TypeString,
			expectedVal: lua.LNil,
			expectedErr: lua.LString("redis: nil"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectGet("missingKey").RedisNil()
			},
		},
	}

	L := lua.NewState()

	L.PreloadModule(global.LuaModRedis, LoaderModRedis)

	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			tt.prepareMockRedis(mock)
			rediscli.ReadHandle = db

			L.SetGlobal("key", lua.LString(tt.key))
			L.SetGlobal("valueType", lua.LString(tt.valueType))

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_get("default", key, valueType)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotVal := L.GetGlobal("result")
			if gotVal.Type() != tt.expectedVal.Type() || gotVal.String() != tt.expectedVal.String() {
				t.Errorf("nauthilus.redis_get() gotVal = %v, want %v", gotVal.String(), tt.expectedVal.String())
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisSet(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		value            lua.LValue
		expiration       int
		expectedResult   lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "SetKeyValue",
			key:            "testKey",
			value:          lua.LString("testValue"),
			expiration:     30,
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectSet("testKey", "testValue", time.Duration(30)*time.Second).SetVal("OK")
			},
		},
		{
			name:           "SetKeyValueWithoutExpiration",
			key:            "anotherKey",
			value:          lua.LString("anotherValue"),
			expiration:     0,
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectSet("anotherKey", "anotherValue", 0).SetVal("OK")
			},
		},
		{
			name:           "SetKeyValueWithError",
			key:            "testKey",
			value:          lua.LString("testValue"),
			expiration:     30,
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectSet("testKey", "testValue", time.Duration(30)*time.Second).SetErr(errors.New("some error"))
			},
		},
	}

	L := lua.NewState()

	L.PreloadModule(global.LuaModRedis, LoaderModRedis)

	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			tt.prepareMockRedis(mock)
			rediscli.WriteHandle = db

			L.SetGlobal("key", lua.LString(tt.key))
			L.SetGlobal("value", tt.value)
			L.SetGlobal("expiration", lua.LNumber(tt.expiration))

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_set("default", key, value, expiration)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedResult.Type() || gotResult.String() != tt.expectedResult.String() {
				t.Errorf("nauthilus.redis_set() gotResult = %v, want %v", gotResult.String(), tt.expectedResult.String())
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisExpire(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		expiration       lua.LNumber
		expectedResult   lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "ExpireWithExistingKey",
			key:            "testKey",
			expiration:     60,
			expectedResult: lua.LTrue,
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectExpire("testKey", time.Duration(60)*time.Second).SetVal(true)
			},
		},
		{
			name:           "ExpireWithNonExistingKey",
			key:            "missingKey",
			expiration:     30,
			expectedResult: lua.LFalse,
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectExpire("missingKey", time.Duration(30)*time.Second).SetVal(false)
			},
		},
		{
			name:           "ExpireWithError",
			key:            "keyWithError",
			expiration:     10,
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectExpire("keyWithError", time.Duration(10)*time.Second).SetErr(errors.New("some error"))
			},
		},
	}

	L := lua.NewState()

	L.PreloadModule(global.LuaModRedis, LoaderModRedis)

	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			tt.prepareMockRedis(mock)
			rediscli.WriteHandle = db

			L.SetGlobal("key", lua.LString(tt.key))
			L.SetGlobal("expiration", tt.expiration)

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_expire("default", key, expiration)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedResult.Type() || gotResult.String() != tt.expectedResult.String() {
				t.Errorf("nauthilus.redis_expire() gotResult = %v, want %v", gotResult.String(), tt.expectedResult.String())
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisIncr(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		expectedResult   lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "IncrementNonExistingKey",
			key:            "testKey",
			expectedResult: lua.LNumber(1),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectIncr("testKey").SetVal(1)
			},
		},
		{
			name:           "IncrementExistingKey",
			key:            "existingKey",
			expectedResult: lua.LNumber(2),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectIncr("existingKey").SetVal(2)
			},
		},
		{
			name:           "IncrementKeyWithError",
			key:            "keyWithError",
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectIncr("keyWithError").SetErr(errors.New("some error"))
			},
		},
	}

	L := lua.NewState()

	L.PreloadModule(global.LuaModRedis, LoaderModRedis)

	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			tt.prepareMockRedis(mock)
			rediscli.WriteHandle = db

			L.SetGlobal("key", lua.LString(tt.key))

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_incr("default", key)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedResult.Type() || lua.LVAsNumber(gotResult) != lua.LVAsNumber(tt.expectedResult) {
				t.Errorf("nauthilus.redis_incr() gotResult = %v, want %v", gotResult, tt.expectedResult)
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisDel(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		expectedResult   lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "DeleteExistingKey",
			key:            "existingKey",
			expectedResult: lua.LNumber(1),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectDel("existingKey").SetVal(1)
			},
		},
		{
			name:           "DeleteNonExistingKey",
			key:            "nonExistingKey",
			expectedResult: lua.LNumber(0),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectDel("nonExistingKey").SetVal(0)
			},
		},
		{
			name:           "DeleteWithError",
			key:            "keyWithError",
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectDel("keyWithError").SetErr(errors.New("some error"))
			},
		},
	}

	L := lua.NewState()

	L.PreloadModule(global.LuaModRedis, LoaderModRedis)

	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			tt.prepareMockRedis(mock)
			rediscli.WriteHandle = db

			L.SetGlobal("key", lua.LString(tt.key))

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_del("default", key)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedResult.Type() || gotResult.String() != tt.expectedResult.String() {
				t.Errorf("nauthilus.redis_del() gotResult = %v, want %v", gotResult.String(), tt.expectedResult.String())
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisRename(t *testing.T) {
	tests := []struct {
		name             string
		oldKey           string
		newKey           string
		expectedResult   lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "RenameExistingKey",
			oldKey:         "existingKey",
			newKey:         "newKey",
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectRename("existingKey", "newKey").SetVal("OK")
			},
		},
		{
			name:           "RenameNonExistingKey",
			oldKey:         "nonExistingKey",
			newKey:         "newKey",
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("redis: nil"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectRename("nonExistingKey", "newKey").RedisNil()
			},
		},
		{
			name:           "RenameWithError",
			oldKey:         "keyWithError",
			newKey:         "newKey",
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectRename("keyWithError", "newKey").SetErr(errors.New("some error"))
			},
		},
	}

	L := lua.NewState()

	L.PreloadModule(global.LuaModRedis, LoaderModRedis)

	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			tt.prepareMockRedis(mock)
			rediscli.WriteHandle = db

			L.SetGlobal("oldKey", lua.LString(tt.oldKey))
			L.SetGlobal("newKey", lua.LString(tt.newKey))

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_rename("default", oldKey, newKey)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			gotErr := L.GetGlobal("err")

			if gotResult.Type() != tt.expectedResult.Type() || gotResult.String() != tt.expectedResult.String() {
				t.Errorf("Unexpected result: got %v, want %v", gotResult, tt.expectedResult)
			}

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestPing(t *testing.T) {
	tests := []struct {
		name             string
		mockError        error
		expectedResult   lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "PingWithSuccess",
			mockError:      nil,
			expectedResult: lua.LString("PONG"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectPing().SetVal("PONG")
			},
		},
		{
			name:           "PingWithError",
			mockError:      errors.New("some error"),
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectPing().SetErr(errors.New("some error"))
			},
		},
	}

	L := lua.NewState()
	L.PreloadModule(global.LuaModRedis, LoaderModRedis)

	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			tt.prepareMockRedis(mock)

			rediscli.ReadHandle = db

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_ping("default")`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")

			gotErr := L.GetGlobal("err")
			if gotResult.String() != tt.expectedResult.String() {
				t.Errorf("Ping = %v, want %v", gotResult, tt.expectedResult)
			}

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}
