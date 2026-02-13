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
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestRedisHGet(t *testing.T) {
	config.SetTestFile(&config.FileSettings{Server: &config.ServerSection{}})

	tests := []struct {
		name             string
		key              string
		field            string
		valueType        string
		expectedResult   lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "GetExistingField",
			key:            "existingKey",
			field:          "existingField",
			valueType:      definitions.TypeString,
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHGet("existingKey", "existingField").SetVal("OK")
			},
		},
		{
			name:           "GetNonExistingField",
			key:            "existingKey",
			field:          "nonExistingField",
			valueType:      definitions.TypeString,
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("redis: nil"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHGet("existingKey", "nonExistingField").RedisNil()
			},
		},
		{
			name:           "GetFieldWithError",
			key:            "keyWithError",
			field:          "fieldWithError",
			valueType:      definitions.TypeString,
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHGet("keyWithError", "fieldWithError").SetErr(errors.New("some error"))
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
			L.SetGlobal("field", lua.LString(tt.field))
			L.SetGlobal("valueType", lua.LString(tt.valueType))

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hget("default", key, field, valueType)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedResult.Type() || gotResult.String() != tt.expectedResult.String() {
				t.Errorf("nauthilus.redis_hget() gotResult = %v, want %v", gotResult.String(), tt.expectedResult.String())
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisHSet(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		kvPairs          []any
		expectedResult   lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "SetStringKeyValuePairs",
			key:            "testKey",
			kvPairs:        []any{"field1", "value1", "field2", "value2"},
			expectedResult: lua.LNumber(2),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHSet("testKey", "field1", "value1", "field2", "value2").SetVal(2)
			},
		},
		{
			name:           "SetNilKeyValuePairs",
			key:            "nilKey",
			kvPairs:        []any{},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("invalid number of arguments"),
		},
		{
			name:           "SetKeyValuePairsWithError",
			key:            "errorKey",
			kvPairs:        []any{"field1", "value1"},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHSet("errorKey", "field1", "value1").SetErr(errors.New("some error"))
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

			if tt.prepareMockRedis != nil {
				tt.prepareMockRedis(mock)
			}

			rediscli.NewTestClient(db)

			L.SetGlobal("key", lua.LString(tt.key))

			kvPairsStr := ""

			for i := 0; i < len(tt.kvPairs); i += 2 {
				field := formatLuaValue(tt.kvPairs[i])
				value := formatLuaValue(tt.kvPairs[i+1])

				kvPairsStr += fmt.Sprintf(", %s, %s", field, value)
			}

			luaScript := fmt.Sprintf(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hset("default", key%s)`, kvPairsStr)

			err := L.DoString(luaScript)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedResult.Type() || gotResult.String() != tt.expectedResult.String() {
				t.Errorf("nauthilus.redis_hset() gotResult = %v, want %v", gotResult.String(), tt.expectedResult.String())
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisHDel(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		fields           []string
		expectedResult   lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "DeleteExistingField",
			key:            "testKey",
			fields:         []string{"field1"},
			expectedResult: lua.LNumber(1),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHDel("testKey", "field1").SetVal(1)
			},
		},
		{
			name:           "DeleteNonExistingField",
			key:            "testKey",
			fields:         []string{"field1"},
			expectedResult: lua.LNumber(0),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHDel("testKey", "field1").SetVal(0)
			},
		},
		{
			name:           "DeleteFromNonExistingKey",
			key:            "nonExistingKey",
			fields:         []string{"field1"},
			expectedResult: lua.LNumber(0),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHDel("nonExistingKey", "field1").SetVal(0)
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

			for index, field := range tt.fields {
				L.SetGlobal(fmt.Sprintf("field%d", index+1), lua.LString(field))
			}

			err := L.DoString(fmt.Sprintf(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hdel("default", key, %s)`, strings.Join(tt.fields, ", ")))

			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")

			if gotResult.Type() != tt.expectedResult.Type() || gotResult.String() != tt.expectedResult.String() {
				t.Errorf("nauthilus.redis_hdel() gotResult = %v, want %v", gotResult, tt.expectedResult)
			}

			gotErr := L.GetGlobal("err")

			if gotErr.Type() != tt.expectedErr.Type() && gotErr.String() != tt.expectedErr.String() {
				t.Errorf("nauthilus.redis_hdel() gotErr = %v, want %v", gotErr.String(), tt.expectedErr)
			}

			mock.ClearExpect()
		})
	}
}

func TestRedisHLen(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		expectedLength   int64
		expectedErr      string
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "ExistingKey",
			key:            "testKey",
			expectedLength: 2,
			expectedErr:    "",
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHLen("testKey").SetVal(2)
			},
		},
		{
			name:           "NonExistingKey",
			key:            "missingKey",
			expectedLength: 0,
			expectedErr:    "redis: nil",
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHLen("missingKey").RedisNil()
			},
		},
		{
			name:           "RedisError",
			key:            "errorKey",
			expectedLength: 0,
			expectedErr:    "connection error",
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHLen("errorKey").SetErr(errors.New("connection error"))
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

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hlen("default", key)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotLength := L.GetGlobal("result")
			if gotLength != lua.LNil && int64(gotLength.(lua.LNumber)) != tt.expectedLength {
				t.Errorf("nauthilus.redis_hlen() gotLength = %v, want %v", int64(gotLength.(lua.LNumber)), tt.expectedLength)
			}

			gotErr := L.GetGlobal("err")
			if tt.expectedErr != "" && gotErr.String() != tt.expectedErr {
				t.Errorf("Expected error: %v, but got: %v", tt.expectedErr, gotErr.String())
			}

			mock.ClearExpect()
		})
	}
}

func TestRedisHGetAll(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		expectedResult   map[string]string
		expectedErr      string
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name: "ExistingKey",
			key:  "testKey",
			expectedResult: map[string]string{
				"field1": "value1",
				"field2": "value2",
			},
			expectedErr: "",
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHGetAll("testKey").SetVal(map[string]string{
					"field1": "value1",
					"field2": "value2",
				})
			},
		},
		{
			name:           "NonExistingKey",
			key:            "missingKey",
			expectedResult: map[string]string{},
			expectedErr:    "redis: nil",
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHGetAll("missingKey").RedisNil()
			},
		},
		{
			name:           "RedisError",
			key:            "errorKey",
			expectedResult: map[string]string{},
			expectedErr:    "connection error",
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHGetAll("errorKey").SetErr(errors.New("connection error"))
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

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hgetall("default", key)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			result := L.GetGlobal("result")

			if result == lua.LNil {
				if !reflect.DeepEqual(map[string]string{}, tt.expectedResult) {
					t.Errorf("nauthilus.redis_hgetall() gotResult = %v, want %v", map[string]string{}, tt.expectedResult)
				}
			} else {
				gotResult, ok := result.(*lua.LTable)
				if !ok {
					t.Fatalf("Expected 'result' to be a table, but got %T", result)
				}

				gotTable := make(map[string]string)
				gotResult.ForEach(func(value lua.LValue, value2 lua.LValue) {
					gotTable[value.String()] = value2.String()
				})

				if !reflect.DeepEqual(gotTable, tt.expectedResult) {
					t.Errorf("nauthilus.redis_hgetall() gotResult = %v, want %v", gotTable, tt.expectedResult)
				}
			}

			gotErr := L.GetGlobal("err")
			if tt.expectedErr != "" && gotErr.String() != tt.expectedErr {
				t.Errorf("Expected error: %v, but got: %v", tt.expectedErr, gotErr.String())
			}

			mock.ClearExpect()
		})
	}
}

func TestRedisHIncrBy(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		field            string
		increment        int64
		expectedResult   int64
		expectedErr      string
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "IncrementExistingField",
			key:            "testKey",
			field:          "field1",
			increment:      5,
			expectedResult: 6,
			expectedErr:    "",
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHIncrBy("testKey", "field1", 5).SetVal(6)
			},
		},
		{
			name:           "IncrementNonExistingField",
			key:            "testKey",
			field:          "missingField",
			increment:      5,
			expectedResult: 5,
			expectedErr:    "",
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHIncrBy("testKey", "missingField", 5).SetVal(5)
			},
		},
		{
			name:           "IncrementWithRedisError",
			key:            "errorKey",
			field:          "errorField",
			increment:      6,
			expectedResult: 0,
			expectedErr:    "connection error",
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHIncrBy("errorKey", "errorField", 6).SetErr(errors.New("connection error"))
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
			L.SetGlobal("field", lua.LString(tt.field))
			L.SetGlobal("increment", lua.LNumber(tt.increment))

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hincrby("default", key, field, increment)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			result := L.GetGlobal("result")

			if result == lua.LNil {
				if tt.expectedResult != 0 {
					t.Errorf("nauthilus.redis_hincrby() gotResult = %v, want %v", 0, tt.expectedResult)
				}
			} else {
				gotResult := int64(result.(lua.LNumber))
				if gotResult != tt.expectedResult {
					t.Errorf("nauthilus.redis_hincrby() gotResult = %v, want %v", gotResult, tt.expectedResult)
				}
			}

			gotErr := L.GetGlobal("err")
			if tt.expectedErr != "" && gotErr.String() != tt.expectedErr {
				t.Errorf("Expected error: %v, but got: %v", tt.expectedErr, gotErr.String())
			}

			mock.ClearExpect()
		})
	}
}

func TestRedisHIncrByFloat(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		field            string
		increment        float64
		expectedResult   float64
		expectedErr      string
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "IncrementFloatExistingField",
			key:            "testKey",
			field:          "field1",
			increment:      3.5,
			expectedResult: 6.5,
			expectedErr:    "",
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHIncrByFloat("testKey", "field1", 3.5).SetVal(6.5)
			},
		},
		{
			name:           "IncrementFloatNonExistingField",
			key:            "testKey",
			field:          "missingField",
			increment:      3.5,
			expectedResult: 3.5,
			expectedErr:    "",
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHIncrByFloat("testKey", "missingField", 3.5).SetVal(3.5)
			},
		},
		{
			name:           "IncrementFloatWithRedisError",
			key:            "errorKey",
			field:          "errorField",
			increment:      3.5,
			expectedResult: 0,
			expectedErr:    "connection error",
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHIncrByFloat("errorKey", "errorField", 3.5).SetErr(errors.New("connection error"))
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
			L.SetGlobal("field", lua.LString(tt.field))
			L.SetGlobal("increment", lua.LNumber(tt.increment))

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hincrbyfloat("default", key, field, increment)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			result := L.GetGlobal("result")

			if result == lua.LNil {
				if tt.expectedResult != 0 {
					t.Errorf("nauthilus.redis_hincrbyfloat() gotResult = %v, want %v", 0, tt.expectedResult)
				}
			} else {
				gotResult := float64(result.(lua.LNumber))
				if gotResult != tt.expectedResult {
					t.Errorf("nauthilus.redis_hincrbyfloat() gotResult = %v, want %v", gotResult, tt.expectedResult)
				}
			}

			gotErr := L.GetGlobal("err")
			if tt.expectedErr != "" && gotErr.String() != tt.expectedErr {
				t.Errorf("Expected error: %v, but got: %v", tt.expectedErr, gotErr.String())
			}

			mock.ClearExpect()
		})
	}
}

func TestRedisHExists(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		field            string
		expectedResult   lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "ExistingKeyField",
			key:            "existingKey",
			field:          "existingField",
			expectedResult: lua.LTrue,
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHExists("existingKey", "existingField").SetVal(true)
			},
		},
		{
			name:           "NonExistingKeyField",
			key:            "nonExistingKey",
			field:          "nonExistingField",
			expectedResult: lua.LFalse,
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHExists("nonExistingKey", "nonExistingField").SetVal(false)
			},
		},
		{
			name:           "KeyFieldWithError",
			key:            "keyWithError",
			field:          "fieldWithError",
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHExists("keyWithError", "fieldWithError").SetErr(errors.New("some error"))
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
			L.SetGlobal("field", lua.LString(tt.field))

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hexists("default", key, field)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedResult.Type() || gotResult.String() != tt.expectedResult.String() {
				t.Errorf("nauthilus.redis_hexists() gotResult = %v, want %v", gotResult.String(), tt.expectedResult.String())
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisHMGet(t *testing.T) {
	tests := []struct {
		name             string
		key              string
		fields           []string
		expectedResult   map[string]*string
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:   "HMGetExistingFields",
			key:    "hashKey",
			fields: []string{"f1", "f2", "f3"},
			expectedResult: map[string]*string{
				"f1": ptr("v1"),
				"f2": ptr("v2"),
				"f3": ptr("v3"),
			},
			expectedErr: lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHMGet("hashKey", "f1", "f2", "f3").SetVal([]interface{}{"v1", "v2", "v3"})
			},
		},
		{
			name:   "HMGetMixedFields",
			key:    "hashKey",
			fields: []string{"f1", "missing", "f3"},
			expectedResult: map[string]*string{
				"f1":      ptr("v1"),
				"missing": nil,
				"f3":      ptr("v3"),
			},
			expectedErr: lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHMGet("hashKey", "f1", "missing", "f3").SetVal([]interface{}{"v1", nil, "v3"})
			},
		},
		{
			name:           "HMGetWithError",
			key:            "hashKey",
			fields:         []string{"f1", "f2"},
			expectedResult: nil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHMGet("hashKey", "f1", "f2").SetErr(errors.New("some error"))
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
			// Prepare fields as Lua variables
			luaCode := `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hmget("default", key`
			for i, f := range tt.fields {
				varName := "f" + string(rune('0'+i))
				L.SetGlobal(varName, lua.LString(f))
				luaCode += ", " + varName
			}
			luaCode += ")"

			if err := L.DoString(luaCode); err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			gotErr := L.GetGlobal("err")

			if tt.expectedErr == lua.LNil {
				if gotResult.Type() != lua.LTTable {
					t.Fatalf("expected table, got %v", gotResult.Type())
				}
				tbl := gotResult.(*lua.LTable)
				for field, exp := range tt.expectedResult {
					v := tbl.RawGetString(field)
					if exp == nil {
						if v.Type() != lua.LTNil {
							t.Errorf("field %s expected nil, got %s", field, v.String())
						}
					} else {
						if v.Type() != lua.LTString || v.String() != *exp {
							t.Errorf("field %s expected %q, got %s", field, *exp, v.String())
						}
					}
				}
				checkLuaError(t, gotErr, lua.LNil)
			} else {
				if gotResult.Type() != lua.LTNil {
					t.Errorf("expected result=nil on error, got %v", gotResult.Type())
				}
				checkLuaError(t, gotErr, tt.expectedErr)
			}

			mock.ClearExpect()
		})
	}
}

// ptr is a small helper for test expected values
func ptr(s string) *string { return &s }
