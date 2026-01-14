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

func TestRedisMGet(t *testing.T) {
	tests := []struct {
		name             string
		keys             []string
		expectedResult   map[string]string
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "MGetExistingKeys",
			keys:           []string{"key1", "key2", "key3"},
			expectedResult: map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"},
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectMGet("key1", "key2", "key3").SetVal([]interface{}{"value1", "value2", "value3"})
			},
		},
		{
			name:           "MGetMixedKeys",
			keys:           []string{"key1", "nonexistent", "key3"},
			expectedResult: map[string]string{"key1": "value1", "key3": "value3"},
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectMGet("key1", "nonexistent", "key3").SetVal([]interface{}{"value1", nil, "value3"})
			},
		},
		{
			name:           "MGetWithError",
			keys:           []string{"key1", "key2"},
			expectedResult: nil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectMGet("key1", "key2").SetErr(errors.New("some error"))
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

			// Set up the Lua code to call redis_mget with the keys
			luaCode := `
				local nauthilus_redis = require("nauthilus_redis")
				result, err = nauthilus_redis.redis_mget("default"`

			// Add each key as a global variable and append to the Lua code
			for i, key := range tt.keys {
				varName := "key" + string(rune('0'+i))
				L.SetGlobal(varName, lua.LString(key))
				luaCode += ", " + varName
			}

			luaCode += ")"

			err := L.DoString(luaCode)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			gotErr := L.GetGlobal("err")

			if tt.expectedErr == lua.LNil {
				if gotResult.Type() != lua.LTTable {
					t.Errorf("Expected table result, got %v", gotResult.Type())
				} else {
					resultTable := gotResult.(*lua.LTable)
					for key, expectedValue := range tt.expectedResult {
						val := resultTable.RawGetString(key)
						if val.Type() == lua.LTNil {
							t.Errorf("Key %s not found in result", key)
						} else if val.String() != expectedValue {
							t.Errorf("For key %s, got value %s, want %s", key, val.String(), expectedValue)
						}
					}
				}
			}

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisMSet(t *testing.T) {
	tests := []struct {
		name             string
		keyValues        map[string]lua.LValue
		expectedResult   lua.LValue
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name: "MSetMultipleKeyValues",
			keyValues: map[string]lua.LValue{
				"key1": lua.LString("value1"),
				"key2": lua.LString("value2"),
				"key3": lua.LString("value3"),
			},
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectMSet("key1", "value1", "key2", "value2", "key3", "value3").SetVal("OK")
			},
		},
		{
			name: "MSetWithError",
			keyValues: map[string]lua.LValue{
				"key1": lua.LString("value1"),
				"key2": lua.LString("value2"),
			},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectMSet("key1", "value1", "key2", "value2").SetErr(errors.New("some error"))
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

			// Set up the Lua code to call redis_mset with the key-value pairs
			luaCode := `
				local nauthilus_redis = require("nauthilus_redis")
				result, err = nauthilus_redis.redis_mset("default"`

			// Add each key-value pair as global variables and append to the Lua code
			i := 0
			for key, value := range tt.keyValues {
				keyVarName := "key" + string(rune('0'+i))
				valueVarName := "value" + string(rune('0'+i))
				L.SetGlobal(keyVarName, lua.LString(key))
				L.SetGlobal(valueVarName, value)
				luaCode += ", " + keyVarName + ", " + valueVarName
				i++
			}

			luaCode += ")"

			err := L.DoString(luaCode)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedResult.Type() || gotResult.String() != tt.expectedResult.String() {
				t.Errorf("nauthilus.redis_mset() gotResult = %v, want %v", gotResult, tt.expectedResult)
			}

			gotErr := L.GetGlobal("err")
			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisKeys(t *testing.T) {
	tests := []struct {
		name             string
		pattern          string
		expectedResult   []string
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "KeysWithPattern",
			pattern:        "user:*",
			expectedResult: []string{"user:1", "user:2", "user:3"},
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectKeys("user:*").SetVal([]string{"user:1", "user:2", "user:3"})
			},
		},
		{
			name:           "KeysWithNoMatches",
			pattern:        "nonexistent:*",
			expectedResult: []string{},
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectKeys("nonexistent:*").SetVal([]string{})
			},
		},
		{
			name:           "KeysWithError",
			pattern:        "error:*",
			expectedResult: nil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectKeys("error:*").SetErr(errors.New("some error"))
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

			L.SetGlobal("pattern", lua.LString(tt.pattern))

			err := L.DoString(`
				local nauthilus_redis = require("nauthilus_redis")
				result, err = nauthilus_redis.redis_keys("default", pattern)
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
						t.Errorf("nauthilus.redis_keys() gotResult = %v, want %v", gotResult, expectedTable)
					}
				}
			}

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisScan(t *testing.T) {
	tests := []struct {
		name             string
		cursor           uint64
		pattern          string
		count            int64
		expectedCursor   uint64
		expectedKeys     []string
		expectedErr      lua.LValue
		prepareMockRedis func(mock redismock.ClientMock)
	}{
		{
			name:           "ScanWithMatches",
			cursor:         0,
			pattern:        "user:*",
			count:          10,
			expectedCursor: 0,
			expectedKeys:   []string{"user:1", "user:2", "user:3"},
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectScan(0, "user:*", 10).SetVal([]string{"user:1", "user:2", "user:3"}, 0)
			},
		},
		{
			name:           "ScanWithContinuation",
			cursor:         0,
			pattern:        "user:*",
			count:          2,
			expectedCursor: 2,
			expectedKeys:   []string{"user:1", "user:2"},
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectScan(0, "user:*", 2).SetVal([]string{"user:1", "user:2"}, 2)
			},
		},
		{
			name:           "ScanWithNoMatches",
			cursor:         0,
			pattern:        "nonexistent:*",
			count:          10,
			expectedCursor: 0,
			expectedKeys:   []string{},
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectScan(0, "nonexistent:*", 10).SetVal([]string{}, 0)
			},
		},
		{
			name:           "ScanWithError",
			cursor:         0,
			pattern:        "error:*",
			count:          10,
			expectedCursor: 0,
			expectedKeys:   nil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectScan(0, "error:*", 10).SetErr(errors.New("some error"))
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

			L.SetGlobal("cursor", lua.LNumber(tt.cursor))
			L.SetGlobal("pattern", lua.LString(tt.pattern))
			L.SetGlobal("count", lua.LNumber(tt.count))

			err := L.DoString(`
				local nauthilus_redis = require("nauthilus_redis")
				result, err = nauthilus_redis.redis_scan("default", cursor, pattern, count)
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
					resultTable := gotResult.(*lua.LTable)

					// Check cursor
					cursor := resultTable.RawGetString("cursor")
					if cursor.Type() != lua.LTNumber {
						t.Errorf("Expected cursor to be a number, got %v", cursor.Type())
					} else if float64(lua.LVAsNumber(cursor)) != float64(tt.expectedCursor) {
						t.Errorf("Expected cursor to be %v, got %v", tt.expectedCursor, lua.LVAsNumber(cursor))
					}

					// Check keys
					keys := resultTable.RawGetString("keys")
					if keys.Type() != lua.LTTable {
						t.Errorf("Expected keys to be a table, got %v", keys.Type())
					} else {
						expectedKeysTable := createLuaTable(tt.expectedKeys)
						if !luaTablesAreEqual(keys.(*lua.LTable), expectedKeysTable) {
							t.Errorf("Expected keys to be %v, got %v", tt.expectedKeys, keys)
						}
					}
				}
			}

			checkLuaError(t, gotErr, tt.expectedErr)

			mock.ClearExpect()
		})
	}
}
