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
	"strings"
	"testing"

	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestRedisMGet(t *testing.T) {
	for _, tt := range redisMGetCases() {
		t.Run(tt.name, func(t *testing.T) {
			runRedisMGetCase(t, tt)
		})
	}
}

type redisMGetTest struct {
	name             string
	keys             []string
	expectedResult   map[string]string
	expectedErr      lua.LValue
	prepareMockRedis func(mock redismock.ClientMock)
}

// redisMGetCases returns Redis MGET behavior cases.
func redisMGetCases() []redisMGetTest {
	return []redisMGetTest{
		{
			name:           "MGetExistingKeys",
			keys:           []string{"key1", "key2", "key3"},
			expectedResult: map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"},
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectMGet("key1", "key2", "key3").SetVal([]any{"value1", "value2", "value3"})
			},
		},
		{
			name:           "MGetMixedKeys",
			keys:           []string{"key1", "nonexistent", "key3"},
			expectedResult: map[string]string{"key1": "value1", "key3": "value3"},
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectMGet("key1", "nonexistent", "key3").SetVal([]any{"value1", nil, "value3"})
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
}

// runRedisMGetCase executes one MGET scenario.
func runRedisMGetCase(t *testing.T, tt redisMGetTest) {
	t.Helper()

	L, mock, _ := newRedisLuaCommandState(t)
	tt.prepareMockRedis(mock)
	runRedisMGetScript(t, L, tt.keys)
	assertRedisMGetResult(t, L.GetGlobal("result"), tt)
	checkLuaError(t, L.GetGlobal("err"), tt.expectedErr)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("mock expectations were not met: %v", err)
	}

	mock.ClearExpect()
}

// runRedisMGetScript builds and executes an MGET Lua call with key globals.
func runRedisMGetScript(t *testing.T, L *lua.LState, keys []string) {
	t.Helper()

	var luaCode strings.Builder
	luaCode.WriteString(`
		local nauthilus_redis = require("nauthilus_redis")
		result, err = nauthilus_redis.redis_mget("default"`)

	for i, key := range keys {
		varName := "key" + string(rune('0'+i))
		L.SetGlobal(varName, lua.LString(key))
		luaCode.WriteString(", " + varName)
	}

	luaCode.WriteString(")")

	if err := L.DoString(luaCode.String()); err != nil {
		t.Fatalf("Running Lua code failed: %v", err)
	}
}

// assertRedisMGetResult checks the key-indexed Lua result table returned by MGET.
func assertRedisMGetResult(t *testing.T, gotResult lua.LValue, tt redisMGetTest) {
	t.Helper()

	if tt.expectedErr != lua.LNil {
		return
	}

	resultTable, ok := gotResult.(*lua.LTable)
	if !ok {
		t.Errorf("Expected table result, got %v", gotResult.Type())

		return
	}

	for key, expectedValue := range tt.expectedResult {
		val := resultTable.RawGetString(key)
		if val.Type() == lua.LTNil {
			t.Errorf("Key %s not found in result", key)
		} else if val.String() != expectedValue {
			t.Errorf("For key %s, got value %s, want %s", key, val.String(), expectedValue)
		}
	}
}

func TestRedisMSet(t *testing.T) {
	for _, tt := range redisMSetCases() {
		t.Run(tt.name, func(t *testing.T) {
			runRedisMSetCase(t, tt)
		})
	}
}

type redisMSetPair struct {
	key   string
	value lua.LValue
}

type redisMSetTest struct {
	name             string
	keyValues        []redisMSetPair
	expectedResult   lua.LValue
	expectedErr      lua.LValue
	prepareMockRedis func(mock redismock.ClientMock)
}

// redisMSetCases returns Redis MSET behavior cases.
func redisMSetCases() []redisMSetTest {
	return []redisMSetTest{
		{
			name: "MSetMultipleKeyValues",
			keyValues: []redisMSetPair{
				{key: "key1", value: lua.LString("value1")},
				{key: "key2", value: lua.LString("value2")},
				{key: "key3", value: lua.LString("value3")},
			},
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectMSet("key1", "value1", "key2", "value2", "key3", "value3").SetVal("OK")
			},
		},
		{
			name: "MSetWithError",
			keyValues: []redisMSetPair{
				{key: "key1", value: lua.LString("value1")},
				{key: "key2", value: lua.LString("value2")},
			},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectMSet("key1", "value1", "key2", "value2").SetErr(errors.New("some error"))
			},
		},
	}
}

// runRedisMSetCase executes one MSET scenario.
func runRedisMSetCase(t *testing.T, tt redisMSetTest) {
	t.Helper()

	L, mock, _ := newRedisLuaCommandState(t)
	tt.prepareMockRedis(mock)
	runRedisMSetScript(t, L, tt.keyValues)
	assertLuaValueEqual(t, "redis_mset", L.GetGlobal("result"), tt.expectedResult)
	checkLuaError(t, L.GetGlobal("err"), tt.expectedErr)
	assertRedisExpectationsAndClear(t, mock)
}

// runRedisMSetScript builds and executes an MSET Lua call with ordered key/value globals.
func runRedisMSetScript(t *testing.T, L *lua.LState, pairs []redisMSetPair) {
	t.Helper()

	var luaCode strings.Builder
	luaCode.WriteString(`
		local nauthilus_redis = require("nauthilus_redis")
		result, err = nauthilus_redis.redis_mset("default"`)

	for i, pair := range pairs {
		keyVarName := "key" + string(rune('0'+i))
		valueVarName := "value" + string(rune('0'+i))

		L.SetGlobal(keyVarName, lua.LString(pair.key))
		L.SetGlobal(valueVarName, pair.value)
		luaCode.WriteString(", " + keyVarName + ", " + valueVarName)
	}

	luaCode.WriteString(")")

	if err := L.DoString(luaCode.String()); err != nil {
		t.Fatalf("Running Lua code failed: %v", err)
	}
}

func TestRedisKeys(t *testing.T) {
	runRedisLuaCommandTests(t, "redis_keys", redisKeysLuaCode(), redisKeysCases())
}

// redisKeysLuaCode returns the Lua script used by Redis KEYS cases.
func redisKeysLuaCode() string {
	return `
		local nauthilus_redis = require("nauthilus_redis")
		result, err = nauthilus_redis.redis_keys("default", pattern)
	`
}

// redisKeysCases returns Redis KEYS behavior cases.
func redisKeysCases() []redisLuaCommandTest {
	return []redisLuaCommandTest{
		{
			name:           "KeysWithPattern",
			luaGlobals:     map[string]lua.LValue{"pattern": lua.LString("user:*")},
			expectedResult: createLuaTable([]string{"user:1", "user:2", "user:3"}),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectKeys("user:*").SetVal([]string{"user:1", "user:2", "user:3"})
			},
		},
		{
			name:           "KeysWithNoMatches",
			luaGlobals:     map[string]lua.LValue{"pattern": lua.LString("nonexistent:*")},
			expectedResult: createLuaTable([]string{}),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectKeys("nonexistent:*").SetVal([]string{})
			},
		},
		{
			name:           "KeysWithError",
			luaGlobals:     map[string]lua.LValue{"pattern": lua.LString("error:*")},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectKeys("error:*").SetErr(errors.New("some error"))
			},
		},
	}
}

func TestRedisScan(t *testing.T) {
	for _, tt := range redisScanCases() {
		t.Run(tt.name, func(t *testing.T) {
			runRedisScanCase(t, tt)
		})
	}
}

type redisScanTest struct {
	name             string
	cursor           uint64
	pattern          string
	count            int64
	expectedCursor   uint64
	expectedKeys     []string
	expectedErr      lua.LValue
	prepareMockRedis func(mock redismock.ClientMock)
}

// redisScanCases returns Redis SCAN behavior cases.
func redisScanCases() []redisScanTest {
	return []redisScanTest{
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
}

// runRedisScanCase executes one SCAN scenario.
func runRedisScanCase(t *testing.T, tt redisScanTest) {
	t.Helper()

	L, mock, _ := newRedisLuaCommandState(t)
	tt.prepareMockRedis(mock)
	runRedisScanScript(t, L, tt)
	assertRedisScanResult(t, L.GetGlobal("result"), tt)
	checkLuaError(t, L.GetGlobal("err"), tt.expectedErr)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("mock expectations were not met: %v", err)
	}

	mock.ClearExpect()
}

// runRedisScanScript executes a SCAN Lua call.
func runRedisScanScript(t *testing.T, L *lua.LState, tt redisScanTest) {
	t.Helper()

	L.SetGlobal("cursor", lua.LNumber(tt.cursor))
	L.SetGlobal("pattern", lua.LString(tt.pattern))
	L.SetGlobal("count", lua.LNumber(tt.count))

	if err := L.DoString(`
		local nauthilus_redis = require("nauthilus_redis")
		result, err = nauthilus_redis.redis_scan("default", cursor, pattern, count)
	`); err != nil {
		t.Fatalf("Running Lua code failed: %v", err)
	}
}

// assertRedisScanResult checks the cursor and keys table returned by SCAN.
func assertRedisScanResult(t *testing.T, gotResult lua.LValue, tt redisScanTest) {
	t.Helper()

	if tt.expectedErr != lua.LNil {
		return
	}

	resultTable, ok := gotResult.(*lua.LTable)
	if !ok {
		t.Errorf("Expected table result, got %v", gotResult.Type())

		return
	}

	assertRedisScanCursor(t, resultTable, tt.expectedCursor)
	assertRedisScanKeys(t, resultTable, tt.expectedKeys)
}

// assertRedisScanCursor checks the cursor field returned by SCAN.
func assertRedisScanCursor(t *testing.T, resultTable *lua.LTable, expectedCursor uint64) {
	t.Helper()

	cursor := resultTable.RawGetString("cursor")
	if cursor.Type() != lua.LTNumber {
		t.Errorf("Expected cursor to be a number, got %v", cursor.Type())

		return
	}

	if float64(lua.LVAsNumber(cursor)) != float64(expectedCursor) {
		t.Errorf("Expected cursor to be %v, got %v", expectedCursor, lua.LVAsNumber(cursor))
	}
}

// assertRedisScanKeys checks the keys table returned by SCAN.
func assertRedisScanKeys(t *testing.T, resultTable *lua.LTable, expectedKeys []string) {
	t.Helper()

	keys := resultTable.RawGetString("keys")
	if keys.Type() != lua.LTTable {
		t.Errorf("Expected keys to be a table, got %v", keys.Type())

		return
	}

	expectedKeysTable := createLuaTable(expectedKeys)
	if !luaTablesAreEqual(keys.(*lua.LTable), expectedKeysTable) {
		t.Errorf("Expected keys to be %v, got %v", expectedKeys, keys)
	}
}
