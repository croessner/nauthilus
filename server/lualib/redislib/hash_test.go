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
	"reflect"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestRedisHGet(t *testing.T) {
	runHashRedisTests(t, "redis_hget", []hashRedisTest{
		{
			name:    "GetExistingField",
			luaCode: `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hget("default", key, field, valueType)`,
			luaGlobals: hashValueTypeGlobals(
				"existingKey",
				"existingField",
				definitions.TypeString,
			),
			expectedResult: lua.LString("OK"),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHGet("existingKey", "existingField").SetVal("OK")
			},
		},
		{
			name:    "GetNonExistingField",
			luaCode: `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hget("default", key, field, valueType)`,
			luaGlobals: hashValueTypeGlobals(
				"existingKey",
				"nonExistingField",
				definitions.TypeString,
			),
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("redis: nil"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHGet("existingKey", "nonExistingField").RedisNil()
			},
		},
		{
			name:    "GetFieldWithError",
			luaCode: `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hget("default", key, field, valueType)`,
			luaGlobals: hashValueTypeGlobals(
				"keyWithError",
				"fieldWithError",
				definitions.TypeString,
			),
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHGet("keyWithError", "fieldWithError").SetErr(errors.New("some error"))
			},
		},
	})
}

func TestRedisHSet(t *testing.T) {
	runHashRedisTests(t, "redis_hset", []hashRedisTest{
		{
			name:    "SetStringKeyValuePairs",
			luaCode: `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hset("default", key, field1, value1, field2, value2)`,
			luaGlobals: hashSetGlobals("testKey", map[string]string{
				"field1": "value1",
				"field2": "value2",
			}),
			expectedResult: lua.LNumber(2),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHSet("testKey", "field1", "value1", "field2", "value2").SetVal(2)
			},
		},
		{
			name:           "SetNilKeyValuePairs",
			luaCode:        `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hset("default", key)`,
			luaGlobals:     map[string]lua.LValue{"key": lua.LString("nilKey")},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("invalid number of arguments"),
		},
		{
			name:    "SetKeyValuePairsWithError",
			luaCode: `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hset("default", key, field1, value1)`,
			luaGlobals: hashSetGlobals("errorKey", map[string]string{
				"field1": "value1",
			}),
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHSet("errorKey", "field1", "value1").SetErr(errors.New("some error"))
			},
		},
	})
}

func TestRedisHDel(t *testing.T) {
	runHashRedisTests(t, "redis_hdel", []hashRedisTest{
		{
			name:           "DeleteExistingField",
			luaCode:        `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hdel("default", key, field1)`,
			luaGlobals:     hashFieldVariableGlobals("testKey", "field1"),
			expectedResult: lua.LNumber(1),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHDel("testKey", "field1").SetVal(1)
			},
		},
		{
			name:           "DeleteNonExistingField",
			luaCode:        `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hdel("default", key, field1)`,
			luaGlobals:     hashFieldVariableGlobals("testKey", "field1"),
			expectedResult: lua.LNumber(0),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHDel("testKey", "field1").SetVal(0)
			},
		},
		{
			name:           "DeleteFromNonExistingKey",
			luaCode:        `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hdel("default", key, field1)`,
			luaGlobals:     hashFieldVariableGlobals("nonExistingKey", "field1"),
			expectedResult: lua.LNumber(0),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHDel("nonExistingKey", "field1").SetVal(0)
			},
		},
	})
}

func TestRedisHLen(t *testing.T) {
	runHashRedisTests(t, "redis_hlen", []hashRedisTest{
		{
			name:           "ExistingKey",
			luaCode:        `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hlen("default", key)`,
			luaGlobals:     map[string]lua.LValue{"key": lua.LString("testKey")},
			expectedResult: lua.LNumber(2),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHLen("testKey").SetVal(2)
			},
		},
		{
			name:           "NonExistingKey",
			luaCode:        `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hlen("default", key)`,
			luaGlobals:     map[string]lua.LValue{"key": lua.LString("missingKey")},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("redis: nil"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHLen("missingKey").RedisNil()
			},
		},
		{
			name:           "RedisError",
			luaCode:        `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hlen("default", key)`,
			luaGlobals:     map[string]lua.LValue{"key": lua.LString("errorKey")},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("connection error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHLen("errorKey").SetErr(errors.New("connection error"))
			},
		},
	})
}

type hashRedisTest struct {
	name             string
	luaCode          string
	luaGlobals       map[string]lua.LValue
	expectedResult   lua.LValue
	expectedErr      lua.LValue
	prepareMockRedis func(mock redismock.ClientMock)
}

// runHashRedisTests runs hash command cases with shared Lua setup.
func runHashRedisTests(t *testing.T, cmdName string, tests []hashRedisTest) {
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

			if err := L.DoString(tt.luaCode); err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			assertLuaValueEqual(t, cmdName, L.GetGlobal("result"), tt.expectedResult)
			checkLuaError(t, L.GetGlobal("err"), tt.expectedErr)
			mock.ClearExpect()
		})
	}
}

// hashValueTypeGlobals returns Lua globals for HGET tests.
func hashValueTypeGlobals(key string, field string, valueType string) map[string]lua.LValue {
	globals := hashFieldGlobals(key, field)
	globals["valueType"] = lua.LString(valueType)

	return globals
}

// hashSetGlobals returns Lua globals for HSET tests.
func hashSetGlobals(key string, values map[string]string) map[string]lua.LValue {
	globals := map[string]lua.LValue{"key": lua.LString(key)}
	for field, value := range values {
		globals[field] = lua.LString(field)
		globals[value] = lua.LString(value)
	}

	return globals
}

// hashFieldVariableGlobals returns Lua globals for one hash field variable.
func hashFieldVariableGlobals(key string, field string) map[string]lua.LValue {
	return map[string]lua.LValue{
		"key":    lua.LString(key),
		"field1": lua.LString(field),
	}
}

func TestRedisHGetAll(t *testing.T) {
	runHashStringMapTests(t, "redis_hgetall", `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hgetall("default", key)`, []hashStringMapTest{
		{
			name: "ExistingKey",
			key:  "testKey",
			expectedResult: map[string]string{
				"field1": "value1",
				"field2": "value2",
			},
			expectedErr: lua.LNil,
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
			expectedErr:    lua.LString("redis: nil"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHGetAll("missingKey").RedisNil()
			},
		},
		{
			name:           "RedisError",
			key:            "errorKey",
			expectedResult: map[string]string{},
			expectedErr:    lua.LString("connection error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHGetAll("errorKey").SetErr(errors.New("connection error"))
			},
		},
	})
}

type hashStringMapTest struct {
	name             string
	key              string
	expectedResult   map[string]string
	expectedErr      lua.LValue
	prepareMockRedis func(mock redismock.ClientMock)
}

// runHashStringMapTests runs hash commands that return string maps.
func runHashStringMapTests(t *testing.T, cmdName string, luaCode string, tests []hashStringMapTest) {
	t.Helper()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			L, mock, _ := newRedisLuaCommandState(t)
			tt.prepareMockRedis(mock)
			L.SetGlobal("key", lua.LString(tt.key))

			if err := L.DoString(luaCode); err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			assertHashStringMapResult(t, cmdName, L.GetGlobal("result"), tt.expectedResult)
			checkLuaError(t, L.GetGlobal("err"), tt.expectedErr)
			mock.ClearExpect()
		})
	}
}

// assertHashStringMapResult compares a Lua hash map result with the expected Go map.
func assertHashStringMapResult(t *testing.T, cmdName string, result lua.LValue, expected map[string]string) {
	t.Helper()

	if result == lua.LNil {
		if !reflect.DeepEqual(map[string]string{}, expected) {
			t.Errorf("nauthilus.%s() gotResult = %v, want %v", cmdName, map[string]string{}, expected)
		}

		return
	}

	gotResult, ok := result.(*lua.LTable)
	if !ok {
		t.Fatalf("Expected 'result' to be a table, but got %T", result)
	}

	gotTable := luaStringMap(gotResult)
	if !reflect.DeepEqual(gotTable, expected) {
		t.Errorf("nauthilus.%s() gotResult = %v, want %v", cmdName, gotTable, expected)
	}
}

// luaStringMap converts a Lua table to a string map.
func luaStringMap(table *lua.LTable) map[string]string {
	values := make(map[string]string)

	table.ForEach(func(key lua.LValue, value lua.LValue) {
		values[key.String()] = value.String()
	})

	return values
}

func TestRedisHIncrBy(t *testing.T) {
	runRedisLuaCommandTests(t, "redis_hincrby", `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hincrby("default", key, field, increment)`, hashIncrByCases())
}

func TestRedisHIncrByFloat(t *testing.T) {
	runRedisLuaCommandTests(t, "redis_hincrbyfloat", `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hincrbyfloat("default", key, field, increment)`, hashIncrByFloatCases())
}

// hashIncrByCases returns shared HINCRBY command cases.
func hashIncrByCases() []redisLuaCommandTest {
	return []redisLuaCommandTest{
		hashIncrementCase("IncrementExistingField", "testKey", "field1", 5, lua.LNumber(6), lua.LNil, expectHIncrByExisting),
		hashIncrementCase("IncrementNonExistingField", "testKey", "missingField", 5, lua.LNumber(5), lua.LNil, expectHIncrByMissing),
		hashIncrementCase("IncrementWithRedisError", "errorKey", "errorField", 6, lua.LNil, lua.LString("connection error"), expectHIncrByError),
	}
}

// hashIncrByFloatCases returns shared HINCRBYFLOAT command cases.
func hashIncrByFloatCases() []redisLuaCommandTest {
	return []redisLuaCommandTest{
		hashIncrementCase("IncrementFloatExistingField", "testKey", "field1", 3.5, lua.LNumber(6.5), lua.LNil, expectHIncrByFloatExisting),
		hashIncrementCase("IncrementFloatNonExistingField", "testKey", "missingField", 3.5, lua.LNumber(3.5), lua.LNil, expectHIncrByFloatMissing),
		hashIncrementCase("IncrementFloatWithRedisError", "errorKey", "errorField", 3.5, lua.LNil, lua.LString("connection error"), expectHIncrByFloatError),
	}
}

// hashIncrementCase builds a hash increment command test case.
func hashIncrementCase(
	name string,
	key string,
	field string,
	increment float64,
	expectedResult lua.LValue,
	expectedErr lua.LValue,
	prepareMockRedis func(redismock.ClientMock),
) redisLuaCommandTest {
	return redisLuaCommandTest{
		name:             name,
		luaGlobals:       hashIncrementGlobals(key, field, increment),
		expectedResult:   expectedResult,
		expectedErr:      expectedErr,
		prepareMockRedis: prepareMockRedis,
	}
}

// expectHIncrByExisting configures HINCRBY for an existing hash field.
func expectHIncrByExisting(mock redismock.ClientMock) {
	mock.ExpectHIncrBy("testKey", "field1", 5).SetVal(6)
}

// expectHIncrByMissing configures HINCRBY for a missing hash field.
func expectHIncrByMissing(mock redismock.ClientMock) {
	mock.ExpectHIncrBy("testKey", "missingField", 5).SetVal(5)
}

// expectHIncrByError configures a failing HINCRBY expectation.
func expectHIncrByError(mock redismock.ClientMock) {
	mock.ExpectHIncrBy("errorKey", "errorField", 6).SetErr(errors.New("connection error"))
}

// expectHIncrByFloatExisting configures HINCRBYFLOAT for an existing hash field.
func expectHIncrByFloatExisting(mock redismock.ClientMock) {
	mock.ExpectHIncrByFloat("testKey", "field1", 3.5).SetVal(6.5)
}

// expectHIncrByFloatMissing configures HINCRBYFLOAT for a missing hash field.
func expectHIncrByFloatMissing(mock redismock.ClientMock) {
	mock.ExpectHIncrByFloat("testKey", "missingField", 3.5).SetVal(3.5)
}

// expectHIncrByFloatError configures a failing HINCRBYFLOAT expectation.
func expectHIncrByFloatError(mock redismock.ClientMock) {
	mock.ExpectHIncrByFloat("errorKey", "errorField", 3.5).SetErr(errors.New("connection error"))
}

// hashIncrementGlobals returns Lua globals for hash increment command tests.
func hashIncrementGlobals(key, field string, increment float64) map[string]lua.LValue {
	return map[string]lua.LValue{
		"key":       lua.LString(key),
		"field":     lua.LString(field),
		"increment": lua.LNumber(increment),
	}
}

func TestRedisHExists(t *testing.T) {
	runRedisLuaCommandTests(t, "redis_hexists", `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hexists("default", key, field)`, []redisLuaCommandTest{
		{
			name:           "ExistingKeyField",
			luaGlobals:     hashFieldGlobals("existingKey", "existingField"),
			expectedResult: lua.LTrue,
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHExists("existingKey", "existingField").SetVal(true)
			},
		},
		{
			name:           "NonExistingKeyField",
			luaGlobals:     hashFieldGlobals("nonExistingKey", "nonExistingField"),
			expectedResult: lua.LFalse,
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHExists("nonExistingKey", "nonExistingField").SetVal(false)
			},
		},
		{
			name:           "KeyFieldWithError",
			luaGlobals:     hashFieldGlobals("keyWithError", "fieldWithError"),
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHExists("keyWithError", "fieldWithError").SetErr(errors.New("some error"))
			},
		},
	})
}

// hashFieldGlobals returns Lua globals for hash key/field command tests.
func hashFieldGlobals(key, field string) map[string]lua.LValue {
	return map[string]lua.LValue{
		"key":   lua.LString(key),
		"field": lua.LString(field),
	}
}

func TestRedisHMGet(t *testing.T) {
	tests := []hashHMGetTest{
		{
			name:   "HMGetExistingFields",
			key:    "hashKey",
			fields: []string{"f1", "f2", "f3"},
			expectedResult: map[string]*string{
				"f1": new("v1"),
				"f2": new("v2"),
				"f3": new("v3"),
			},
			expectedErr: lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHMGet("hashKey", "f1", "f2", "f3").SetVal([]any{"v1", "v2", "v3"})
			},
		},
		{
			name:   "HMGetMixedFields",
			key:    "hashKey",
			fields: []string{"f1", "missing", "f3"},
			expectedResult: map[string]*string{
				"f1":      new("v1"),
				"missing": nil,
				"f3":      new("v3"),
			},
			expectedErr: lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectHMGet("hashKey", "f1", "missing", "f3").SetVal([]any{"v1", nil, "v3"})
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
			runHashHMGetCase(t, tt)
		})
	}
}

type hashHMGetTest struct {
	name             string
	key              string
	fields           []string
	expectedResult   map[string]*string
	expectedErr      lua.LValue
	prepareMockRedis func(mock redismock.ClientMock)
}

// runHashHMGetCase runs one HMGET command case.
func runHashHMGetCase(t *testing.T, tt hashHMGetTest) {
	t.Helper()

	L, mock, _ := newRedisLuaCommandState(t)
	tt.prepareMockRedis(mock)
	L.SetGlobal("key", lua.LString(tt.key))
	luaCode := hashHMGetLuaCode(L, tt.fields)

	if err := L.DoString(luaCode); err != nil {
		t.Fatalf("Running Lua code failed: %v", err)
	}

	assertHashHMGetResult(t, L.GetGlobal("result"), tt.expectedResult, tt.expectedErr)
	checkLuaError(t, L.GetGlobal("err"), tt.expectedErr)
	mock.ClearExpect()
}

// hashHMGetLuaCode prepares field globals and returns the HMGET Lua script.
func hashHMGetLuaCode(L *lua.LState, fields []string) string {
	var luaCode strings.Builder
	luaCode.WriteString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_hmget("default", key`)

	for i, field := range fields {
		varName := "f" + string(rune('0'+i))
		L.SetGlobal(varName, lua.LString(field))
		luaCode.WriteString(", " + varName)
	}

	luaCode.WriteString(")")

	return luaCode.String()
}

// assertHashHMGetResult verifies HMGET success and error result shapes.
func assertHashHMGetResult(t *testing.T, result lua.LValue, expected map[string]*string, expectedErr lua.LValue) {
	t.Helper()

	if expectedErr != lua.LNil {
		if result.Type() != lua.LTNil {
			t.Errorf("expected result=nil on error, got %v", result.Type())
		}

		return
	}

	if result.Type() != lua.LTTable {
		t.Fatalf("expected table, got %v", result.Type())
	}

	assertHashHMGetTable(t, result.(*lua.LTable), expected)
}

// assertHashHMGetTable verifies HMGET field values in a Lua table.
func assertHashHMGetTable(t *testing.T, table *lua.LTable, expected map[string]*string) {
	t.Helper()

	for field, expectedValue := range expected {
		assertHashHMGetField(t, table, field, expectedValue)
	}
}

// assertHashHMGetField verifies one HMGET field value.
func assertHashHMGetField(t *testing.T, table *lua.LTable, field string, expected *string) {
	t.Helper()

	value := table.RawGetString(field)
	if expected == nil {
		if value.Type() != lua.LTNil {
			t.Errorf("field %s expected nil, got %s", field, value.String())
		}

		return
	}

	if value.Type() != lua.LTString || value.String() != *expected {
		t.Errorf("field %s expected %q, got %s", field, *expected, value.String())
	}
}
