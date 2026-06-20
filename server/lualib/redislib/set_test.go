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
	"fmt"
	"strings"
	"testing"

	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestRedisSAdd(t *testing.T) {
	runSetValuesRedisTests(t, "redis_sadd", sAddCases())
}

func TestRedisSIsMember(t *testing.T) {
	runRedisLuaCommandTests(t, "redis_sismember", redisSIsMemberLuaCode(), redisSIsMemberCases())
}

// redisSIsMemberLuaCode returns the Lua script used by Redis SISMEMBER cases.
func redisSIsMemberLuaCode() string {
	return `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_sismember("default", key, value)`
}

// redisSIsMemberCases returns Redis SISMEMBER behavior cases.
func redisSIsMemberCases() []redisLuaCommandTest {
	return []redisLuaCommandTest{
		{
			name: "ExistInSet",
			luaGlobals: map[string]lua.LValue{
				"key":   lua.LString("existingKey"),
				"value": lua.LString("existingValue"),
			},
			expectedResult: lua.LTrue,
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectSIsMember("existingKey", "existingValue").SetVal(true)
			},
		},
		{
			name: "NotExistInSet",
			luaGlobals: map[string]lua.LValue{
				"key":   lua.LString("existingKey"),
				"value": lua.LString("nonExistingValue"),
			},
			expectedResult: lua.LFalse,
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectSIsMember("existingKey", "nonExistingValue").SetVal(false)
			},
		},
		{
			name: "ErrOnMemberCheck",
			luaGlobals: map[string]lua.LValue{
				"key":   lua.LString("existingKey"),
				"value": lua.LString("anyValue"),
			},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectSIsMember("existingKey", "anyValue").SetErr(errors.New("some error"))
			},
		},
	}
}

func TestRedisSMembers(t *testing.T) {
	runRedisLuaCommandTests(t, "redis_smembers", redisSMembersLuaCode(), redisSMembersCases())
}

// redisSMembersLuaCode returns the Lua script used by Redis SMEMBERS cases.
func redisSMembersLuaCode() string {
	return `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_smembers("default", key)`
}

// redisSMembersCases returns Redis SMEMBERS behavior cases.
func redisSMembersCases() []redisLuaCommandTest {
	return []redisLuaCommandTest{
		{
			name:           "ValidKey",
			luaGlobals:     map[string]lua.LValue{"key": lua.LString("existingKey")},
			expectedResult: createLuaTable([]string{"val1", "val2"}),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectSMembers("existingKey").SetVal([]string{"val1", "val2"})
			},
		},
		{
			name:           "NonExistingKey",
			luaGlobals:     map[string]lua.LValue{"key": lua.LString("nonExistingKey")},
			expectedResult: createLuaTable([]string{}),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectSMembers("nonExistingKey").SetVal([]string{})
			},
		},
		{
			name:           "ErrOnSMembers",
			luaGlobals:     map[string]lua.LValue{"key": lua.LString("anyKey")},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("some error"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectSMembers("anyKey").SetErr(errors.New("some error"))
			},
		},
	}
}

func TestRedisSRem(t *testing.T) {
	runSetValuesRedisTests(t, "redis_srem", sRemCases())
}

type setValuesRedisTest struct {
	name          string
	key           string
	values        []any
	expectedValue lua.LValue
	expectedErr   lua.LValue
	setupMock     func(mock redismock.ClientMock)
}

// sAddCases returns SADD command cases.
func sAddCases() []setValuesRedisTest {
	return setValuesCases(true)
}

// sRemCases returns SREM command cases.
func sRemCases() []setValuesRedisTest {
	return setValuesCases(false)
}

// setValuesCases returns SADD or SREM cases for mirrored set command behavior.
func setValuesCases(add bool) []setValuesRedisTest {
	if add {
		return []setValuesRedisTest{
			setValuesCase("AddNewValues", "existingKey", []any{"val1", "val2"}, lua.LNumber(2), lua.LNil, expectSAddNew),
			setValuesCase("AddExistingValues", "existingKey", []any{"val1", "val2"}, lua.LNumber(0), lua.LNil, expectSAddExisting),
			setValuesCase("AddWithErr", "existingKey", []any{"val1", "val2"}, lua.LNil, lua.LString("some error"), expectSAddError),
			setValuesCase("AddEmptyValues", "existingKey", []any{}, lua.LNumber(0), lua.LNil, expectSAddEmpty),
		}
	}

	return []setValuesRedisTest{
		setValuesCase("RemoveExistingValues", "existingKey", []any{"val1", "val2"}, lua.LNumber(2), lua.LNil, expectSRemExisting),
		setValuesCase("RemoveNonExistingValues", "existingKey", []any{"nonExistingVal1", "nonExistingVal2"}, lua.LNumber(0), lua.LNil, expectSRemMissing),
		setValuesCase("ErrorOnRemove", "existingKey", []any{"val1", "val2"}, lua.LNil, lua.LString("some error"), expectSRemError),
		setValuesCase("RemoveNoValues", "existingKey", []any{}, lua.LNumber(0), lua.LNil, expectSRemEmpty),
	}
}

// setValuesCase builds a variadic set command test case.
func setValuesCase(
	name string,
	key string,
	values []any,
	expectedValue lua.LValue,
	expectedErr lua.LValue,
	setupMock func(redismock.ClientMock),
) setValuesRedisTest {
	return setValuesRedisTest{
		name:          name,
		key:           key,
		values:        values,
		expectedValue: expectedValue,
		expectedErr:   expectedErr,
		setupMock:     setupMock,
	}
}

// expectSAddNew configures SADD for new values.
func expectSAddNew(mock redismock.ClientMock) {
	mock.ExpectSAdd("existingKey", []any{"val1", "val2"}).SetVal(2)
}

// expectSAddExisting configures SADD for existing values.
func expectSAddExisting(mock redismock.ClientMock) {
	mock.ExpectSAdd("existingKey", []any{"val1", "val2"}).SetVal(0)
}

// expectSAddError configures a failing SADD expectation.
func expectSAddError(mock redismock.ClientMock) {
	mock.ExpectSAdd("existingKey", []any{"val1", "val2"}).SetErr(errors.New("some error"))
}

// expectSAddEmpty configures SADD for an empty value list.
func expectSAddEmpty(mock redismock.ClientMock) {
	mock.ExpectSAdd("existingKey", []any{}).SetVal(0)
}

// expectSRemExisting configures SREM for existing values.
func expectSRemExisting(mock redismock.ClientMock) {
	mock.ExpectSRem("existingKey", []any{"val1", "val2"}).SetVal(2)
}

// expectSRemMissing configures SREM for missing values.
func expectSRemMissing(mock redismock.ClientMock) {
	mock.ExpectSRem("existingKey", []any{"nonExistingVal1", "nonExistingVal2"}).SetVal(0)
}

// expectSRemError configures a failing SREM expectation.
func expectSRemError(mock redismock.ClientMock) {
	mock.ExpectSRem("existingKey", []any{"val1", "val2"}).SetErr(errors.New("some error"))
}

// expectSRemEmpty configures SREM for an empty value list.
func expectSRemEmpty(mock redismock.ClientMock) {
	mock.ExpectSRem("existingKey", []any{}).SetVal(0)
}

// runSetValuesRedisTests runs Redis set commands that take a key and variadic values.
func runSetValuesRedisTests(t *testing.T, luaCmd string, tests []setValuesRedisTest) {
	t.Helper()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			L, mock, _ := newRedisLuaCommandState(t)

			tt.setupMock(mock)
			L.SetGlobal("key", lua.LString(tt.key))

			var valueStr strings.Builder
			for _, value := range tt.values {
				fmt.Fprintf(&valueStr, ", %s", formatLuaValue(value))
			}

			luaCode := fmt.Sprintf(
				`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.%s("default", key%s)`,
				luaCmd,
				valueStr.String(),
			)
			if err := L.DoString(luaCode); err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			assertLuaValueEqual(t, luaCmd, L.GetGlobal("result"), tt.expectedValue)
			checkLuaError(t, L.GetGlobal("err"), tt.expectedErr)

			mock.ClearExpect()
		})
	}
}

func TestRedisSCard(t *testing.T) {
	runSimpleKeyRedisTests(t, "redis_scard", []simpleKeyRedisTest{
		simpleKeyCase("ValidKey", "existingKey", lua.LNumber(2), lua.LNil, expectSCardValid),
		simpleKeyCase("NonExistingKey", "nonExistingKey", lua.LNumber(0), lua.LNil, expectSCardMissing),
		simpleKeyCase("ErrorOnSCard", "anyKey", lua.LNil, lua.LString("some error"), expectSCardError),
	})
}

// expectSCardValid configures SCARD for an existing key.
func expectSCardValid(mock redismock.ClientMock) {
	mock.ExpectSCard("existingKey").SetVal(2)
}

// expectSCardMissing configures SCARD for a missing key.
func expectSCardMissing(mock redismock.ClientMock) {
	mock.ExpectSCard("nonExistingKey").SetVal(0)
}

// expectSCardError configures a failing SCARD expectation.
func expectSCardError(mock redismock.ClientMock) {
	mock.ExpectSCard("anyKey").SetErr(errors.New("some error"))
}
