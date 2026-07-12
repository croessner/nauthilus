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
	"sort"
	"testing"

	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestRedisZAdd(t *testing.T) {
	for _, tt := range redisZAddCases() {
		t.Run(tt.name, func(t *testing.T) {
			runRedisZAddCase(t, tt)
		})
	}
}

type zAddRedisTest struct {
	name          string
	key           string
	luaTable      func(L *lua.LState) *lua.LTable
	expectedCount lua.LValue
	expectedErr   lua.LValue
	setupMock     func(mock redismock.ClientMock, key string, zSet []redis.Z)
}

// redisZAddCases returns Redis ZADD behavior cases.
func redisZAddCases() []zAddRedisTest {
	return []zAddRedisTest{
		{
			name:          "AddSingleEntry",
			key:           "key1",
			luaTable:      zScoreTable(zScoreEntry{member: "member1", score: 10}),
			expectedCount: lua.LNumber(1),
			expectedErr:   lua.LNil,
			setupMock: func(mock redismock.ClientMock, key string, zSet []redis.Z) {
				mock.ExpectZAdd(key, zSet...).SetVal(1)
			},
		},
		{
			name: "AddMultipleEntries",
			key:  "key2",
			luaTable: zScoreTable(
				zScoreEntry{member: "member1", score: 10},
				zScoreEntry{member: "member2", score: 20},
			),
			expectedCount: lua.LNumber(2),
			expectedErr:   lua.LNil,
			setupMock: func(mock redismock.ClientMock, key string, zSet []redis.Z) {
				mock.ExpectZAdd(key, zSet...).SetVal(2)
			},
		},
		{
			name:          "AddEmptyTable",
			key:           "key3",
			luaTable:      emptyLuaTable,
			expectedCount: lua.LNumber(0),
			expectedErr:   lua.LNil,
			setupMock: func(mock redismock.ClientMock, key string, zSet []redis.Z) {
				mock.ExpectZAdd(key, zSet...).SetVal(0)
			},
		},
		{
			name:          "RedisError",
			key:           "key5",
			luaTable:      zScoreTable(zScoreEntry{member: "member1", score: 10}),
			expectedCount: lua.LNil,
			expectedErr:   lua.LString("context deadline exceeded"),
			setupMock: func(mock redismock.ClientMock, key string, zSet []redis.Z) {
				mock.ExpectZAdd(key, zSet...).SetErr(context.DeadlineExceeded)
			},
		},
	}
}

// runRedisZAddCase executes one ZADD scenario.
func runRedisZAddCase(t *testing.T, tt zAddRedisTest) {
	t.Helper()

	L, mock, _ := newRedisLuaCommandState(t)
	luaTbl := tt.luaTable(L)
	tt.setupMock(mock, tt.key, zSetFromLuaTable(luaTbl))

	L.SetGlobal("table", luaTbl)
	L.SetGlobal("key", lua.LString(tt.key))

	if err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_zadd("default", key, table)`); err != nil {
		t.Fatalf("Running Lua code failed: %v", err)
	}

	assertLuaValueEqual(t, "redis_zadd", L.GetGlobal("result"), tt.expectedCount)
	checkLuaError(t, L.GetGlobal("err"), tt.expectedErr)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("mock expectations were not met: %v", err)
	}

	mock.ClearExpect()
}

type zScoreEntry struct {
	member string
	score  float64
}

// zScoreTable builds a Lua table factory for ZSet score maps.
func zScoreTable(entries ...zScoreEntry) func(*lua.LState) *lua.LTable {
	return func(L *lua.LState) *lua.LTable {
		tbl := L.NewTable()

		for _, entry := range entries {
			tbl.RawSetString(entry.member, lua.LNumber(entry.score))
		}

		return tbl
	}
}

// zSetFromLuaTable converts a Lua score map into a stable redis.Z slice.
func zSetFromLuaTable(luaTbl *lua.LTable) []redis.Z {
	elements := make([]zScoreEntry, 0)

	luaTbl.ForEach(func(key, value lua.LValue) {
		elements = append(elements, zScoreEntry{
			member: key.String(),
			score:  float64(lua.LVAsNumber(value)),
		})
	})

	sort.Slice(elements, func(i, j int) bool {
		return elements[i].member < elements[j].member
	})

	zSet := make([]redis.Z, 0, len(elements))
	for _, elem := range elements {
		zSet = append(zSet, redis.Z{Member: elem.member, Score: elem.score})
	}

	return zSet
}

func TestRedisZRange(t *testing.T) {
	runZIndexRangeRedisTests(t, "redis_zrange", redisZRangeCases())
}

func TestRedisZRevRange(t *testing.T) {
	runZIndexRangeRedisTests(t, "redis_zrevrange", redisZRevRangeCases())
}

func TestRedisZRevRangeWithScores(t *testing.T) {
	for _, tt := range redisZRevRangeWithScoresCases() {
		t.Run(tt.name, func(t *testing.T) {
			runRedisZRevRangeWithScoresCase(t, tt)
		})
	}
}

type zRevRangeWithScoresRedisTest struct {
	redisErr     error
	name         string
	values       []redis.Z
	customHandle bool
}

// redisZRevRangeWithScoresCases returns handle, result, and error coverage for scored ranges.
func redisZRevRangeWithScoresCases() []zRevRangeWithScoresRedisTest {
	return []zRevRangeWithScoresRedisTest{
		{
			name: "DefaultHandle",
			values: []redis.Z{
				{Member: "alice@example.test", Score: 12},
				{Member: "bob@example.test", Score: 10},
			},
		},
		{
			name:         "CustomHandle",
			customHandle: true,
			values:       []redis.Z{{Member: "custom@example.test", Score: 9}},
		},
		{name: "EmptyRange", values: []redis.Z{}},
		{name: "RedisError", redisErr: context.DeadlineExceeded},
	}
}

// runRedisZRevRangeWithScoresCase executes one scored reverse-range scenario.
func runRedisZRevRangeWithScoresCase(t *testing.T, tt zRevRangeWithScoresRedisTest) {
	t.Helper()

	L, mock, db := newRedisLuaCommandState(t)
	key := "hotspots"
	expectation := mock.ExpectZRevRangeWithScores(key, 0, 1)

	if tt.redisErr != nil {
		expectation.SetErr(tt.redisErr)
	} else {
		expectation.SetVal(tt.values)
	}

	handle := lua.LValue(lua.LString("default"))

	if tt.customHandle {
		userData := L.NewUserData()
		userData.Value = db
		handle = userData
	}

	L.SetGlobal("handle", handle)
	L.SetGlobal("key", lua.LString(key))

	if err := L.DoString(`
local redis = require("nauthilus_redis")
result, err = redis.redis_zrevrange_withscores(handle, key, 0, 1)
`); err != nil {
		t.Fatalf("Running Lua code failed: %v", err)
	}

	assertScoredRangeResult(t, L, tt)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("mock expectations were not met: %v", err)
	}
}

// assertScoredRangeResult verifies the Lua result or Redis error for one scored range.
func assertScoredRangeResult(t *testing.T, L *lua.LState, tt zRevRangeWithScoresRedisTest) {
	t.Helper()

	if tt.redisErr != nil {
		if L.GetGlobal("result") != lua.LNil {
			t.Fatalf("redis_zrevrange_withscores() result = %s, want nil", L.GetGlobal("result"))
		}

		checkLuaError(t, L.GetGlobal("err"), lua.LString(tt.redisErr.Error()))

		return
	}

	result, ok := L.GetGlobal("result").(*lua.LTable)
	if !ok {
		t.Fatalf("redis_zrevrange_withscores() result = %s, want table", L.GetGlobal("result"))
	}

	if result.Len() != len(tt.values) {
		t.Fatalf("redis_zrevrange_withscores() rows = %d, want %d", result.Len(), len(tt.values))
	}

	for index, value := range tt.values {
		assertScoredRangeRow(t, result, index+1, value.Member.(string), value.Score)
	}

	checkLuaError(t, L.GetGlobal("err"), lua.LNil)
}

// assertScoredRangeRow verifies one member-score row returned to Lua.
func assertScoredRangeRow(t *testing.T, rows *lua.LTable, index int, member string, score float64) {
	t.Helper()

	row, ok := rows.RawGetInt(index).(*lua.LTable)
	if !ok {
		t.Fatalf("scored range row %d = %s, want table", index, rows.RawGetInt(index))
	}

	if got := row.RawGetString("member").String(); got != member {
		t.Fatalf("scored range row %d member = %q, want %q", index, got, member)
	}

	if got := float64(lua.LVAsNumber(row.RawGetString("score"))); got != score {
		t.Fatalf("scored range row %d score = %v, want %v", index, got, score)
	}
}

// redisZRangeCases returns Redis ZRANGE behavior cases.
func redisZRangeCases() []zIndexRangeRedisTest {
	return []zIndexRangeRedisTest{
		zIndexRangeCase("ValidRangeWithMultipleMembers", "key1", 0, 2, zMemberTable("member1", "member2"), lua.LNil, expectZRangeValues("member1", "member2")),
		zIndexRangeCase("ValidRangeWithNoMembers", "key2", 0, 1, emptyLuaTable, lua.LNil, expectZRangeValues()),
		zIndexRangeCase("NonExistentKey", "key3", 0, 1, emptyLuaTable, lua.LNil, expectZRangeValues()),
		zIndexRangeCase("RedisError", "key4", 0, 1, nilLuaTable, lua.LString("context deadline exceeded"), expectZRangeError),
	}
}

// redisZRevRangeCases returns Redis ZREVRANGE behavior cases.
func redisZRevRangeCases() []zIndexRangeRedisTest {
	return []zIndexRangeRedisTest{
		zIndexRangeCase("ValidReverseRangeWithMultipleMembers", "key1", 0, 2, zMemberTable("member3", "member2", "member1"), lua.LNil, expectZRevRangeValues("member3", "member2", "member1")),
		zIndexRangeCase("ValidReverseRangeWithNoMembers", "key2", 0, 1, emptyLuaTable, lua.LNil, expectZRevRangeValues()),
		zIndexRangeCase("NonExistentKey", "key3", 0, 1, emptyLuaTable, lua.LNil, expectZRevRangeValues()),
		zIndexRangeCase("RedisError", "key4", 0, 1, nilLuaTable, lua.LString("context deadline exceeded"), expectZRevRangeError),
	}
}

// zIndexRangeRedisTest defines a ZSet range-by-index test case.
type zIndexRangeRedisTest struct {
	name        string
	key         string
	start, stop int64
	expected    func(L *lua.LState) *lua.LTable
	expectedErr lua.LValue
	setupMock   func(mock redismock.ClientMock, key string, start, stop int64)
}

// zIndexRangeCase builds a ZSet range-by-index case.
func zIndexRangeCase(
	name string,
	key string,
	start int64,
	stop int64,
	expected func(*lua.LState) *lua.LTable,
	expectedErr lua.LValue,
	setupMock func(redismock.ClientMock, string, int64, int64),
) zIndexRangeRedisTest {
	return zIndexRangeRedisTest{
		name:        name,
		key:         key,
		start:       start,
		stop:        stop,
		expected:    expected,
		expectedErr: expectedErr,
		setupMock:   setupMock,
	}
}

// expectZRangeValues configures a successful ZRANGE expectation.
func expectZRangeValues(values ...string) func(redismock.ClientMock, string, int64, int64) {
	return func(mock redismock.ClientMock, key string, start, stop int64) {
		mock.ExpectZRange(key, start, stop).SetVal(values)
	}
}

// expectZRevRangeValues configures a successful ZREVRANGE expectation.
func expectZRevRangeValues(values ...string) func(redismock.ClientMock, string, int64, int64) {
	return func(mock redismock.ClientMock, key string, start, stop int64) {
		mock.ExpectZRevRange(key, start, stop).SetVal(values)
	}
}

// expectZRangeError configures a failing ZRANGE expectation.
func expectZRangeError(mock redismock.ClientMock, key string, start, stop int64) {
	mock.ExpectZRange(key, start, stop).SetErr(context.DeadlineExceeded)
}

// expectZRevRangeError configures a failing ZREVRANGE expectation.
func expectZRevRangeError(mock redismock.ClientMock, key string, start, stop int64) {
	mock.ExpectZRevRange(key, start, stop).SetErr(context.DeadlineExceeded)
}

// runZIndexRangeRedisTests executes ZSet range-by-index tests with shared setup and assertions.
func runZIndexRangeRedisTests(t *testing.T, luaCmd string, tests []zIndexRangeRedisTest) {
	t.Helper()

	luaCode := `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.` +
		luaCmd + `("default", key, start, stop)`

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			L, mock, _ := newRedisLuaCommandState(t)

			if tt.setupMock != nil {
				tt.setupMock(mock, tt.key, tt.start, tt.stop)
			}

			L.SetGlobal("key", lua.LString(tt.key))
			L.SetGlobal("start", lua.LNumber(tt.start))
			L.SetGlobal("stop", lua.LNumber(tt.stop))

			if err := L.DoString(luaCode); err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			expectedResult := tt.expected(L)

			if expectedResult != nil && !luaTablesAreEqual(gotResult.(*lua.LTable), expectedResult) {
				t.Errorf("%s() result = %s, want %s", luaCmd, gotResult, expectedResult)
			} else if expectedResult == nil && gotResult != lua.LNil {
				t.Errorf("%s() result = %s, want nil", luaCmd, gotResult)
			}

			checkLuaError(t, L.GetGlobal("err"), tt.expectedErr)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("mock expectations were not met: %v", err)
			}

			mock.ClearExpect()
		})
	}
}

func TestRedisZRangeByScore(t *testing.T) {
	for _, tt := range redisZRangeByScoreCases() {
		t.Run(tt.name, func(t *testing.T) {
			runRedisZRangeByScoreCase(t, tt)
		})
	}
}

type zRangeByScoreRedisTest struct {
	name        string
	key         string
	minScore    string
	maxScore    string
	optsTable   func(L *lua.LState) *lua.LTable
	expected    func(L *lua.LState) *lua.LTable
	expectedErr lua.LValue
	setupMock   func(mock redismock.ClientMock, key, minScore, maxScore string, opts redis.ZRangeBy)
}

// redisZRangeByScoreCases returns Redis ZRANGEBYSCORE behavior cases.
func redisZRangeByScoreCases() []zRangeByScoreRedisTest {
	cases := redisZRangeByScoreSuccessCases()
	cases = append(cases, redisZRangeByScoreEmptyCases()...)
	cases = append(cases, redisZRangeByScoreErrorCases()...)

	return cases
}

// redisZRangeByScoreSuccessCases returns successful ZRANGEBYSCORE cases with members.
func redisZRangeByScoreSuccessCases() []zRangeByScoreRedisTest {
	return []zRangeByScoreRedisTest{
		{
			name:        "ValidRangeWithMultipleMembers",
			key:         "key1",
			minScore:    "10",
			maxScore:    "20",
			optsTable:   nilLuaTable,
			expected:    zMemberTable("member1", "member2"),
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key, _, _ string, opts redis.ZRangeBy) {
				mock.ExpectZRangeByScore(key, &opts).SetVal([]string{"member1", "member2"})
			},
		},
		{
			name:        "ValidRangeWithOffsetAndCount",
			key:         "key2",
			minScore:    "10",
			maxScore:    "30",
			optsTable:   zRangeByScoreOffsetOptions,
			expected:    zMemberTable("member2", "member3"),
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key, _, _ string, opts redis.ZRangeBy) {
				opts.Offset = 1
				opts.Count = 2
				mock.ExpectZRangeByScore(key, &opts).SetVal([]string{"member2", "member3"})
			},
		},
	}
}

// redisZRangeByScoreEmptyCases returns ZRANGEBYSCORE cases with no returned members.
func redisZRangeByScoreEmptyCases() []zRangeByScoreRedisTest {
	return []zRangeByScoreRedisTest{
		{
			name:        "RangeWithNoMembers",
			key:         "key3",
			minScore:    "50",
			maxScore:    "60",
			optsTable:   nilLuaTable,
			expected:    emptyLuaTable,
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key, _, _ string, opts redis.ZRangeBy) {
				mock.ExpectZRangeByScore(key, &opts).SetVal([]string{})
			},
		},
		{
			name:        "NonExistentKey",
			key:         "key4",
			minScore:    "10",
			maxScore:    "20",
			optsTable:   nilLuaTable,
			expected:    emptyLuaTable,
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key, _, _ string, opts redis.ZRangeBy) {
				mock.ExpectZRangeByScore(key, &opts).SetVal([]string{})
			},
		},
	}
}

// redisZRangeByScoreErrorCases returns failing ZRANGEBYSCORE cases.
func redisZRangeByScoreErrorCases() []zRangeByScoreRedisTest {
	return []zRangeByScoreRedisTest{
		{
			name:        "RedisError",
			key:         "key5",
			minScore:    "10",
			maxScore:    "20",
			optsTable:   nilLuaTable,
			expected:    nilLuaTable,
			expectedErr: lua.LString("context deadline exceeded"),
			setupMock: func(mock redismock.ClientMock, key, _, _ string, opts redis.ZRangeBy) {
				mock.ExpectZRangeByScore(key, &opts).SetErr(context.DeadlineExceeded)
			},
		},
	}
}

// zRangeByScoreOffsetOptions returns Lua options for offset/count range tests.
func zRangeByScoreOffsetOptions(L *lua.LState) *lua.LTable {
	tbl := L.NewTable()
	tbl.RawSetString("offset", lua.LNumber(1))
	tbl.RawSetString("count", lua.LNumber(2))

	return tbl
}

// runRedisZRangeByScoreCase executes one ZRANGEBYSCORE scenario.
func runRedisZRangeByScoreCase(t *testing.T, tt zRangeByScoreRedisTest) {
	t.Helper()

	L, mock, _ := newRedisLuaCommandState(t)
	opts := setRedisZRangeByScoreGlobals(L, tt)

	if tt.setupMock != nil {
		tt.setupMock(mock, tt.key, tt.minScore, tt.maxScore, opts)
	}

	if err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_zrangebyscore("default", key, minScore, maxScore, opts)`); err != nil {
		t.Fatalf("Running Lua code failed: %v", err)
	}

	assertZSetTableOrNil(t, "redis_zrangebyscore", L.GetGlobal("result"), tt.expected(L))
	checkLuaError(t, L.GetGlobal("err"), tt.expectedErr)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("mock expectations were not met: %v", err)
	}

	mock.ClearExpect()
}

// setRedisZRangeByScoreGlobals installs Lua globals and returns the Redis expectation options.
func setRedisZRangeByScoreGlobals(L *lua.LState, tt zRangeByScoreRedisTest) redis.ZRangeBy {
	L.SetGlobal("opts", zRangeByScoreOptionsValue(L, tt.optsTable))
	L.SetGlobal("key", lua.LString(tt.key))
	L.SetGlobal("minScore", lua.LString(tt.minScore))
	L.SetGlobal("maxScore", lua.LString(tt.maxScore))

	return redis.ZRangeBy{Min: tt.minScore, Max: tt.maxScore}
}

// zRangeByScoreOptionsValue resolves the optional Lua options table.
func zRangeByScoreOptionsValue(L *lua.LState, optsTable func(*lua.LState) *lua.LTable) lua.LValue {
	if optsTable == nil {
		return lua.LNil
	}

	luaOpts := optsTable(L)
	if luaOpts == nil {
		return lua.LNil
	}

	return luaOpts
}

// assertZSetTableOrNil checks ZSet commands that return either a Lua table or nil.
func assertZSetTableOrNil(t *testing.T, cmdName string, gotResult lua.LValue, expectedResult *lua.LTable) {
	t.Helper()

	if expectedResult == nil {
		if gotResult != lua.LNil {
			t.Errorf("%s() result = %s, want nil", cmdName, gotResult)
		}

		return
	}

	tbl, ok := gotResult.(*lua.LTable)
	if !ok {
		t.Errorf("%s() result = %s, want %s", cmdName, gotResult.Type(), expectedResult)

		return
	}

	if !luaTablesAreEqual(tbl, expectedResult) {
		t.Errorf("%s() result = %s, want %s", cmdName, gotResult, expectedResult)
	}
}

func TestRedisZRem(t *testing.T) {
	for _, tt := range redisZRemCases() {
		t.Run(tt.name, func(t *testing.T) {
			runRedisZRemCase(t, tt)
		})
	}
}

type zRemRedisTest struct {
	name        string
	key         string
	members     func(L *lua.LState) *lua.LTable
	expectedRes lua.LValue
	expectedErr lua.LValue
	setupMock   func(mock redismock.ClientMock, key string, members []any)
}

// redisZRemCases returns Redis ZREM behavior cases.
func redisZRemCases() []zRemRedisTest {
	return []zRemRedisTest{
		{
			name:        "RemoveSingleMember",
			key:         "key1",
			members:     zMemberTable("member1"),
			expectedRes: lua.LNumber(1),
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key string, members []any) {
				mock.ExpectZRem(key, members...).SetVal(1)
			},
		},
		{
			name:        "RemoveMultipleMembers",
			key:         "key2",
			members:     zMemberTable("member1", "member2"),
			expectedRes: lua.LNumber(2),
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key string, members []any) {
				mock.ExpectZRem(key, members...).SetVal(2)
			},
		},
		{
			name:        "RemoveNonExistentMembers",
			key:         "key3",
			members:     zMemberTable("member1", "member2"),
			expectedRes: lua.LNumber(0),
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key string, members []any) {
				mock.ExpectZRem(key, members...).SetVal(0)
			},
		},
		{
			name:        "RemoveFromEmptyKey",
			key:         "key4",
			members:     zMemberTable("member1"),
			expectedRes: lua.LNumber(0),
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key string, members []any) {
				mock.ExpectZRem(key, members...).SetVal(0)
			},
		},
		{
			name:        "RedisError",
			key:         "key5",
			members:     zMemberTable("member1"),
			expectedRes: lua.LNil,
			expectedErr: lua.LString("context deadline exceeded"),
			setupMock: func(mock redismock.ClientMock, key string, members []any) {
				mock.ExpectZRem(key, members...).SetErr(context.DeadlineExceeded)
			},
		},
	}
}

// runRedisZRemCase executes one ZREM scenario.
func runRedisZRemCase(t *testing.T, tt zRemRedisTest) {
	t.Helper()

	L, mock, _ := newRedisLuaCommandState(t)
	luaMembers := tt.members(L)
	members := zMembersFromLuaTable(luaMembers)

	if tt.setupMock != nil {
		tt.setupMock(mock, tt.key, members)
	}

	L.SetGlobal("key", lua.LString(tt.key))
	L.SetGlobal("members", luaMembers)

	if err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_zrem("default", key, members)`); err != nil {
		t.Fatalf("Running Lua code failed: %v", err)
	}

	assertLuaValueEqual(t, "redis_zrem", L.GetGlobal("result"), tt.expectedRes)
	checkLuaError(t, L.GetGlobal("err"), tt.expectedErr)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("mock expectations were not met: %v", err)
	}

	mock.ClearExpect()
}

// zMembersFromLuaTable converts a Lua member table into Redis command arguments.
func zMembersFromLuaTable(luaMembers *lua.LTable) []any {
	members := make([]any, 0, luaMembers.Len())
	luaMembers.ForEach(func(_, value lua.LValue) {
		members = append(members, value.String())
	})

	return members
}

func TestRedisZRemRangeByScore(t *testing.T) {
	runRedisLuaCommandTests(t, "redis_zremrangebyscore", `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_zremrangebyscore("default", key, minScore, maxScore)`, []redisLuaCommandTest{
		{
			name: "RemoveRangeWithExistingMembers",
			luaGlobals: map[string]lua.LValue{
				"key":      lua.LString("key1"),
				"minScore": lua.LString("10"),
				"maxScore": lua.LString("30"),
			},
			expectedResult: lua.LNumber(3),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectZRemRangeByScore("key1", "10", "30").SetVal(3)
			},
		},
		{
			name: "RemoveRangeWithNoMembers",
			luaGlobals: map[string]lua.LValue{
				"key":      lua.LString("key2"),
				"minScore": lua.LString("40"),
				"maxScore": lua.LString("50"),
			},
			expectedResult: lua.LNumber(0),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectZRemRangeByScore("key2", "40", "50").SetVal(0)
			},
		},
		{
			name: "RemoveRangeFromNonExistentKey",
			luaGlobals: map[string]lua.LValue{
				"key":      lua.LString("key3"),
				"minScore": lua.LString("10"),
				"maxScore": lua.LString("20"),
			},
			expectedResult: lua.LNumber(0),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectZRemRangeByScore("key3", "10", "20").SetVal(0)
			},
		},
		{
			name: "RedisError",
			luaGlobals: map[string]lua.LValue{
				"key":      lua.LString("key4"),
				"minScore": lua.LString("10"),
				"maxScore": lua.LString("20"),
			},
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("context deadline exceeded"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectZRemRangeByScore("key4", "10", "20").SetErr(context.DeadlineExceeded)
			},
		},
	})
}

func TestRedisZRemRangeByRank(t *testing.T) {
	runRedisLuaCommandTests(t, "redis_zremrangebyrank", redisZRemRangeByRankLuaCode(), redisZRemRangeByRankCases())
}

// redisZRemRangeByRankLuaCode returns the Lua script used by Redis ZREMRANGEBYRANK cases.
func redisZRemRangeByRankLuaCode() string {
	return `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_zremrangebyrank("default", key, start, stop)`
}

// redisZRemRangeByRankCases returns Redis ZREMRANGEBYRANK behavior cases.
func redisZRemRangeByRankCases() []redisLuaCommandTest {
	return []redisLuaCommandTest{
		zRemRangeByRankCase("RemoveRangeWithExistingMembers", "key1", 0, 2, lua.LNumber(3), lua.LNil, expectZRemRangeByRankValue("key1", 0, 2, 3)),
		zRemRangeByRankCase("RemoveRangeWithNoMembers", "key2", 10, 20, lua.LNumber(0), lua.LNil, expectZRemRangeByRankValue("key2", 10, 20, 0)),
		zRemRangeByRankCase("RemoveRangeFromNonExistentKey", "key3", 0, -1, lua.LNumber(0), lua.LNil, expectZRemRangeByRankValue("key3", 0, -1, 0)),
		zRemRangeByRankCase("RemoveNegativeRange", "key4", -3, -1, lua.LNumber(3), lua.LNil, expectZRemRangeByRankValue("key4", -3, -1, 3)),
		zRemRangeByRankCase("RedisError", "key5", 0, 10, lua.LNil, lua.LString("context deadline exceeded"), expectZRemRangeByRankError),
	}
}

// zRemRangeByRankCase builds a ZREMRANGEBYRANK command case.
func zRemRangeByRankCase(
	name string,
	key string,
	start int64,
	stop int64,
	expectedResult lua.LValue,
	expectedErr lua.LValue,
	prepareMock func(redismock.ClientMock),
) redisLuaCommandTest {
	return redisLuaCommandTest{
		name:           name,
		luaGlobals:     zRankRangeGlobals(key, start, stop),
		expectedResult: expectedResult,
		expectedErr:    expectedErr,
		prepareMockRedis: func(mock redismock.ClientMock) {
			prepareMock(mock)
		},
	}
}

// zRankRangeGlobals returns Lua globals for rank-range commands.
func zRankRangeGlobals(key string, start, stop int64) map[string]lua.LValue {
	return map[string]lua.LValue{
		"key":   lua.LString(key),
		"start": lua.LNumber(start),
		"stop":  lua.LNumber(stop),
	}
}

// expectZRemRangeByRankValue configures a successful ZREMRANGEBYRANK expectation.
func expectZRemRangeByRankValue(key string, start, stop, value int64) func(redismock.ClientMock) {
	return func(mock redismock.ClientMock) {
		mock.ExpectZRemRangeByRank(key, start, stop).SetVal(value)
	}
}

// expectZRemRangeByRankError configures a failing ZREMRANGEBYRANK expectation.
func expectZRemRangeByRankError(mock redismock.ClientMock) {
	mock.ExpectZRemRangeByRank("key5", 0, 10).SetErr(context.DeadlineExceeded)
}

func TestRedisZRank(t *testing.T) {
	tests := zMemberLookupCases("zrank", lua.LNumber(0))

	runKeyMemberRedisTests(t, "redis_zrank", `"default"`, false, tests)
}

// TestRedisZCount tests the RedisZCount function which counts the number of members in a sorted set with scores between min and max.
// Added in version 1.7.7
func TestRedisZCount(t *testing.T) {
	runRedisLuaCommandTests(t, "redis_zcount", `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_zcount("default", key, min, max)`, []redisLuaCommandTest{
		{
			name:           "ValidRange",
			luaGlobals:     zScoreRangeGlobals("key1", "10", "20"),
			expectedResult: lua.LNumber(5),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectZCount("key1", "10", "20").SetVal(5)
			},
		},
		{
			name:           "EmptyRange",
			luaGlobals:     zScoreRangeGlobals("key2", "30", "40"),
			expectedResult: lua.LNumber(0),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectZCount("key2", "30", "40").SetVal(0)
			},
		},
		{
			name:           "InfiniteRange",
			luaGlobals:     zScoreRangeGlobals("key3", "-inf", "+inf"),
			expectedResult: lua.LNumber(10),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectZCount("key3", "-inf", "+inf").SetVal(10)
			},
		},
		{
			name:           "NonExistentKey",
			luaGlobals:     zScoreRangeGlobals("nonexistent", "0", "100"),
			expectedResult: lua.LNumber(0),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectZCount("nonexistent", "0", "100").SetVal(0)
			},
		},
		{
			name:           "RedisError",
			luaGlobals:     zScoreRangeGlobals("key4", "10", "20"),
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("context deadline exceeded"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectZCount("key4", "10", "20").SetErr(context.DeadlineExceeded)
			},
		},
	})
}

// TestRedisZIncrBy tests the RedisZIncrBy function which increments the score of a member in a sorted set.
// Added in version 1.7.18
func TestRedisZIncrBy(t *testing.T) {
	runRedisLuaCommandTests(t, "redis_zincrby", `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_zincrby("default", key, increment, member)`, []redisLuaCommandTest{
		{
			name:           "IncrementExistingMember",
			luaGlobals:     zIncrByGlobals("key1", 1.0, "member1"),
			expectedResult: lua.LNumber(11.0),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectZIncrBy("key1", 1.0, "member1").SetVal(11.0)
			},
		},
		{
			name:           "DecrementExistingMember",
			luaGlobals:     zIncrByGlobals("key2", -5.0, "member2"),
			expectedResult: lua.LNumber(5.0),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectZIncrBy("key2", -5.0, "member2").SetVal(5.0)
			},
		},
		{
			name:           "IncrementNonExistingMember",
			luaGlobals:     zIncrByGlobals("key3", 2.5, "newmember"),
			expectedResult: lua.LNumber(2.5),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectZIncrBy("key3", 2.5, "newmember").SetVal(2.5)
			},
		},
		{
			name:           "RedisError",
			luaGlobals:     zIncrByGlobals("key4", 1.0, "member1"),
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("context deadline exceeded"),
			prepareMockRedis: func(mock redismock.ClientMock) {
				mock.ExpectZIncrBy("key4", 1.0, "member1").SetErr(context.DeadlineExceeded)
			},
		},
	})
}

// TestRedisZScore tests the RedisZScore function which retrieves the score of a member in a sorted set.
// Added in version 1.7.7
func TestRedisZScore(t *testing.T) {
	tests := zMemberLookupCases("zscore", lua.LNumber(10.5))

	runKeyMemberRedisTests(t, "redis_zscore", `"default"`, false, tests)
}

// TestRedisZRevRank tests the RedisZRevRank function which retrieves the rank of a member in a sorted set, with scores ordered from high to low.
func TestRedisZRevRank(t *testing.T) {
	tests := zMemberLookupCases("zrevrank", lua.LNumber(0))

	runKeyMemberRedisTests(t, "redis_zrevrank", `"default"`, false, tests)
}

// TestRedisZScoreWithCustomHandle tests the RedisZScore function with a custom connection handle
func TestRedisZScoreWithCustomHandle(t *testing.T) {
	tests := []keyMemberRedisTest{
		{
			name:           "MemberExistsWithCustomHandle",
			key:            "key1",
			member:         "member1",
			expectedResult: lua.LNumber(10.5),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock, key, member string) {
				mock.ExpectZScore(key, member).SetVal(10.5)
			},
		},
	}

	runKeyMemberRedisTests(t, "redis_zscore", "custom_handle", true, tests)
}

// TestRedisZRevRankWithCustomHandle tests the RedisZRevRank function with a custom connection handle
func TestRedisZRevRankWithCustomHandle(t *testing.T) {
	tests := []keyMemberRedisTest{
		{
			name:           "MemberExistsWithCustomHandle",
			key:            "key1",
			member:         "member1",
			expectedResult: lua.LNumber(0),
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock, key, member string) {
				mock.ExpectZRevRank(key, member).SetVal(0)
			},
		},
	}

	runKeyMemberRedisTests(t, "redis_zrevrank", "custom_handle", true, tests)
}

// nilLuaTable returns no Lua table for optional table-based test inputs.
func nilLuaTable(_ *lua.LState) *lua.LTable {
	return nil
}

// emptyLuaTable returns an empty Lua table for expected empty result cases.
func emptyLuaTable(L *lua.LState) *lua.LTable {
	return L.NewTable()
}

// zMemberTable builds a Lua table factory for ZSet member lists.
func zMemberTable(members ...string) func(*lua.LState) *lua.LTable {
	return func(L *lua.LState) *lua.LTable {
		tbl := L.NewTable()

		for _, member := range members {
			tbl.Append(lua.LString(member))
		}

		return tbl
	}
}

// zScoreRangeGlobals returns Lua globals for min/max score range commands.
func zScoreRangeGlobals(key, minScore, maxScore string) map[string]lua.LValue {
	return map[string]lua.LValue{
		"key": lua.LString(key),
		"min": lua.LString(minScore),
		"max": lua.LString(maxScore),
	}
}

// zIncrByGlobals returns Lua globals for ZINCRBY command tests.
func zIncrByGlobals(key string, increment float64, member string) map[string]lua.LValue {
	return map[string]lua.LValue{
		"key":       lua.LString(key),
		"increment": lua.LNumber(increment),
		"member":    lua.LString(member),
	}
}

// zMemberLookupCases builds the shared success, nil, empty-key, and deadline cases for key/member ZSet lookups.
func zMemberLookupCases(command string, foundResult lua.LValue) []keyMemberRedisTest {
	return []keyMemberRedisTest{
		{
			name:           "MemberExists",
			key:            "key1",
			member:         "member1",
			expectedResult: foundResult,
			expectedErr:    lua.LNil,
			prepareMockRedis: func(mock redismock.ClientMock, key, member string) {
				prepareZMemberLookupFound(command, mock, key, member, foundResult)
			},
		},
		{
			name:           "MemberNotExists",
			key:            "key2",
			member:         "nonexistent",
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("redis: nil"),
			prepareMockRedis: func(mock redismock.ClientMock, key, member string) {
				prepareZMemberLookupError(command, mock, key, member, redis.Nil)
			},
		},
		{
			name:           "EmptyKey",
			key:            "",
			member:         "member1",
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("redis: nil"),
			prepareMockRedis: func(mock redismock.ClientMock, key, member string) {
				prepareZMemberLookupError(command, mock, key, member, redis.Nil)
			},
		},
		{
			name:           "RedisError",
			key:            "key4",
			member:         "member1",
			expectedResult: lua.LNil,
			expectedErr:    lua.LString("context deadline exceeded"),
			prepareMockRedis: func(mock redismock.ClientMock, key, member string) {
				prepareZMemberLookupError(command, mock, key, member, context.DeadlineExceeded)
			},
		},
	}
}

// prepareZMemberLookupFound configures the success expectation for a key/member ZSet lookup.
func prepareZMemberLookupFound(command string, mock redismock.ClientMock, key, member string, foundResult lua.LValue) {
	switch command {
	case "zrank":
		mock.ExpectZRank(key, member).SetVal(int64(lua.LVAsNumber(foundResult)))
	case "zscore":
		mock.ExpectZScore(key, member).SetVal(float64(lua.LVAsNumber(foundResult)))
	case "zrevrank":
		mock.ExpectZRevRank(key, member).SetVal(int64(lua.LVAsNumber(foundResult)))
	}
}

// prepareZMemberLookupError configures an error expectation for a key/member ZSet lookup.
func prepareZMemberLookupError(command string, mock redismock.ClientMock, key, member string, err error) {
	switch command {
	case "zrank":
		mock.ExpectZRank(key, member).SetErr(err)
	case "zscore":
		mock.ExpectZScore(key, member).SetErr(err)
	case "zrevrank":
		mock.ExpectZRevRank(key, member).SetErr(err)
	}
}
