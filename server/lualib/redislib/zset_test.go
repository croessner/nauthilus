package redislib

import (
	"context"
	"sort"
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestRedisZAdd(t *testing.T) {
	tests := []struct {
		name          string
		key           string
		luaTable      func(L *lua.LState) *lua.LTable
		expectedCount lua.LValue
		expectedErr   lua.LValue
		setupMock     func(mock redismock.ClientMock, key string, zSet []redis.Z)
	}{
		{
			name: "AddSingleEntry",
			key:  "key1",
			luaTable: func(L *lua.LState) *lua.LTable {
				tbl := L.NewTable()
				tbl.RawSetString("member1", lua.LNumber(10))

				return tbl
			},
			expectedCount: lua.LNumber(1),
			expectedErr:   lua.LNil,
			setupMock: func(mock redismock.ClientMock, key string, zSet []redis.Z) {
				mock.ExpectZAdd(key, zSet...).SetVal(1)
			},
		},
		{
			name: "AddMultipleEntries",
			key:  "key2",
			luaTable: func(L *lua.LState) *lua.LTable {
				tbl := L.NewTable()
				tbl.RawSetString("member1", lua.LNumber(10))
				tbl.RawSetString("member2", lua.LNumber(20))

				return tbl
			},
			expectedCount: lua.LNumber(2),
			expectedErr:   lua.LNil,
			setupMock: func(mock redismock.ClientMock, key string, zSet []redis.Z) {
				mock.ExpectZAdd(key, zSet...).SetVal(2)
			},
		},
		{
			name: "AddEmptyTable",
			key:  "key3",
			luaTable: func(L *lua.LState) *lua.LTable {
				return L.NewTable()
			},
			expectedCount: lua.LNumber(0),
			expectedErr:   lua.LNil,
			setupMock: func(mock redismock.ClientMock, key string, zSet []redis.Z) {
				mock.ExpectZAdd(key, zSet...).SetVal(0)
			},
		},
		{
			name: "RedisError",
			key:  "key5",
			luaTable: func(L *lua.LState) *lua.LTable {
				tbl := L.NewTable()
				tbl.RawSetString("member1", lua.LNumber(10))

				return tbl
			},
			expectedCount: lua.LNil,
			expectedErr:   lua.LString("context deadline exceeded"),
			setupMock: func(mock redismock.ClientMock, key string, zSet []redis.Z) {
				mock.ExpectZAdd(key, zSet...).SetErr(context.DeadlineExceeded)
			},
		},
	}

	L := lua.NewState()

	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background()))

	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			rediscli.NewTestClient(db)

			zSet := make([]redis.Z, 0)

			if tt.luaTable != nil {
				luaTbl := tt.luaTable(L)

				elements := make([]struct {
					Member string
					Score  float64
				}, 0)

				luaTbl.ForEach(func(key, value lua.LValue) {
					member, errMember := convert.LuaValue(key)
					score, errScore := convert.LuaValue(value)

					if errMember == nil && errScore == nil {
						elements = append(elements, struct {
							Member string
							Score  float64
						}{
							Member: member.(string),
							Score:  score.(float64),
						})
					}
				})

				sort.Slice(elements, func(i, j int) bool {
					return elements[i].Member < elements[j].Member
				})

				for _, elem := range elements {
					zSet = append(zSet, redis.Z{
						Member: elem.Member,
						Score:  elem.Score,
					})
				}

				tt.setupMock(mock, tt.key, zSet)
				L.SetGlobal("table", luaTbl)
			}

			L.SetGlobal("key", lua.LString(tt.key))

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_zadd("default", key, table)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedCount.Type() || gotResult.String() != tt.expectedCount.String() {
				t.Errorf("redis_zadd() gotResult = %s, want %s", gotResult, tt.expectedCount)
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("mock expectations were not met: %v", err)
			}

			mock.ClearExpect()
		})
	}
}

func TestRedisZRange(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		start, stop int64
		expected    func(L *lua.LState) *lua.LTable
		expectedErr lua.LValue
		setupMock   func(mock redismock.ClientMock, key string, start, stop int64)
	}{
		{
			name:  "ValidRangeWithMultipleMembers",
			key:   "key1",
			start: 0,
			stop:  2,
			expected: func(L *lua.LState) *lua.LTable {
				tbl := L.NewTable()

				tbl.Append(lua.LString("member1"))
				tbl.Append(lua.LString("member2"))

				return tbl
			},
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key string, start, stop int64) {
				mock.ExpectZRange(key, start, stop).SetVal([]string{"member1", "member2"})
			},
		},
		{
			name:  "ValidRangeWithNoMembers",
			key:   "key2",
			start: 0,
			stop:  1,
			expected: func(L *lua.LState) *lua.LTable {
				return L.NewTable()
			},
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key string, start, stop int64) {
				mock.ExpectZRange(key, start, stop).SetVal([]string{})
			},
		},
		{
			name:  "NonExistentKey",
			key:   "key3",
			start: 0,
			stop:  1,
			expected: func(L *lua.LState) *lua.LTable {
				return L.NewTable()
			},
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key string, start, stop int64) {
				mock.ExpectZRange(key, start, stop).SetVal([]string{})
			},
		},
		{
			name:  "RedisError",
			key:   "key4",
			start: 0,
			stop:  1,
			expected: func(L *lua.LState) *lua.LTable {
				return nil
			},
			expectedErr: lua.LString("context deadline exceeded"),
			setupMock: func(mock redismock.ClientMock, key string, start, stop int64) {
				mock.ExpectZRange(key, start, stop).SetErr(context.DeadlineExceeded)
			},
		},
	}

	L := lua.NewState()

	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background()))

	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			rediscli.NewTestClient(db)

			if tt.setupMock != nil {
				tt.setupMock(mock, tt.key, tt.start, tt.stop)
			}

			L.SetGlobal("key", lua.LString(tt.key))
			L.SetGlobal("start", lua.LNumber(tt.start))
			L.SetGlobal("stop", lua.LNumber(tt.stop))

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_zrange("default", key, start, stop)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			expectedResult := tt.expected(L)

			if expectedResult != nil && !luaTablesAreEqual(gotResult.(*lua.LTable), expectedResult) {
				t.Errorf("redis_zrange() result = %s, want %s", gotResult, expectedResult)
			} else if expectedResult == nil && gotResult != lua.LNil {
				t.Errorf("redis_zrange() result = %s, want nil", gotResult)
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("mock expectations were not met: %v", err)
			}

			mock.ClearExpect()
		})
	}
}

func TestRedisZRevRange(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		start, stop int64
		expected    func(L *lua.LState) *lua.LTable
		expectedErr lua.LValue
		setupMock   func(mock redismock.ClientMock, key string, start, stop int64)
	}{
		{
			name:  "ValidReverseRangeWithMultipleMembers",
			key:   "key1",
			start: 0,
			stop:  2,
			expected: func(L *lua.LState) *lua.LTable {
				tbl := L.NewTable()
				tbl.Append(lua.LString("member3"))
				tbl.Append(lua.LString("member2"))
				tbl.Append(lua.LString("member1"))

				return tbl
			},
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key string, start, stop int64) {
				mock.ExpectZRevRange(key, start, stop).SetVal([]string{"member3", "member2", "member1"})
			},
		},
		{
			name:  "ValidReverseRangeWithNoMembers",
			key:   "key2",
			start: 0,
			stop:  1,
			expected: func(L *lua.LState) *lua.LTable {
				return L.NewTable()
			},
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key string, start, stop int64) {
				mock.ExpectZRevRange(key, start, stop).SetVal([]string{})
			},
		},
		{
			name:  "NonExistentKey",
			key:   "key3",
			start: 0,
			stop:  1,
			expected: func(L *lua.LState) *lua.LTable {
				return L.NewTable()
			},
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key string, start, stop int64) {
				mock.ExpectZRevRange(key, start, stop).SetVal([]string{})
			},
		},
		{
			name:  "RedisError",
			key:   "key4",
			start: 0,
			stop:  1,
			expected: func(L *lua.LState) *lua.LTable {
				return nil
			},
			expectedErr: lua.LString("context deadline exceeded"),
			setupMock: func(mock redismock.ClientMock, key string, start, stop int64) {
				mock.ExpectZRevRange(key, start, stop).SetErr(context.DeadlineExceeded)
			},
		},
	}

	L := lua.NewState()

	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background()))

	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			rediscli.NewTestClient(db)

			if tt.setupMock != nil {
				tt.setupMock(mock, tt.key, tt.start, tt.stop)
			}

			L.SetGlobal("key", lua.LString(tt.key))
			L.SetGlobal("start", lua.LNumber(tt.start))
			L.SetGlobal("stop", lua.LNumber(tt.stop))

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_zrevrange("default", key, start, stop)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			expectedResult := tt.expected(L)

			if expectedResult != nil && !luaTablesAreEqual(gotResult.(*lua.LTable), expectedResult) {
				t.Errorf("redis_zrevrange() result = %s, want %s", gotResult, expectedResult)
			} else if expectedResult == nil && gotResult != lua.LNil {
				t.Errorf("redis_zrevrange() result = %s, want nil", gotResult)
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("mock expectations were not met: %v", err)
			}

			mock.ClearExpect()
		})
	}
}

func TestRedisZRangeByScore(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		minScore    string
		maxScore    string
		optsTable   func(L *lua.LState) *lua.LTable
		expected    func(L *lua.LState) *lua.LTable
		expectedErr lua.LValue
		setupMock   func(mock redismock.ClientMock, key, minScore, maxScore string, opts redis.ZRangeBy)
	}{
		{
			name:     "ValidRangeWithMultipleMembers",
			key:      "key1",
			minScore: "10",
			maxScore: "20",
			optsTable: func(L *lua.LState) *lua.LTable {
				return nil
			},
			expected: func(L *lua.LState) *lua.LTable {
				tbl := L.NewTable()

				tbl.Append(lua.LString("member1"))
				tbl.Append(lua.LString("member2"))

				return tbl
			},
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key, minScore, maxScore string, opts redis.ZRangeBy) {
				mock.ExpectZRangeByScore(key, &opts).SetVal([]string{"member1", "member2"})
			},
		},
		{
			name:     "ValidRangeWithOffsetAndCount",
			key:      "key2",
			minScore: "10",
			maxScore: "30",
			optsTable: func(L *lua.LState) *lua.LTable {
				tbl := L.NewTable()

				tbl.RawSetString("offset", lua.LNumber(1))
				tbl.RawSetString("count", lua.LNumber(2))

				return tbl
			},
			expected: func(L *lua.LState) *lua.LTable {
				tbl := L.NewTable()

				tbl.Append(lua.LString("member2"))
				tbl.Append(lua.LString("member3"))

				return tbl
			},
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key, minScore, maxScore string, opts redis.ZRangeBy) {
				opts.Offset = 1
				opts.Count = 2
				mock.ExpectZRangeByScore(key, &opts).SetVal([]string{"member2", "member3"})
			},
		},
		{
			name:     "RangeWithNoMembers",
			key:      "key3",
			minScore: "50",
			maxScore: "60",
			optsTable: func(L *lua.LState) *lua.LTable {
				return nil
			},
			expected: func(L *lua.LState) *lua.LTable {
				return L.NewTable()
			},
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key, minScore, maxScore string, opts redis.ZRangeBy) {
				mock.ExpectZRangeByScore(key, &opts).SetVal([]string{})
			},
		},
		{
			name:     "NonExistentKey",
			key:      "key4",
			minScore: "10",
			maxScore: "20",
			optsTable: func(L *lua.LState) *lua.LTable {
				return nil
			},
			expected: func(L *lua.LState) *lua.LTable {
				return L.NewTable()
			},
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key, minScore, maxScore string, opts redis.ZRangeBy) {
				mock.ExpectZRangeByScore(key, &opts).SetVal([]string{})
			},
		},
		{
			name:     "RedisError",
			key:      "key5",
			minScore: "10",
			maxScore: "20",
			optsTable: func(L *lua.LState) *lua.LTable {
				return nil
			},
			expected: func(L *lua.LState) *lua.LTable {
				return nil
			},
			expectedErr: lua.LString("context deadline exceeded"),
			setupMock: func(mock redismock.ClientMock, key, minScore, maxScore string, opts redis.ZRangeBy) {
				mock.ExpectZRangeByScore(key, &opts).SetErr(context.DeadlineExceeded)
			},
		},
	}

	L := lua.NewState()

	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background()))

	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			rediscli.NewTestClient(db)

			opts := redis.ZRangeBy{
				Min:    tt.minScore,
				Max:    tt.maxScore,
				Offset: 0,
				Count:  0,
			}

			if tt.optsTable != nil {
				luaOpts := tt.optsTable(L)
				optsTable := L.NewTable()

				if luaOpts != nil {
					luaOpts.ForEach(func(k, v lua.LValue) {
						optsTable.RawSet(k, v)
					})
				}

				L.SetGlobal("opts", luaOpts)
			} else {
				L.SetGlobal("opts", lua.LNil)
			}

			L.SetGlobal("key", lua.LString(tt.key))
			L.SetGlobal("minScore", lua.LString(tt.minScore))
			L.SetGlobal("maxScore", lua.LString(tt.maxScore))

			if tt.setupMock != nil {
				tt.setupMock(mock, tt.key, tt.minScore, tt.maxScore, opts)
			}

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_zrangebyscore("default", key, minScore, maxScore, opts)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			expectedResult := tt.expected(L)

			if expectedResult != nil && !luaTablesAreEqual(gotResult.(*lua.LTable), expectedResult) {
				t.Errorf("redis_zrangebyscore() result = %s, want %s", gotResult, expectedResult)
			} else if expectedResult == nil && gotResult != lua.LNil {
				t.Errorf("redis_zrangebyscore() result = %s, want nil", gotResult)
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("mock expectations were not met: %v", err)
			}

			mock.ClearExpect()
		})
	}
}

func TestRedisZRem(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		members     func(L *lua.LState) *lua.LTable
		expectedRes lua.LValue
		expectedErr lua.LValue
		setupMock   func(mock redismock.ClientMock, key string, members []any)
	}{
		{
			name: "RemoveSingleMember",
			key:  "key1",
			members: func(L *lua.LState) *lua.LTable {
				tbl := L.NewTable()

				tbl.Append(lua.LString("member1"))

				return tbl
			},
			expectedRes: lua.LNumber(1),
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key string, members []any) {
				mock.ExpectZRem(key, members...).SetVal(1)
			},
		},
		{
			name: "RemoveMultipleMembers",
			key:  "key2",
			members: func(L *lua.LState) *lua.LTable {
				tbl := L.NewTable()

				tbl.Append(lua.LString("member1"))
				tbl.Append(lua.LString("member2"))

				return tbl
			},
			expectedRes: lua.LNumber(2),
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key string, members []any) {
				mock.ExpectZRem(key, members...).SetVal(2)
			},
		},
		{
			name: "RemoveNonExistentMembers",
			key:  "key3",
			members: func(L *lua.LState) *lua.LTable {
				tbl := L.NewTable()

				tbl.Append(lua.LString("member1"))
				tbl.Append(lua.LString("member2"))

				return tbl
			},
			expectedRes: lua.LNumber(0),
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key string, members []any) {
				mock.ExpectZRem(key, members...).SetVal(0)
			},
		},
		{
			name: "RemoveFromEmptyKey",
			key:  "key4",
			members: func(L *lua.LState) *lua.LTable {
				tbl := L.NewTable()

				tbl.Append(lua.LString("member1"))

				return tbl
			},
			expectedRes: lua.LNumber(0),
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key string, members []any) {
				mock.ExpectZRem(key, members...).SetVal(0)
			},
		},
		{
			name: "RedisError",
			key:  "key5",
			members: func(L *lua.LState) *lua.LTable {
				tbl := L.NewTable()

				tbl.Append(lua.LString("member1"))

				return tbl
			},
			expectedRes: lua.LNil,
			expectedErr: lua.LString("context deadline exceeded"),
			setupMock: func(mock redismock.ClientMock, key string, members []any) {
				mock.ExpectZRem(key, members...).SetErr(context.DeadlineExceeded)
			},
		},
	}

	L := lua.NewState()

	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background()))

	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			rediscli.NewTestClient(db)

			var members []any

			luaMembers := tt.members(L)
			luaMembers.ForEach(func(_, v lua.LValue) {
				members = append(members, v.String())
			})

			if tt.setupMock != nil {
				tt.setupMock(mock, tt.key, members)
			}

			L.SetGlobal("key", lua.LString(tt.key))
			L.SetGlobal("members", luaMembers)

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_zrem("default", key, members)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedRes.Type() || gotResult.String() != tt.expectedRes.String() {
				t.Errorf("redis_zrem() gotResult = %s, want %s", gotResult, tt.expectedRes)
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("mock expectations were not met: %v", err)
			}

			mock.ClearExpect()
		})
	}
}

func TestRedisZRemRangeByScore(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		minScore    string
		maxScore    string
		expectedRes lua.LValue
		expectedErr lua.LValue
		setupMock   func(mock redismock.ClientMock, key, minScore, maxScore string)
	}{
		{
			name:        "RemoveRangeWithExistingMembers",
			key:         "key1",
			minScore:    "10",
			maxScore:    "30",
			expectedRes: lua.LNumber(3),
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key, minScore, maxScore string) {
				mock.ExpectZRemRangeByScore(key, minScore, maxScore).SetVal(3)
			},
		},
		{
			name:        "RemoveRangeWithNoMembers",
			key:         "key2",
			minScore:    "40",
			maxScore:    "50",
			expectedRes: lua.LNumber(0),
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key, minScore, maxScore string) {
				mock.ExpectZRemRangeByScore(key, minScore, maxScore).SetVal(0)
			},
		},
		{
			name:        "RemoveRangeFromNonExistentKey",
			key:         "key3",
			minScore:    "10",
			maxScore:    "20",
			expectedRes: lua.LNumber(0),
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key, minScore, maxScore string) {
				mock.ExpectZRemRangeByScore(key, minScore, maxScore).SetVal(0)
			},
		},
		{
			name:        "RedisError",
			key:         "key4",
			minScore:    "10",
			maxScore:    "20",
			expectedRes: lua.LNil,
			expectedErr: lua.LString("context deadline exceeded"),
			setupMock: func(mock redismock.ClientMock, key, minScore, maxScore string) {
				mock.ExpectZRemRangeByScore(key, minScore, maxScore).SetErr(context.DeadlineExceeded)
			},
		},
	}

	L := lua.NewState()

	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background()))

	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			rediscli.NewTestClient(db)

			if tt.setupMock != nil {
				tt.setupMock(mock, tt.key, tt.minScore, tt.maxScore)
			}

			L.SetGlobal("key", lua.LString(tt.key))
			L.SetGlobal("minScore", lua.LString(tt.minScore))
			L.SetGlobal("maxScore", lua.LString(tt.maxScore))

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_zremrangebyscore("default", key, minScore, maxScore)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedRes.Type() || gotResult.String() != tt.expectedRes.String() {
				t.Errorf("redis_zremrangebyscore() gotResult = %s, want %s", gotResult, tt.expectedRes)
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("mock expectations were not met: %v", err)
			}

			mock.ClearExpect()
		})
	}
}

func TestRedisZRank(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		member      string
		expectedRes lua.LValue
		expectedErr lua.LValue
		setupMock   func(mock redismock.ClientMock, key, member string)
	}{
		{
			name:        "MemberExists",
			key:         "key1",
			member:      "member1",
			expectedRes: lua.LNumber(0),
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key, member string) {
				mock.ExpectZRank(key, member).SetVal(0)
			},
		},
		{
			name:        "MemberNotExists",
			key:         "key2",
			member:      "nonexistent",
			expectedRes: lua.LNil,
			expectedErr: lua.LString("redis: nil"),
			setupMock: func(mock redismock.ClientMock, key, member string) {
				mock.ExpectZRank(key, member).SetErr(redis.Nil)
			},
		},
		{
			name:        "EmptyKey",
			key:         "",
			member:      "member1",
			expectedRes: lua.LNil,
			expectedErr: lua.LString("redis: nil"),
			setupMock: func(mock redismock.ClientMock, key, member string) {
				mock.ExpectZRank(key, member).SetErr(redis.Nil)
			},
		},
		{
			name:        "RedisError",
			key:         "key4",
			member:      "member1",
			expectedRes: lua.LNil,
			expectedErr: lua.LString("context deadline exceeded"),
			setupMock: func(mock redismock.ClientMock, key, member string) {
				mock.ExpectZRank(key, member).SetErr(context.DeadlineExceeded)
			},
		},
	}

	L := lua.NewState()

	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background()))

	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			rediscli.NewTestClient(db)

			if tt.setupMock != nil {
				tt.setupMock(mock, tt.key, tt.member)
			}

			L.SetGlobal("key", lua.LString(tt.key))
			L.SetGlobal("member", lua.LString(tt.member))

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_zrank("default", key, member)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedRes.Type() || gotResult.String() != tt.expectedRes.String() {
				t.Errorf("redis_zrank() gotResult = %s, want %s", gotResult, tt.expectedRes)
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("mock expectations were not met: %v", err)
			}

			mock.ClearExpect()
		})
	}
}

// TestRedisZCount tests the RedisZCount function which counts the number of members in a sorted set with scores between min and max.
// Added in version 1.7.7
func TestRedisZCount(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		min         string
		max         string
		expectedRes lua.LValue
		expectedErr lua.LValue
		setupMock   func(mock redismock.ClientMock, key, min, max string)
	}{
		{
			name:        "ValidRange",
			key:         "key1",
			min:         "10",
			max:         "20",
			expectedRes: lua.LNumber(5),
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key, min, max string) {
				mock.ExpectZCount(key, min, max).SetVal(5)
			},
		},
		{
			name:        "EmptyRange",
			key:         "key2",
			min:         "30",
			max:         "40",
			expectedRes: lua.LNumber(0),
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key, min, max string) {
				mock.ExpectZCount(key, min, max).SetVal(0)
			},
		},
		{
			name:        "InfiniteRange",
			key:         "key3",
			min:         "-inf",
			max:         "+inf",
			expectedRes: lua.LNumber(10),
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key, min, max string) {
				mock.ExpectZCount(key, min, max).SetVal(10)
			},
		},
		{
			name:        "NonExistentKey",
			key:         "nonexistent",
			min:         "0",
			max:         "100",
			expectedRes: lua.LNumber(0),
			expectedErr: lua.LNil,
			setupMock: func(mock redismock.ClientMock, key, min, max string) {
				mock.ExpectZCount(key, min, max).SetVal(0)
			},
		},
		{
			name:        "RedisError",
			key:         "key4",
			min:         "10",
			max:         "20",
			expectedRes: lua.LNil,
			expectedErr: lua.LString("context deadline exceeded"),
			setupMock: func(mock redismock.ClientMock, key, min, max string) {
				mock.ExpectZCount(key, min, max).SetErr(context.DeadlineExceeded)
			},
		},
	}

	L := lua.NewState()

	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background()))

	defer L.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock := redismock.NewClientMock()
			if db == nil || mock == nil {
				t.Fatalf("Failed to create Redis mock client.")
			}

			rediscli.NewTestClient(db)

			if tt.setupMock != nil {
				tt.setupMock(mock, tt.key, tt.min, tt.max)
			}

			L.SetGlobal("key", lua.LString(tt.key))
			L.SetGlobal("min", lua.LString(tt.min))
			L.SetGlobal("max", lua.LString(tt.max))

			err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.redis_zcount("default", key, min, max)`)
			if err != nil {
				t.Fatalf("Running Lua code failed: %v", err)
			}

			gotResult := L.GetGlobal("result")
			if gotResult.Type() != tt.expectedRes.Type() || gotResult.String() != tt.expectedRes.String() {
				t.Errorf("redis_zcount() gotResult = %s, want %s", gotResult, tt.expectedRes)
			}

			gotErr := L.GetGlobal("err")

			checkLuaError(t, gotErr, tt.expectedErr)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("mock expectations were not met: %v", err)
			}

			mock.ClearExpect()
		})
	}
}
