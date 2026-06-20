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
	"context"
	"errors"
	"sort"

	"github.com/croessner/nauthilus/v3/server/lualib/luastack"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

// RedisZAdd adds one or more members to a sorted set, or updates its score if it already exists.
func (rm *RedisManager) RedisZAdd(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		top := stack.GetTop()

		var zValues []redis.Z

		if top == 3 && stack.L.Get(3).Type() == lua.LTTable {
			values := stack.CheckTable(3)

			zValues = rm.parseLuaTableToRedisZSet(values, "zadd expects a table of scores and values")
		} else {
			if top < 4 || (top-2)%2 != 0 {
				return stack.PushError(errors.New("invalid number of arguments"))
			}

			for i := 3; i <= top; i += 2 {
				member := stack.CheckString(i)
				score := float64(stack.CheckNumber(i + 1))

				zValues = append(zValues, redis.Z{
					Member: member,
					Score:  score,
				})
			}

			sort.Slice(zValues, func(i, j int) bool {
				return zValues[i].Member.(string) < zValues[j].Member.(string)
			})
		}

		cmd := conn.ZAdd(ctx, key, zValues...)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(lua.LNumber(cmd.Val()), lua.LNil)
	})
}

// parseLuaTableToRedisZSet is a helper function to parse a Lua table into a slice of redis.Z values.
func (rm *RedisManager) parseLuaTableToRedisZSet(values *lua.LTable, _ string) []redis.Z {
	var zValues []redis.Z

	values.ForEach(func(key lua.LValue, value lua.LValue) {
		zValues = append(zValues, redis.Z{
			Score:  float64(lua.LVAsNumber(value)),
			Member: key.String(),
		})
	})

	sort.Slice(zValues, func(i, j int) bool {
		return zValues[i].Member.(string) < zValues[j].Member.(string)
	})

	return zValues
}

// RedisZRange returns a range of members in a sorted set, by index.
func (rm *RedisManager) RedisZRange(L *lua.LState) int {
	return executeRangeStringSliceCmd(rm, L, func(ctx context.Context, conn redis.Cmdable, key string, start, stop int64) *redis.StringSliceCmd {
		return conn.ZRange(ctx, key, start, stop)
	})
}

// RedisZRevRange returns a range of members in a sorted set, by index, with scores ordered from high to low.
func (rm *RedisManager) RedisZRevRange(L *lua.LState) int {
	return executeRangeStringSliceCmd(rm, L, func(ctx context.Context, conn redis.Cmdable, key string, start, stop int64) *redis.StringSliceCmd {
		return conn.ZRevRange(ctx, key, start, stop)
	})
}

// RedisZRangeByScore returns a range of members in a sorted set, by score.
func (rm *RedisManager) RedisZRangeByScore(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		minScore := stack.CheckString(3)
		maxScore := stack.CheckString(4)

		var (
			offset int64
			count  int64
		)

		top := stack.GetTop()
		if top >= 5 && L.Get(5) != lua.LNil {
			if tbl, ok := L.Get(5).(*lua.LTable); ok {
				if v := tbl.RawGetString("offset"); v.Type() == lua.LTNumber {
					offset = int64(lua.LVAsNumber(v))
				}

				if v := tbl.RawGetString("count"); v.Type() == lua.LTNumber {
					count = int64(lua.LVAsNumber(v))
				}
			} else {
				offset = int64(stack.CheckInt(5))
				if top >= 6 {
					count = int64(stack.CheckInt(6))
				}
			}
		}

		cmd := conn.ZRangeByScore(ctx, key, &redis.ZRangeBy{
			Min:    minScore,
			Max:    maxScore,
			Offset: offset,
			Count:  count,
		})
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		result := L.NewTable()

		for _, val := range cmd.Val() {
			result.Append(lua.LString(val))
		}

		return stack.PushResults(result, lua.LNil)
	})
}

// RedisZRem removes one or more members from a sorted set.
func (rm *RedisManager) RedisZRem(L *lua.LState) int {
	return executeWriteIntCmd(rm, L, collectLuaValues, func(ctx context.Context, conn redis.Cmdable, key string, values []any) *redis.IntCmd {
		return conn.ZRem(ctx, key, values...)
	})
}

// RedisZRemRangeByScore removes all members in a sorted set within the given scores.
func (rm *RedisManager) RedisZRemRangeByScore(L *lua.LState) int {
	return executeKeyTwoStringNumberCmd(rm, L, true, func(ctx context.Context, conn redis.Cmdable, key string, minScore string, maxScore string) redisValueCmd[int64] {
		return conn.ZRemRangeByScore(ctx, key, minScore, maxScore)
	})
}

// RedisZRemRangeByRank removes all members in a sorted set within the given indexes.
func (rm *RedisManager) RedisZRemRangeByRank(L *lua.LState) int {
	return executeKeyIndexRangeNumberCmd(rm, L, true, func(ctx context.Context, conn redis.Cmdable, key string, start, stop int64) *redis.IntCmd {
		return conn.ZRemRangeByRank(ctx, key, start, stop)
	})
}

// RedisZRank returns the rank of a member in a sorted set, with scores ordered from low to high.
func (rm *RedisManager) RedisZRank(L *lua.LState) int {
	return executeTwoStringCmd(rm, L, false, func(ctx context.Context, conn redis.Cmdable, key string, member string) *redis.IntCmd {
		return conn.ZRank(ctx, key, member)
	}, luaNumberValue[int64])
}

// RedisZCount returns the number of members in a sorted set with scores within the given values.
func (rm *RedisManager) RedisZCount(L *lua.LState) int {
	return executeKeyTwoStringNumberCmd(rm, L, false, func(ctx context.Context, conn redis.Cmdable, key string, minScore string, maxScore string) redisValueCmd[int64] {
		return conn.ZCount(ctx, key, minScore, maxScore)
	})
}

// RedisZScore returns the score of a member in a sorted set.
func (rm *RedisManager) RedisZScore(L *lua.LState) int {
	return executeTwoStringCmd(rm, L, false, func(ctx context.Context, conn redis.Cmdable, key string, member string) *redis.FloatCmd {
		return conn.ZScore(ctx, key, member)
	}, luaNumberValue[float64])
}

// RedisZRevRank returns the rank of a member in a sorted set, with scores ordered from high to low.
func (rm *RedisManager) RedisZRevRank(L *lua.LState) int {
	return executeTwoStringCmd(rm, L, false, func(ctx context.Context, conn redis.Cmdable, key string, member string) *redis.IntCmd {
		return conn.ZRevRank(ctx, key, member)
	}, luaNumberValue[int64])
}

// RedisZIncrBy increments the score of a member in a sorted set.
func (rm *RedisManager) RedisZIncrBy(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		increment := float64(stack.CheckNumber(3))
		member := stack.CheckString(4)

		cmd := conn.ZIncrBy(ctx, key, increment, member)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(lua.LNumber(cmd.Val()), lua.LNil)
	})
}
