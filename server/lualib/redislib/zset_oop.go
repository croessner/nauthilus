//go:build redislib_oop

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

	"github.com/croessner/nauthilus/server/lualib/luastack"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

// RedisZAdd adds one or more members to a sorted set, or updates its score if it already exists.
func (rm *RedisManager) RedisZAdd(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		values := stack.CheckTable(3)

		zValues := rm.parseLuaTableToRedisZSet(L, values, "zadd expects a table of scores and values")
		if zValues == nil {
			return 2
		}

		cmd := conn.ZAdd(ctx, key, zValues...)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResult(lua.LNumber(cmd.Val()))
	})
}

// parseLuaTableToRedisZSet is a helper function to parse a Lua table into a slice of redis.Z values.
func (rm *RedisManager) parseLuaTableToRedisZSet(L *lua.LState, values *lua.LTable, errorMsg string) []redis.Z {
	var zValues []redis.Z

	var parseErr bool

	values.ForEach(func(key lua.LValue, value lua.LValue) {
		if parseErr {
			return
		}

		score, okScore := key.(lua.LNumber)
		valStr, okVal := value.(lua.LString)

		if !okScore || !okVal {
			L.Push(lua.LNil)
			L.Push(lua.LString(errorMsg))

			parseErr = true

			return
		}

		zValues = append(zValues, redis.Z{
			Score:  float64(score),
			Member: valStr.String(),
		})
	})

	if parseErr {
		return nil
	}

	return zValues
}

// RedisZRange returns a range of members in a sorted set, by index.
func (rm *RedisManager) RedisZRange(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		start := int64(stack.CheckInt(3))
		stop := int64(stack.CheckInt(4))

		cmd := conn.ZRange(ctx, key, start, stop)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		result := L.NewTable()
		for _, val := range cmd.Val() {
			result.Append(lua.LString(val))
		}

		return stack.PushResult(result)
	})
}

// RedisZRevRange returns a range of members in a sorted set, by index, with scores ordered from high to low.
func (rm *RedisManager) RedisZRevRange(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		start := int64(stack.CheckInt(3))
		stop := int64(stack.CheckInt(4))

		cmd := conn.ZRevRange(ctx, key, start, stop)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		result := L.NewTable()
		for _, val := range cmd.Val() {
			result.Append(lua.LString(val))
		}

		return stack.PushResult(result)
	})
}

// RedisZRangeByScore returns a range of members in a sorted set, by score.
func (rm *RedisManager) RedisZRangeByScore(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		min := stack.CheckString(3)
		max := stack.CheckString(4)

		var (
			offset int64
			count  int64
		)

		if stack.GetTop() == 6 {
			offset = int64(stack.CheckInt(5))
			count = int64(stack.CheckInt(6))
		}

		cmd := conn.ZRangeByScore(ctx, key, &redis.ZRangeBy{
			Min:    min,
			Max:    max,
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

		return stack.PushResult(result)
	})
}

// RedisZRem removes one or more members from a sorted set.
func (rm *RedisManager) RedisZRem(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		top := stack.GetTop()
		members := make([]any, top-2)

		for i := 3; i <= top; i++ {
			members[i-3] = stack.CheckString(i)
		}

		cmd := conn.ZRem(ctx, key, members...)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResult(lua.LNumber(cmd.Val()))
	})
}

// RedisZRemRangeByScore removes all members in a sorted set within the given scores.
func (rm *RedisManager) RedisZRemRangeByScore(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		min := stack.CheckString(3)
		max := stack.CheckString(4)

		cmd := conn.ZRemRangeByScore(ctx, key, min, max)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResult(lua.LNumber(cmd.Val()))
	})
}

// RedisZRemRangeByRank removes all members in a sorted set within the given indexes.
func (rm *RedisManager) RedisZRemRangeByRank(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		start := int64(stack.CheckInt(3))
		stop := int64(stack.CheckInt(4))

		cmd := conn.ZRemRangeByRank(ctx, key, start, stop)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResult(lua.LNumber(cmd.Val()))
	})
}

// RedisZRank returns the rank of a member in a sorted set, with scores ordered from low to high.
func (rm *RedisManager) RedisZRank(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		member := stack.CheckString(3)

		cmd := conn.ZRank(ctx, key, member)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResult(lua.LNumber(cmd.Val()))
	})
}

// RedisZCount returns the number of members in a sorted set with scores within the given values.
func (rm *RedisManager) RedisZCount(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		min := stack.CheckString(3)
		max := stack.CheckString(4)

		cmd := conn.ZCount(ctx, key, min, max)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResult(lua.LNumber(cmd.Val()))
	})
}

// RedisZScore returns the score of a member in a sorted set.
func (rm *RedisManager) RedisZScore(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		member := stack.CheckString(3)

		cmd := conn.ZScore(ctx, key, member)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResult(lua.LNumber(cmd.Val()))
	})
}

// RedisZRevRank returns the rank of a member in a sorted set, with scores ordered from high to low.
func (rm *RedisManager) RedisZRevRank(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		member := stack.CheckString(3)

		cmd := conn.ZRevRank(ctx, key, member)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResult(lua.LNumber(cmd.Val()))
	})
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

		return stack.PushResult(lua.LNumber(cmd.Val()))
	})
}
