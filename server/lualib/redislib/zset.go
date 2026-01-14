//go:build !redislib_oop

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

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

// RedisZAdd adds members with scores to a Redis sorted set, returning the number of elements added to the set.
func RedisZAdd(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return func(L *lua.LState) int {
		const errorMsg = "Expected a table of string-number pairs"

		conn := getRedisConnectionWithFallback(L, client.GetWriteHandle())

		key := L.CheckString(2)
		values := L.CheckTable(3)

		redisZSet := parseLuaTableToRedisZSet(L, values, errorMsg)

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, cfg)
		defer cancel()

		cmd := conn.ZAdd(dCtx, key, redisZSet...)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// parseLuaTableToRedisZSet converts a Lua table of key-value pairs into a slice of Redis ZSet members with scores.
func parseLuaTableToRedisZSet(L *lua.LState, values *lua.LTable, errorMsg string) []redis.Z {
	redisZSet := make([]redis.Z, 0)

	elements := make([]struct {
		Member string
		Score  float64
	}, 0)

	values.ForEach(func(k, v lua.LValue) {
		member := k.String()
		if member == "" {
			L.ArgError(1, errorMsg)
		}

		score := float64(lua.LVAsNumber(v))

		elements = append(elements, struct {
			Member string
			Score  float64
		}{
			Member: member,
			Score:  score,
		})
	})

	sort.Slice(elements, func(i, j int) bool {
		return elements[i].Member < elements[j].Member
	})

	for _, elem := range elements {
		redisZSet = append(redisZSet, redis.Z{
			Member: elem.Member,
			Score:  elem.Score,
		})
	}

	return redisZSet
}

// RedisZRange retrieves a range of members from a sorted set in Redis based on their rank, defined by start and stop indexes.
func RedisZRange(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return func(L *lua.LState) int {
		conn := getRedisConnectionWithFallback(L, client.GetReadHandle())

		key := L.CheckString(2)
		start := int64(L.CheckNumber(3))
		stop := int64(L.CheckNumber(4))

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, cfg)
		defer cancel()

		cmd := conn.ZRange(dCtx, key, start, stop)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		result := L.NewTable()
		for _, val := range cmd.Val() {
			result.Append(lua.LString(val))
		}

		L.Push(result)

		return 1
	}
}

// RedisZRevRange retrieves a range of elements from a sorted set in reverse order based on their indices.
func RedisZRevRange(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return func(L *lua.LState) int {
		conn := getRedisConnectionWithFallback(L, client.GetReadHandle())

		key := L.CheckString(2)
		start := int64(L.CheckNumber(3))
		stop := int64(L.CheckNumber(4))

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, cfg)
		defer cancel()

		cmd := conn.ZRevRange(dCtx, key, start, stop)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		result := L.NewTable()
		for _, val := range cmd.Val() {
			result.Append(lua.LString(val))
		}

		L.Push(result)

		return 1
	}
}

// RedisZRangeByScore retrieves elements from a sorted set in Redis based on a given score range and optional limits.
func RedisZRangeByScore(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return func(L *lua.LState) int {
		conn := getRedisConnectionWithFallback(L, client.GetReadHandle())

		key := L.CheckString(2)
		minScore := L.CheckString(3)    // The minimum score (e.g., "-inf" or a numeric value)
		maxScore := L.CheckString(4)    // The maximum score (e.g., "+inf" or a numeric value)
		optsTable := L.OptTable(5, nil) // Optional table for additional options like LIMIT

		// Initialize options for ZRangeByScore
		zrangeOpts := redis.ZRangeBy{
			Min:    minScore,
			Max:    maxScore,
			Offset: 0, // Default value
			Count:  0, // Default value
		}

		// If an optional table is provided, process its values
		if optsTable != nil {
			if offset := optsTable.RawGetString("offset"); offset != lua.LNil {
				zrangeOpts.Offset = int64(lua.LVAsNumber(offset))
			}

			if count := optsTable.RawGetString("count"); count != lua.LNil {
				zrangeOpts.Count = int64(lua.LVAsNumber(count))
			}
		}

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, cfg)
		defer cancel()

		cmd := conn.ZRangeByScore(dCtx, key, &zrangeOpts)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		result := L.NewTable()
		for _, val := range cmd.Val() {
			result.Append(lua.LString(val))
		}

		L.Push(result)

		return 1
	}
}

// RedisZRem removes one or more members from a sorted set in Redis and returns the number of members removed.
func RedisZRem(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return func(L *lua.LState) int {
		var members []any

		conn := getRedisConnectionWithFallback(L, client.GetWriteHandle())

		key := L.CheckString(2)
		membersTable := L.CheckTable(3) // Lua table containing the members to remove

		// Convert the Lua table into a slice of strings (the members to remove)
		membersTable.ForEach(func(_, v lua.LValue) {
			member := v.String()
			if member == "" {
				L.ArgError(1, "Expected a table of string values")
			}

			members = append(members, member)
		})

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, cfg)
		defer cancel()

		cmd := conn.ZRem(dCtx, key, members...)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisZRemRangeByScore removes all elements in a Redis sorted set with scores within the specified range.
func RedisZRemRangeByScore(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return func(L *lua.LState) int {
		conn := getRedisConnectionWithFallback(L, client.GetWriteHandle())

		key := L.CheckString(2)      // The key of the sorted set
		minScore := L.CheckString(3) // Minimum score (e.g., "-inf" or a numeric value)
		maxScore := L.CheckString(4) // Maximum score (e.g., "+inf" or a numeric value)

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, cfg)
		defer cancel()

		cmd := conn.ZRemRangeByScore(dCtx, key, minScore, maxScore)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisZRemRangeByRank removes all elements in a Redis sorted set with ranks within the specified range.
// Added in version 1.7.20
func RedisZRemRangeByRank(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return func(L *lua.LState) int {
		conn := getRedisConnectionWithFallback(L, client.GetWriteHandle())

		key := L.CheckString(2)  // The key of the sorted set
		start := L.CheckInt64(3) // Start rank (0-based, inclusive)
		stop := L.CheckInt64(4)  // Stop rank (0-based, inclusive)

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, cfg)
		defer cancel()

		cmd := conn.ZRemRangeByRank(dCtx, key, int64(start), int64(stop))
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisZRank retrieves the rank of a member within a sorted set in Redis, returning the rank or an error if applicable.
func RedisZRank(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return func(L *lua.LState) int {
		conn := getRedisConnectionWithFallback(L, client.GetReadHandle())
		key := L.CheckString(2)
		member := L.CheckString(3) // The member whose rank needs to be retrieved

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, cfg)
		defer cancel()

		cmd := conn.ZRank(dCtx, key, member)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisZCount counts the number of members in a sorted set with scores between min and max.
// Added in version 1.7.7
func RedisZCount(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return func(L *lua.LState) int {
		conn := getRedisConnectionWithFallback(L, client.GetReadHandle())
		key := L.CheckString(2)
		minScore := L.CheckString(3) // Minimum score (e.g., "-inf" or a numeric value)
		maxScore := L.CheckString(4) // Maximum score (e.g., "+inf" or a numeric value)

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, cfg)
		defer cancel()

		cmd := conn.ZCount(dCtx, key, minScore, maxScore)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisZScore retrieves the score of a member in a sorted set.
// Added in version 1.7.7
func RedisZScore(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return func(L *lua.LState) int {
		conn := getRedisConnectionWithFallback(L, client.GetReadHandle())
		key := L.CheckString(2)
		member := L.CheckString(3) // The member whose score needs to be retrieved

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, cfg)
		defer cancel()

		cmd := conn.ZScore(dCtx, key, member)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisZRevRank retrieves the rank of a member within a sorted set in Redis, with the scores ordered from high to low.
// The rank is 0-based, meaning that the member with the highest score has rank 0.
func RedisZRevRank(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return func(L *lua.LState) int {
		conn := getRedisConnectionWithFallback(L, client.GetReadHandle())
		key := L.CheckString(2)
		member := L.CheckString(3) // The member whose rank needs to be retrieved

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, cfg)
		defer cancel()

		cmd := conn.ZRevRank(dCtx, key, member)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisZIncrBy increments the score of a member in a sorted set by the given increment value.
// Added in version 1.7.18
func RedisZIncrBy(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return func(L *lua.LState) int {
		conn := getRedisConnectionWithFallback(L, client.GetWriteHandle())
		key := L.CheckString(2)
		increment := float64(L.CheckNumber(3)) // The increment value
		member := L.CheckString(4)             // The member whose score needs to be incremented

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, cfg)
		defer cancel()

		cmd := conn.ZIncrBy(dCtx, key, increment, member)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}
