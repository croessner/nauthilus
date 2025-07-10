package redislib

import (
	"context"
	"sort"

	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

// RedisZAdd adds members with scores to a Redis sorted set, returning the number of elements added to the set.
func RedisZAdd(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		const errorMsg = "Expected a table of string-number pairs"

		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetWriteHandle())

		key := L.CheckString(2)
		values := L.CheckTable(3)

		redisZSet := parseLuaTableToRedisZSet(L, values, errorMsg)

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		cmd := client.ZAdd(ctx, key, redisZSet...)
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
func RedisZRange(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetReadHandle())

		key := L.CheckString(2)
		start := int64(L.CheckNumber(3))
		stop := int64(L.CheckNumber(4))

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		cmd := client.ZRange(ctx, key, start, stop)
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
func RedisZRevRange(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetReadHandle())

		key := L.CheckString(2)
		start := int64(L.CheckNumber(3))
		stop := int64(L.CheckNumber(4))

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		cmd := client.ZRevRange(ctx, key, start, stop)
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
func RedisZRangeByScore(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetReadHandle())

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

		cmd := client.ZRangeByScore(ctx, key, &zrangeOpts)
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
func RedisZRem(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		var members []any

		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetWriteHandle())

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

		cmd := client.ZRem(ctx, key, members...)
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
func RedisZRemRangeByScore(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetWriteHandle())

		key := L.CheckString(2)      // The key of the sorted set
		minScore := L.CheckString(3) // Minimum score (e.g., "-inf" or a numeric value)
		maxScore := L.CheckString(4) // Maximum score (e.g., "+inf" or a numeric value)

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		cmd := client.ZRemRangeByScore(ctx, key, minScore, maxScore)
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
func RedisZRank(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetReadHandle())

		key := L.CheckString(2)
		member := L.CheckString(3) // The member whose rank needs to be retrieved

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		cmd := client.ZRank(ctx, key, member)
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
func RedisZCount(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetReadHandle())

		key := L.CheckString(2)
		minScore := L.CheckString(3) // Minimum score (e.g., "-inf" or a numeric value)
		maxScore := L.CheckString(4) // Maximum score (e.g., "+inf" or a numeric value)

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		cmd := client.ZCount(ctx, key, minScore, maxScore)
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
func RedisZScore(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetReadHandle())

		key := L.CheckString(2)
		member := L.CheckString(3) // The member whose score needs to be retrieved

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		cmd := client.ZScore(ctx, key, member)
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
func RedisZRevRank(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetReadHandle())

		key := L.CheckString(2)
		member := L.CheckString(3) // The member whose rank needs to be retrieved

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		cmd := client.ZRevRank(ctx, key, member)
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
func RedisZIncrBy(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetWriteHandle())

		key := L.CheckString(2)
		increment := float64(L.CheckNumber(3)) // The increment value
		member := L.CheckString(4)             // The member whose score needs to be incremented

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		cmd := client.ZIncrBy(ctx, key, increment, member)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}
