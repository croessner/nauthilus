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

// parseLuaTableToRedisZSet converts a Lua table of string-number pairs to a slice of redis.Z objects for use with Redis.
// L is the Lua state used to interact with Lua values and propagate errors.
// values is the Lua table containing string-number pairs to be converted.
// errorMsg is the error message to be thrown if a key in the Lua table is not a valid string.
// Returns a slice of redis.Z containing the converted key-value pairs.
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

// RedisZRange retrieves a range of elements from a Redis sorted set (ZSET) by index (start and stop) via ZRANGE.
// It pushes the resulting table or an error to the Lua state stack.
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

// RedisZRangeByScore retrieves elements from a sorted set in Redis within the specified score range (inclusive).
// It accepts an optional table with "offset" and "count" for result pagination.
// Returns a Lua table with the matching elements or an error message if the operation fails.
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

// RedisZRemRangeByScore removes members in a sorted set within a given score range from Redis.
// It requires the Redis connection, set key, minimum score, and maximum score as arguments.
// Returns the count of removed elements or an error if the operation fails.
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

// RedisZRank executes a Redis ZRANK command to retrieve the rank of a specified member in a sorted set.
// Returns the rank as Lua.LNumber or nil and error string on failure.
// Requires the context, key, and member as inputs.
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
