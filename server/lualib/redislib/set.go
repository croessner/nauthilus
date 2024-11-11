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

	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/yuin/gopher-lua"
)

// RedisSAdd adds one or more members to a Redis set. It maps directly to the SADD command in Redis.
//
// Parameters:
//   - L: The Lua state, which includes the arguments passed from Lua to Go.
//     The first argument should be the key of the Redis set (string),
//     and the subsequent arguments should be the members to add (various types).
//
// Returns:
//   - 1 value if successful: the number of elements added to the set (integer).
//   - 2 values if an error occurs: nil and an error message (string).
//
// Lua Usage Example:
//
//	redis.sadd("myset", "value1", "value2", 123, true)
func RedisSAdd(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.WriteHandle)
		key := L.CheckString(2)
		values := make([]any, L.GetTop()-2)

		for i := 3; i <= L.GetTop(); i++ {
			value, err := convert.LuaValue(L.Get(i))
			if err != nil {
				L.Push(lua.LNil)
				L.Push(lua.LString(err.Error()))

				return 2
			}

			values[i-3] = value
		}

		defer stats.RedisWriteCounter.Inc()

		cmd := client.SAdd(ctx, key, values...)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisSIsMember checks if a given value is a member of the set stored at a specified key in Redis.
//
// Parameters:
//
//	L *lua.LState - The current Lua state that's used for interfacing with Lua scripts.
//
// Returns:
//
//	int - The number of results returned to Lua.
//	      It returns the following to the Lua stack:
//	      - If an error occurs, it returns nil followed by the error message.
//	      - If the operation is successful, it returns a boolean indicating presence of the value in the set.
//
// Lua Usage:
//
//	result, err = RedisSIsMember(key, value)
//
// Example:
//
//	local is_member, err = RedisSIsMember("my_set", "value1")
//	if err then
//	  print("Error:", err)
//	else
//	  if is_member then
//	    print("Value is a member of the set.")
//	  else
//	    print("Value is not a member of the set.")
//	  end
//	end
func RedisSIsMember(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.ReadHandle)
		key := L.CheckString(2)

		value, err := convert.LuaValue(L.Get(3))
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))

			return 2
		}

		defer stats.RedisReadCounter.Inc()

		cmd := client.SIsMember(ctx, key, value)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LBool(cmd.Val()))

		return 1
	}
}

// RedisSMembers retrieves all the members of a set in Redis corresponding to the given key.
//
// Parameters:
// - L: A Lua state object. The first argument in the Lua state is expected to be a string representing the Redis key.
//
// Returns:
// - If the operation is successful, returns a Lua table containing all the members of the set.
// - If the operation fails, returns nil and an error message.
//
// Example usage:
// members = redis_smembers("myset")
// if members ~= nil then
//
//	for _, member in ipairs(members) do
//	    print(member)
//	end
//
// else
//
//	print("Error retrieving members from Redis")
//
// end
//
// This function utilizes the SMembers command from the Redis client to fetch the set members,
// and it increments the RedisReadCounter to track the read operation.
func RedisSMembers(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.ReadHandle)
		key := L.CheckString(2)

		defer stats.RedisReadCounter.Inc()

		cmd := client.SMembers(ctx, key)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		members := cmd.Val()
		table := L.NewTable()
		for _, member := range members {
			table.Append(convert.GoToLuaValue(L, member))
		}

		L.Push(table)

		return 1
	}
}

// RedisSRem removes one or more members from a Redis set.
//
// This function wraps the Redis SREM command. It accepts a key and a variable
// number of values to remove from the set. If any value cannot be converted,
// it returns an error.
//
// Parameters:
// - L (lua.LState): The current Lua state.
//
// Returns:
//   - int: The number of return values on the Lua stack. On error, it returns
//     two values: nil and the error message. On success, it returns the number
//     of removed elements.
func RedisSRem(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.WriteHandle)
		key := L.CheckString(2)
		values := make([]any, L.GetTop()-2)

		for i := 3; i <= L.GetTop(); i++ {
			value, err := convert.LuaValue(L.Get(i))
			if err != nil {
				L.Push(lua.LNil)
				L.Push(lua.LString(err.Error()))

				return 2
			}

			values[i-3] = value
		}

		defer stats.RedisWriteCounter.Inc()

		cmd := client.SRem(ctx, key, values...)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisSCard fetches the cardinality (number of elements) of the set stored at the specified key in Redis.
//
// Parameters:
// - L (lua.LState): The Lua state that provides the key as its first argument.
//
// Returns:
// - 1 result on the Lua stack representing the number of elements in the set if successful (lua.LNumber).
// - 2 results on the Lua stack (lua.LNil and lua.LString) if there is an error.
//
// Usage example:
// local count = redis_scard("myset")
func RedisSCard(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.ReadHandle)
		key := L.CheckString(2)

		defer stats.RedisReadCounter.Inc()

		cmd := client.SCard(ctx, key)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}
