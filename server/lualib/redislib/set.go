package redislib

import (
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	lua "github.com/yuin/gopher-lua"
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
func RedisSAdd(L *lua.LState) int {
	key := L.CheckString(1)
	values := make([]any, L.GetTop()-1)

	for i := 2; i <= L.GetTop(); i++ {
		value, err := ConvertLuaValue(L.Get(i))
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))

			return 2
		}

		values[i-2] = value
	}

	cmd := rediscli.WriteHandle.SAdd(ctx, key, values...)
	if cmd.Err() != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(cmd.Err().Error()))

		return 2
	} else {
		stats.RedisWriteCounter.Inc()
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
func RedisSIsMember(L *lua.LState) int {
	key := L.CheckString(1)

	value, err := ConvertLuaValue(L.Get(2))
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))

		return 2
	}

	cmd := rediscli.ReadHandle.SIsMember(ctx, key, value)
	if cmd.Err() != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(cmd.Err().Error()))

		return 2
	} else {
		stats.RedisReadCounter.Inc()
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
func RedisSMembers(L *lua.LState) int {
	key := L.CheckString(1)

	cmd := rediscli.ReadHandle.SMembers(ctx, key)
	if cmd.Err() != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(cmd.Err().Error()))

		return 2
	} else {
		members := cmd.Val()
		table := L.NewTable()
		for _, member := range members {
			table.Append(ConvertGoToLuaValue(member))
		}

		stats.RedisReadCounter.Inc()
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
func RedisSRem(L *lua.LState) int {
	key := L.CheckString(1)
	values := make([]any, L.GetTop()-1)

	for i := 2; i <= L.GetTop(); i++ {
		value, err := ConvertLuaValue(L.Get(i))
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))

			return 2
		}

		values[i-2] = value
	}

	cmd := rediscli.WriteHandle.SRem(ctx, key, values...)
	if cmd.Err() != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(cmd.Err().Error()))

		return 2
	} else {
		stats.RedisWriteCounter.Inc()
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
func RedisSCard(L *lua.LState) int {
	key := L.CheckString(1)

	cmd := rediscli.ReadHandle.SCard(ctx, key)
	if cmd.Err() != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(cmd.Err().Error()))

		return 2
	} else {
		stats.RedisReadCounter.Inc()
		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}