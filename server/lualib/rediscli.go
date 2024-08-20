package lualib

import (
	"context"
	"time"

	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	lua "github.com/yuin/gopher-lua"
)

var ctx = context.Background()

// RedisGet retrieves the value associated with the given key from the Redis server.
// It returns the value as a Lua string. If an error occurs, it returns nil and the error message as a Lua string.
// The function expects one argument: the key to retrieve.
// Example usage: val = redis_get_str("mykey")
func RedisGet(L *lua.LState) int {
	key := L.CheckString(1)
	valueType := global.TypeString

	if L.GetTop() == 2 {
		valueType = L.CheckString(2)
	}

	err := ConvertStringCmd(rediscli.ReadHandle.Get(ctx, key), valueType, L)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))

		return 2
	} else {
		stats.RedisReadCounter.Inc()
	}

	return 1
}

// RedisSet sets the value of the given key to the provided value in the Redis server.
// It returns "OK" as a Lua string if the operation is successful.
// If an error occurs, it returns nil and the error message as a Lua string.
// The function expects two arguments: the key and the value to set.
func RedisSet(L *lua.LState) int {
	expiration := time.Duration(0)
	key := L.CheckString(1)

	value, err := ConvertLuaValue(L.Get(2))
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))

		return 2
	}

	if L.GetTop() == 3 {
		expiration = time.Duration(L.CheckInt(3))
	}

	err = rediscli.WriteHandle.Set(ctx, key, value, expiration*time.Second).Err()
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))

		return 2
	} else {
		stats.RedisWriteCounter.Inc()
	}

	L.Push(lua.LString("OK"))

	return 1
}

// RedisIncr increments the value associated with the given key in the Redis server.
// It returns the incremented value as a Lua number. If an error occurs, it returns nil
// and the error message as a Lua string.
// The function expects one argument: the key to increment.
// Example usage: val = redis_incr("counter")
func RedisIncr(L *lua.LState) int {
	key := L.CheckString(1)

	val, err := rediscli.WriteHandle.Incr(ctx, key).Result()
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))

		return 2
	} else {
		stats.RedisWriteCounter.Inc()
	}

	L.Push(lua.LNumber(val))

	return 1
}

// RedisDel deletes the value associated with the given key from the Redis server.
// It returns "OK" as a Lua string if the delete operation is successful.
// If an error occurs, it returns nil and the error message as a Lua string.
// The function expects one argument: the key to delete.
func RedisDel(L *lua.LState) int {
	key := L.CheckString(1)

	err := rediscli.WriteHandle.Del(ctx, key).Err()
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))

		return 2
	} else {
		stats.RedisWriteCounter.Inc()
	}

	L.Push(lua.LString("OK"))

	return 1
}

// RedisExpire sets a timeout on the specified key in the Redis server.
// It expects two arguments: the key and the expiration time in seconds.
// If the operation succeeds, it returns "OK" as a Lua string.
// If an error occurs, it returns nil and the error message as a Lua string.
// Example usage: result = redis_expire("mykey", 60)
func RedisExpire(L *lua.LState) int {
	key := L.CheckString(1)
	expiration := L.CheckNumber(2)

	err := rediscli.WriteHandle.Expire(ctx, key, time.Duration(expiration)*time.Second).Err()
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))

		return 2
	} else {
		stats.RedisWriteCounter.Inc()
	}

	L.Push(lua.LString("OK"))

	return 1
}

// RedisHGet is a function interacting with Redis using a Lua State.
// It retrieves the value associated with the `field` in the Hash stored at `key` in Redis.
// The function checks for three arguments where first two are mandatory:
//  1. `key` - The key under which the Hash is stored.
//  2. `field` - The field in the Hash whose value needs to be retrieved.
//  3. Optional `valueType` - The type of the value to be returned. If not provided,
//     a string value is assumed.
//
// In case of any error during the operation, it pushes a nil value
// and error string to Lua stack and returns 2 indicating two return values.
// If the operation is successful, it increments a Redis read counter and returns 1.
func RedisHGet(L *lua.LState) int {
	key := L.CheckString(1)
	field := L.CheckString(2)
	valueType := global.TypeString

	if L.GetTop() == 1 {
		valueType = L.CheckString(3)
	}

	err := ConvertStringCmd(rediscli.ReadHandle.HGet(ctx, key, field), valueType, L)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))

		return 2
	} else {
		stats.RedisReadCounter.Inc()
	}

	return 1
}

// RedisHSet is a function that acts as a command interface for setting field in the hash stored at key to value.
// If key does not exist, a new key holding a hash is created. If field already exists in the hash, it is overridden.
//
// The function requires at least two parameters. The first one is the key where the hash is stored.
// The remaining ones are pairs of field and value, where field is the field in the hash and value the value to be set.
// Parameters must be passed in pairs to ensure that every field has a corresponding value.
//
// It returns an integer.
// If the operation is successful, it pushes a string "OK" to Lua state L and returns 1.
// If an error occurs, it pushes nil and the error message to Lua state L and returns 2.
func RedisHSet(L *lua.LState) int {
	var kvpairs []any

	if L.GetTop() < 3 || (L.GetTop()-1)%2 != 0 {
		L.Push(lua.LNil)
		L.Push(lua.LString("Invalid number of arguments"))

		return 2
	}

	key := L.CheckString(1)

	for i := 2; i <= L.GetTop(); i += 2 {
		field := L.CheckString(i)

		value, err := ConvertLuaValue(L.Get(i + 1))
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))

			return 2
		}

		kvpairs = append(kvpairs, field, value)
	}

	err := rediscli.WriteHandle.HSet(ctx, key, kvpairs...).Err()
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))

		return 2
	} else {
		stats.RedisWriteCounter.Inc()
	}

	L.Push(lua.LString("OK"))

	return 1
}

// RedisHDel is a function that uses lua as its first parameter. This function removes
// given fields from the Hash stored at key. It accepts an arbitrary number of arguments
// (represented by the *lua.LState value) where these arguments are fields to delete
// from the Hash. This function returns an int indicating the status of the operation.
// It begins by checking the number of arguments passed, if they are valid, fields are
// appended and prepared for deletion from Redis. If the deletion process encounters an error,
// the function returns an error message. If the deletion is successful, it increments the
// RedisWriteCounter stats and return a string "OK". This function use Lua's inbuilt Push
// method for returning values to the Lua stack. It is used with the L.Push(lua.LNil)
// and L.Push(lua.LString("Error")), which pushes a nil value and an error string, respectively,
// in case of an error. On successful deletion, it returns "OK".
func RedisHDel(L *lua.LState) int {
	var fields []string

	if L.GetTop() < 2 {
		L.Push(lua.LNil)
		L.Push(lua.LString("Invalid number of arguments"))

		return 2
	}

	key := L.CheckString(1)

	for i := 2; i <= L.GetTop(); i += 1 {
		fields = append(fields, L.CheckString(i))
	}

	err := rediscli.WriteHandle.HDel(ctx, key, fields...).Err()
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))

		return 2
	} else {
		stats.RedisWriteCounter.Inc()
	}

	L.Push(lua.LString("OK"))

	return 1
}

// RedisHLen is a function in Go that interacts with a Redis database.
// It takes a Lua State object pointer as an argument, which probably points to the system's Lua state instance.
// This function is designed to read the length of a Hash data structure in Redis corresponding to a key.
//
// The function works as follows:
//  1. It retrieves the first argument from the Lua state, anticipated to be a string representing the key of a Redis hash.
//  2. It interacts with the Redis ReadHandle to get the length of the Hash (HLen function) associated with the given key.
//     The operation is processed synchronously, and the result is read back. Since the operation can throw an error,
//     the function also listens for any potential errors thrown by Redis.
//  3. If an error takes place, the function pushes a nil value and the error into the Lua stack then returns with a value of 2 representing two returned values.
//  4. If there's no error, it pushes the numerical result (the hash length) into the Lua stack and return with a value of 1, representing one returned value.
//
// It is important to note that this function returns the number of items that it pushes onto the Lua stack,
// rather than the actual results of the Redis HLen operation.
func RedisHLen(L *lua.LState) int {
	key := L.CheckString(1)

	result, err := rediscli.ReadHandle.HLen(ctx, key).Result()
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))

		return 2
	} else {
		L.Push(lua.LNumber(result))
	}

	return 1
}

// RedisHGetAll is a function that interacts with the Redis database. This function takes a Lua state object,
// which contains the key for the database record it needs to search for, as an argument. It uses the CheckString(1)
// method on the Lua state object to extract the required key.
// It then tries to retrieve the record associated with that key from the database using the HGetAll(ctx, key).Result() method
// on the ReadHandle object of the rediscli.
//
// In case of an error during the database operation, it pushes the nil value and the error message onto the Lua stack
// and return 2 (to represent two return values: nil and the error message), quitting the function.
//
// If the operation is successful, it increments the RedisReadCounter for statistics.
// It then creates a new Lua table and sets the fields and their corresponding values from the retrieved record into the table.
// Regardless of the original type of value in the record, all values are stored as strings in the Lua table.
//
// It then pushes this table onto the Lua stack and returns 1 (to represent one return value, which is the table containing
// the database records), thereby ending the function.
func RedisHGetAll(L *lua.LState) int {
	key := L.CheckString(1)

	result, err := rediscli.ReadHandle.HGetAll(ctx, key).Result()
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))

		return 2
	} else {
		stats.RedisReadCounter.Inc()
	}

	table := L.NewTable()
	for field, value := range result {
		// We cannot make a difference for the types of the values. So, all values are returned as strings
		table.RawSetString(field, lua.LString(value))
	}

	L.Push(table)

	return 1
}

// RedisHIncrBy is responsible for the increment operation on a hash field in a Redis data structure.
// It takes in 3 parameters: the state of the Lua interpreter (L *lua.LState), the target key,
// field, and the amount to increment.
//
// The function first checks the provided parameters and uses the HIncrBy method of the redis client
// to perform the increment operation. If successful, the function increments the RedisWriteCounter
// and pushes the new field value onto the Lua stack, returning 1.
//
// In case of an error, the function pushes nil and the error's message onto the Lua stack, then
// returning 2.
//
// Parameters:
// L *lua.LState: Pointer to the current state of the Lua interpreter.
// key: Name of the hash where the incremented field is kept.
// field: Name of the field to be incremented.
// increment: Amount to increment the field by.
//
// Returns:
// int: Returns 1 if the increment operation was successful, with the new field value pushed onto
// the Lua stack. Returns 2 if there was an error, with nil and the error's message pushed onto
// the Lua stack.
func RedisHIncrBy(L *lua.LState) int {
	key := L.CheckString(1)
	field := L.CheckString(2)
	increment := L.CheckInt64(3)

	val, err := rediscli.WriteHandle.HIncrBy(ctx, key, field, increment).Result()
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))

		return 2
	} else {
		stats.RedisWriteCounter.Inc()
	}

	L.Push(lua.LNumber(val))

	return 1
}

func RedisHIncrByFloat(L *lua.LState) int {
	key := L.CheckString(1)
	field := L.CheckString(2)
	increment := float64(L.CheckNumber(3))

	val, err := rediscli.WriteHandle.HIncrByFloat(ctx, key, field, increment).Result()
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))

		return 2
	} else {
		stats.RedisWriteCounter.Inc()
	}

	L.Push(lua.LNumber(val))

	return 1
}

// RedisHExists is a function which checks if the given field exists in the Redis hash stored at key.
// It accepts two flags, 'key' and 'field' to define the location of the data.
// This function interacts with the Redis instance through the ReadHandle.
// If an error occurs during the operation, the Lua state is pushed with 'nil' and the error message.
// If the operation is successful, the Lua state is pushed with either LTrue or LFalse, indicating the existence of the given field.
//
// Parameters:
//
//	L *lua.LState: The lua state
//
// Returns:
//
//	int: The status of the operation. If an error occurs, 2 is returned, otherwise 1.
func RedisHExists(L *lua.LState) int {
	key := L.CheckString(1)
	field := L.CheckString(2)

	exists, err := rediscli.ReadHandle.HExists(ctx, key, field).Result()
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))

		return 2
	} else {
		stats.RedisReadCounter.Inc()
	}

	if exists {
		L.Push(lua.LTrue)
	} else {
		L.Push(lua.LFalse)
	}

	return 1
}

// RedisRename renames a key in the Redis server.
// It takes two arguments: the old key and the new key.
// If the rename operation is successful, it returns "OK" as a Lua string.
// If an error occurs, it returns nil and the error message as a Lua string.
func RedisRename(L *lua.LState) int {
	oldKey := L.CheckString(1)
	newKey := L.CheckString(2)

	err := rediscli.WriteHandle.Rename(ctx, oldKey, newKey).Err()
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))

		return 2
	} else {
		stats.RedisWriteCounter.Inc()
	}

	L.Push(lua.LString("OK"))

	return 1
}

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

// SetUPRedisFunctions is a function that associates a set of Redis-related functions to a Lua table.
// Each function is linked to a string that corresponds to its name in the global Lua functions namespace.
// The provided Lua state `L` and the Lua table `table` are used to facilitate this setting up process.
// Here are the functions that this function sets up:
// - RedisGet
// - RedisSet
// - RedisIncr
// - RedisDel
// - RedisExpire
// - RedisHGet
// - RedisHSet
// - RedisHDel
// - RedisHLen
// - RedisHGetAll
// - RedisHIncrBy
func SetUPRedisFunctions(table *lua.LTable, L *lua.LState) {
	table.RawSetString(global.LuaFnRedisGet, L.NewFunction(RedisGet))
	table.RawSetString(global.LuaFnRedisSet, L.NewFunction(RedisSet))
	table.RawSetString(global.LuaFnRedisIncr, L.NewFunction(RedisIncr))
	table.RawSetString(global.LuaFnRedisDel, L.NewFunction(RedisDel))
	table.RawSetString(global.LuaFnRedisExpire, L.NewFunction(RedisExpire))
	table.RawSetString(global.LuaFnRedisHGet, L.NewFunction(RedisHGet))
	table.RawSetString(global.LuaFnRedisHSet, L.NewFunction(RedisHSet))
	table.RawSetString(global.LuaFnRedisHDel, L.NewFunction(RedisHDel))
	table.RawSetString(global.LuaFnRedisHLen, L.NewFunction(RedisHLen))
	table.RawSetString(global.LuaFnRedisHGetAll, L.NewFunction(RedisHGetAll))
	table.RawSetString(global.LuaFnRedisHIncrBy, L.NewFunction(RedisHIncrBy))
	table.RawSetString(global.LuaFnRedisHIncrByFloat, L.NewFunction(RedisHIncrByFloat))
	table.RawSetString(global.LuaFnRedisHExists, L.NewFunction(RedisHExists))
	table.RawSetString(global.LuaFnRedisRename, L.NewFunction(RedisRename))
	table.RawSetString(global.LuaFnRedisSAdd, L.NewFunction(RedisSAdd))
	table.RawSetString(global.LuaFnRedisSIsMember, L.NewFunction(RedisSIsMember))
	table.RawSetString(global.LuaFnRedisSMembers, L.NewFunction(RedisSMembers))
	table.RawSetString(global.LuaFnRedisSRem, L.NewFunction(RedisSRem))
	table.RawSetString(global.LuaFnRedisSCard, L.NewFunction(RedisSCard))
}
