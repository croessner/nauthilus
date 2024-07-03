package lualib

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

var ctx = context.Background()

// convertLuaValue converts a Lua value to its corresponding Go type.
// It takes a lua.LValue as input and returns the converted value and an error.
// The function supports converting Lua strings to Go strings, Lua numbers to Go float64,
// Lua booleans to Go bool, and Lua nil to Go nil.
// If the Lua value is of any other type, it returns an error.
func convertLuaValue(lValue lua.LValue) (any, error) {
	switch lValue.Type() {
	case lua.LTString:
		return lua.LVAsString(lValue), nil
	case lua.LTNumber:
		return float64(lua.LVAsNumber(lValue)), nil
	case lua.LTBool:
		return lua.LVAsBool(lValue), nil
	case lua.LTNil:
		return nil, nil
	default:
		err := fmt.Errorf("unable to convert Lua value of type %s", lValue.Type())

		return nil, err
	}
}

// convertStringCmd attempts to convert a given *redis.StringCmd value into the specified type.
//
// Parameters:
// value: The redis.StringCmd value to be converted.
// valType: The type that the redis.StringCmd should be converted to. Acceptable values include:
//   - "string": converts the redis.StringCmd to a Lua string.
//   - "number": converts the redis.StringCmd to a Lua number. If the conversion fails, it returns an error.
//   - "boolean": converts the redis.StringCmd to a Lua boolean. If the conversion fails, it returns an error.
//
// L: The Lua state against which these conversions are made.
// This method pushes the converted value onto the L lua.LState if the conversion is successful.
//
// It returns nil if the conversion is successful.
// It returns an error if the conversion fails or if the conversion is attempted on an unsupported type.
//
// Example usage:
//
//	err := convertStringCmd(myStringCmd, "number", myLuaState)
//	if err != nil {
//	    log.Fatal(err)
//	}
func convertStringCmd(value *redis.StringCmd, valType string, L *lua.LState) error {
	switch valType {
	case global.TypeString:
		L.Push(lua.LString(value.Val()))
	case global.TypeNumber:
		if result, err := value.Float64(); err == nil {
			L.Push(lua.LNumber(result))
		} else {
			return err
		}
	case global.TypeBoolean:
		if result, err := value.Bool(); err == nil {
			L.Push(lua.LBool(result))
		} else {
			return err
		}
	case global.TypeNil:
		L.Push(lua.LNil)
	default:
		return fmt.Errorf("unable to convert string command of type %s", valType)
	}

	return nil
}

// RedisGet retrieves the value associated with the given key from the Redis server.
// It returns the value as a Lua string. If an error occurs, it returns nil and the error message as a Lua string.
// The function expects one argument: the key to retrieve.
// Example usage: val = redis_get_str("mykey")
func RedisGet(L *lua.LState) int {
	key := L.CheckString(1)
	valueType := global.TypeString

	if L.GetTop() == 1 {
		valueType = L.CheckString(2)
	}

	err := convertStringCmd(rediscli.ReadHandle.Get(ctx, key), valueType, L)
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

	value, err := convertLuaValue(L.Get(2))
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))

		return 2
	}

	if L.GetTop() == 3 {
		expiration, _ = time.ParseDuration(strconv.Itoa(L.CheckInt(3)))
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

	err := convertStringCmd(rediscli.ReadHandle.HGet(ctx, key, field), valueType, L)
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

	if (L.GetTop()-1)%2 != 0 {
		L.Push(lua.LNil)
		L.Push(lua.LString("Invalid number of arguments"))

		return 2
	}

	key := L.CheckString(1)

	for i := 2; i <= L.GetTop(); i += 2 {
		field := L.CheckString(i)

		value, err := convertLuaValue(L.Get(i + 1))
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

	if (L.GetTop()-1)%2 != 0 {
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

// RedisHIncrBy is a function that increments the value of a hash field stored in Redis database.
// The function accepts a lua.LState pointer and an integer value as parameters.
// It uses the `IncrBy` method from the redis client to increment the value of the key.
//
// Parameters:
// L *lua.LState - The state of the Lua interpreter.
//
// Returns:
// int - The return value is an integer. If the hash field increment operation is successful,
// the function returns 1 and pushes the new value on the Lua stack.
// If an error occurs, the function pushes `nil` and an error message on the Lua stack, and returns 2.
func RedisHIncrBy(L *lua.LState) int {
	key := L.CheckString(1)
	increment := L.CheckInt64(2)

	val, err := rediscli.WriteHandle.IncrBy(ctx, key, increment).Result()
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
	table.RawSetString(global.LuaFNRedisHIncrBy, L.NewFunction(RedisHIncrBy))
	table.RawSetString(global.LuaFnRedisHExists, L.NewFunction(RedisHExists))
}
