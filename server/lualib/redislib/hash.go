package redislib

import (
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	lua "github.com/yuin/gopher-lua"
)

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

// RedisHIncrByFloat increments the value of a hash field by the provided floating-point increment.
// It retrieves a string `key`, a hash field `field`, and a floating-point `increment` from the Lua state.
// The function uses `rediscli.WriteHandle.HIncrByFloat` to handle the increment operation.
// If the operation is successful, it returns the new value as a Lua number.
// If an error occurs, it returns nil and an error message as Lua strings.
// The function is designed to be called from Lua scripts and uses the provided Lua state `L`.
// Example usage: `result = redis_hincrby_float("mykey", "myfield", 0.5)`.
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

// RedisHExists is a function that checks if the given field exists in the Redis hash stored at a key.
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