package redislib

import (
	"context"
	"time"

	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	lua "github.com/yuin/gopher-lua"
)

var ctx = context.TODO()

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
