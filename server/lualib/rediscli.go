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
	valueType := L.CheckString(2)

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
	luaValue := L.Get(2)

	value, err := convertLuaValue(luaValue)
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
