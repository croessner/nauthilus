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
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/yuin/gopher-lua"
)

// RedisGet retrieves the value associated with the given key from the Redis server.
// It returns the value as a Lua string. If an error occurs, it returns nil and the error message as a Lua string.
// The function expects one argument: the key to retrieve.
// Example usage: val = redis_get_str("mykey")
func RedisGet(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetReadHandle())
		key := L.CheckString(2)
		valueType := definitions.TypeString

		if L.GetTop() == 3 {
			valueType = L.CheckString(3)
		}

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		err := convert.StringCmd(client.Get(ctx, key), valueType, L)
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))

			return 2
		}

		return 1
	}
}

// RedisSet sets the value of the given key to the provided value in the Redis server.
// It returns "OK" as a Lua string if the operation is successful.
// If an error occurs, it returns nil and the error message as a Lua string.
// The function expects two arguments: the key and the value to set.
func RedisSet(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		expiration := time.Duration(0)
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetWriteHandle())
		key := L.CheckString(2)

		value, err := convert.LuaValue(L.Get(3))
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))

			return 2
		}

		if L.GetTop() == 4 {
			expiration = time.Duration(L.CheckInt(4))
		}

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		cmd := client.Set(ctx, key, value, expiration*time.Second)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LString(cmd.Val()))

		return 1
	}
}

// RedisIncr increments the value associated with the given key in the Redis server.
// It returns the incremented value as a Lua number. If an error occurs, it returns nil
// and the error message as a Lua string.
// The function expects one argument: the key to increment.
// Example usage: val = redis_incr("counter")
func RedisIncr(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetWriteHandle())
		key := L.CheckString(2)

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		cmd := client.Incr(ctx, key)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisDel deletes the value associated with the given key from the Redis server.
// It returns "OK" as a Lua string if the delete operation is successful.
// If an error occurs, it returns nil and the error message as a Lua string.
// The function expects one argument: the key to delete.
func RedisDel(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetWriteHandle())
		key := L.CheckString(2)

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		cmd := client.Del(ctx, key)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisExpire sets a timeout on the specified key in the Redis server.
// It expects two arguments: the key and the expiration time in seconds.
// If the operation succeeds, it returns "OK" as a Lua string.
// If an error occurs, it returns nil and the error message as a Lua string.
// Example usage: result = redis_expire("mykey", 60)
func RedisExpire(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetWriteHandle())
		key := L.CheckString(2)
		expiration := L.CheckNumber(3)

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		cmd := client.Expire(ctx, key, time.Duration(expiration)*time.Second)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LBool(cmd.Val()))

		return 1
	}
}

// RedisRename renames a key in the Redis server.
// It takes two arguments: the old key and the new key.
// If the rename operation is successful, it returns "OK" as a Lua string.
// If an error occurs, it returns nil and the error message as a Lua string.
func RedisRename(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetWriteHandle())
		oldKey := L.CheckString(2)
		newKey := L.CheckString(3)

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		cmd := client.Rename(ctx, oldKey, newKey)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LString(cmd.Val()))

		return 1
	}
}

// RedisPing executes a Redis PING command and returns the result or an error message if it fails. Increases Redis read counter on success.
func RedisPing(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetReadHandle())

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		cmd := client.Ping(ctx)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LString(cmd.Val()))

		return 1
	}
}
