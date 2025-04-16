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
	lua "github.com/yuin/gopher-lua"
)

// RedisGet retrieves a value from Redis using the given key and pushes it to the Lua state based on a specified type.
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

// RedisSet provides a Lua function for setting a Redis key to a given value with optional expiration time in seconds.
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

// RedisIncr increments the integer value of a Redis key by 1 and returns the new value or an error if it fails.
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

// RedisDel deletes a given Redis key and reports the number of keys removed or an error if the operation fails.
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

// RedisExpire sets an expiration time on a Redis key and returns true if successful, or nil and an error if it fails.
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

// RedisRename renames a Redis key to a new key; returns an error if the operation fails.
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

// RedisExists checks if a given key exists in Redis, returning the count of matching keys as a Lua number.
func RedisExists(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetReadHandle())
		key := L.CheckString(2)

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		cmd := client.Exists(ctx, key)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}
