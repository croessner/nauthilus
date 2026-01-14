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

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	lua "github.com/yuin/gopher-lua"
)

// RedisMGet retrieves the values of multiple keys from Redis.
func RedisMGet(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return func(L *lua.LState) int {
		conn := getRedisConnectionWithFallback(L, client.GetReadHandle())
		keys := make([]string, L.GetTop()-1)

		for i := 2; i <= L.GetTop(); i++ {
			keys[i-2] = L.CheckString(i)
		}

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, cfg)
		defer cancel()

		cmd := conn.MGet(dCtx, keys...)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		result := L.NewTable()
		for i, val := range cmd.Val() {
			if val == nil {
				result.RawSetString(keys[i], lua.LNil)
			} else {
				result.RawSetString(keys[i], lua.LString(val.(string)))
			}
		}

		L.Push(result)

		return 1
	}
}

// RedisMSet sets multiple key-value pairs in Redis.
func RedisMSet(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return func(L *lua.LState) int {
		if L.GetTop() < 3 || (L.GetTop()-1)%2 != 0 {
			L.Push(lua.LNil)
			L.Push(lua.LString("Invalid number of arguments"))

			return 2
		}

		conn := getRedisConnectionWithFallback(L, client.GetWriteHandle())
		kvpairs := make([]any, L.GetTop()-1)

		for i := 2; i <= L.GetTop(); i++ {
			value, err := convert.LuaValue(L.Get(i))
			if err != nil {
				L.Push(lua.LNil)
				L.Push(lua.LString(err.Error()))

				return 2
			}

			kvpairs[i-2] = value
		}

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, cfg)
		defer cancel()

		cmd := conn.MSet(dCtx, kvpairs...)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LString(cmd.Val()))

		return 1
	}
}

// RedisKeys returns all keys matching a pattern.
func RedisKeys(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return func(L *lua.LState) int {
		conn := getRedisConnectionWithFallback(L, client.GetReadHandle())
		pattern := L.CheckString(2)

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, cfg)
		defer cancel()

		cmd := conn.Keys(dCtx, pattern)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		result := L.NewTable()
		for _, key := range cmd.Val() {
			result.Append(lua.LString(key))
		}

		L.Push(result)

		return 1
	}
}

// RedisScan incrementally iterates over keys in Redis.
func RedisScan(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return func(L *lua.LState) int {
		conn := getRedisConnectionWithFallback(L, client.GetReadHandle())
		cursor := uint64(L.CheckNumber(2))
		match := L.OptString(3, "*")
		count := int64(L.OptNumber(4, 10))

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, cfg)
		defer cancel()

		// Use the Scan command to get a batch of keys
		keys, cursor, err := conn.Scan(dCtx, cursor, match, count).Result()
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))

			return 2
		}

		// Create a table to hold the result
		result := L.NewTable()
		result.RawSetString("cursor", lua.LNumber(cursor))

		// Create a table to hold the keys
		keysTable := L.NewTable()
		for i, key := range keys {
			keysTable.RawSetInt(i+1, lua.LString(key))
		}
		result.RawSetString("keys", keysTable)

		L.Push(result)

		return 1
	}
}
