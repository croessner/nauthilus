// Copyright (C) 2025 Christian Rößner
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

// RedisPFAdd adds the specified elements to the specified HyperLogLog (HLL) key.
// Returns 1 if at least one internal register was altered, 0 otherwise.
// Usage from Lua: nauthilus_redis.redis_pfadd(client_or_"default", key, element1, element2, ...)
func RedisPFAdd(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return func(L *lua.LState) int {
		conn := getRedisConnectionWithFallback(L, client.GetWriteHandle())
		key := L.CheckString(2)

		values := make([]any, 0, max(0, L.GetTop()-2))
		for i := 3; i <= L.GetTop(); i++ {
			val, err := convert.LuaValue(L.Get(i))
			if err != nil {
				L.Push(lua.LNil)
				L.Push(lua.LString(err.Error()))

				return 2
			}

			values = append(values, val)
		}

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, cfg)
		defer cancel()

		cmd := conn.PFAdd(dCtx, key, values...)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisPFCount returns the approximated cardinality computed by the HyperLogLog at the specified keys.
// When multiple keys are provided, returns the approximated cardinality of the union of the HyperLogLogs.
// Usage from Lua: nauthilus_redis.redis_pfcount(client_or_"default", key1, [key2, ...])
func RedisPFCount(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return func(L *lua.LState) int {
		conn := getRedisConnectionWithFallback(L, client.GetReadHandle())

		if L.GetTop() < 2 {
			L.Push(lua.LNil)
			L.Push(lua.LString("at least one key required"))

			return 2
		}

		keys := make([]string, 0, L.GetTop()-1)
		for i := 2; i <= L.GetTop(); i++ {
			keys = append(keys, L.CheckString(i))
		}

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, cfg)
		defer cancel()

		cmd := conn.PFCount(dCtx, keys...)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisPFMerge merges multiple HyperLogLogs into a destination key.
// Returns "OK" on success.
// Usage from Lua: nauthilus_redis.redis_pfmerge(client_or_"default", destKey, sourceKey1, [sourceKey2, ...])
func RedisPFMerge(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return func(L *lua.LState) int {
		conn := getRedisConnectionWithFallback(L, client.GetWriteHandle())

		dest := L.CheckString(2)
		if L.GetTop() < 3 {
			L.Push(lua.LNil)
			L.Push(lua.LString("at least one source key required"))

			return 2
		}

		sources := make([]string, 0, L.GetTop()-2)
		for i := 3; i <= L.GetTop(); i++ {
			sources = append(sources, L.CheckString(i))
		}

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, cfg)
		defer cancel()

		cmd := conn.PFMerge(dCtx, dest, sources...)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LString(cmd.Val()))

		return 1
	}
}
