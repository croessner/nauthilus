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

	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	lua "github.com/yuin/gopher-lua"
)

// RedisLPush adds one or more values to the beginning of a Redis list and returns the length of the list after the push operation.
func RedisLPush(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, getDefaultClient().GetWriteHandle())
		key := L.CheckString(2)
		values := make([]any, L.GetTop()-2)

		for i := 3; i <= L.GetTop(); i++ {
			value, err := convert.LuaValue(L.Get(i))
			if err != nil {
				L.Push(lua.LNil)
				L.Push(lua.LString(err.Error()))

				return 2
			}

			values[i-3] = value
		}

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx)
		defer cancel()

		cmd := client.LPush(dCtx, key, values...)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisRPush adds one or more values to the end of a Redis list and returns the length of the list after the push operation.
func RedisRPush(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, getDefaultClient().GetWriteHandle())
		key := L.CheckString(2)
		values := make([]any, L.GetTop()-2)

		for i := 3; i <= L.GetTop(); i++ {
			value, err := convert.LuaValue(L.Get(i))
			if err != nil {
				L.Push(lua.LNil)
				L.Push(lua.LString(err.Error()))

				return 2
			}

			values[i-3] = value
		}

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx)
		defer cancel()

		cmd := client.RPush(dCtx, key, values...)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisLPop removes and returns the first element of a Redis list.
func RedisLPop(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, getDefaultClient().GetWriteHandle())
		key := L.CheckString(2)

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx)
		defer cancel()

		cmd := client.LPop(dCtx, key)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LString(cmd.Val()))

		return 1
	}
}

// RedisRPop removes and returns the last element of a Redis list.
func RedisRPop(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, getDefaultClient().GetWriteHandle())
		key := L.CheckString(2)

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx)
		defer cancel()

		cmd := client.RPop(dCtx, key)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LString(cmd.Val()))

		return 1
	}
}

// RedisLRange returns a range of elements from a Redis list.
func RedisLRange(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, getDefaultClient().GetReadHandle())
		key := L.CheckString(2)
		start := L.CheckInt64(3)
		stop := L.CheckInt64(4)

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx)
		defer cancel()

		cmd := client.LRange(dCtx, key, start, stop)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		result := L.NewTable()
		for _, val := range cmd.Val() {
			result.Append(lua.LString(val))
		}

		L.Push(result)

		return 1
	}
}

// RedisLLen returns the length of a Redis list.
func RedisLLen(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, getDefaultClient().GetReadHandle())
		key := L.CheckString(2)

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx)
		defer cancel()

		cmd := client.LLen(dCtx, key)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}
