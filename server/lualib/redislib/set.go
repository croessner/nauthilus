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
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/yuin/gopher-lua"
)

// RedisSAdd adds one or more members to a Redis set associated with the given key and returns the count of added members.
func RedisSAdd(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetWriteHandle())
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

		cmd := client.SAdd(ctx, key, values...)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisSIsMember determines if a specified value is a member of a Redis set, returning a boolean or an error.
func RedisSIsMember(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetReadHandle())
		key := L.CheckString(2)

		value, err := convert.LuaValue(L.Get(3))
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))

			return 2
		}

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		cmd := client.SIsMember(ctx, key, value)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LBool(cmd.Val()))

		return 1
	}
}

// RedisSMembers retrieves all members of a Redis set corresponding to the given key and returns them as a Lua table.
func RedisSMembers(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetReadHandle())
		key := L.CheckString(2)

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		cmd := client.SMembers(ctx, key)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		members := cmd.Val()
		table := L.NewTable()
		for _, member := range members {
			table.Append(convert.GoToLuaValue(L, member))
		}

		L.Push(table)

		return 1
	}
}

// RedisSRem removes one or more members from a Redis set identified by the given key. Returns the count of removed members.
func RedisSRem(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetWriteHandle())
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

		cmd := client.SRem(ctx, key, values...)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisSCard returns a Lua function to retrieve the cardinality (number of elements) of a Redis set for a given key.
func RedisSCard(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetReadHandle())
		key := L.CheckString(2)

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		cmd := client.SCard(ctx, key)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}
