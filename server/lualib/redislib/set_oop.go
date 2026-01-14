//go:build redislib_oop

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

	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/lualib/luastack"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

// RedisSAdd adds one or more members to a set.
func (rm *RedisManager) RedisSAdd(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		top := stack.GetTop()
		values := make([]any, top-2)

		for i := 3; i <= top; i++ {
			val, err := convert.LuaValue(stack.CheckAny(i))
			if err != nil {
				return stack.PushError(err)
			}
			values[i-3] = val
		}

		cmd := conn.SAdd(ctx, key, values...)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResult(lua.LNumber(cmd.Val()))
	})
}

// RedisSIsMember checks if a member exists in a set.
func (rm *RedisManager) RedisSIsMember(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		val, err := convert.LuaValue(stack.CheckAny(3))
		if err != nil {
			return stack.PushError(err)
		}

		cmd := conn.SIsMember(ctx, key, val)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResult(lua.LBool(cmd.Val()))
	})
}

// RedisSMembers gets all members in a set.
func (rm *RedisManager) RedisSMembers(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)

		cmd := conn.SMembers(ctx, key)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		result := L.NewTable()
		for _, member := range cmd.Val() {
			result.Append(lua.LString(member))
		}

		return stack.PushResult(result)
	})
}

// RedisSRem removes one or more members from a set.
func (rm *RedisManager) RedisSRem(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		top := stack.GetTop()
		values := make([]any, top-2)

		for i := 3; i <= top; i++ {
			val, err := convert.LuaValue(stack.CheckAny(i))
			if err != nil {
				return stack.PushError(err)
			}
			values[i-3] = val
		}

		cmd := conn.SRem(ctx, key, values...)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResult(lua.LNumber(cmd.Val()))
	})
}

// RedisSCard returns the number of members in a set.
func (rm *RedisManager) RedisSCard(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)

		cmd := conn.SCard(ctx, key)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResult(lua.LNumber(cmd.Val()))
	})
}
