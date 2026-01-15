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

		var values []any

		if top == 3 && stack.L.Get(3).Type() == lua.LTTable {
			tbl := stack.CheckTable(3)
			tbl.ForEach(func(_, value lua.LValue) {
				val, err := convert.LuaValue(value)
				if err != nil {
					values = append(values, value.String())
				} else {
					values = append(values, val)
				}
			})
		} else {
			for i := 3; i <= top; i++ {
				val, err := convert.LuaValue(stack.CheckAny(i))
				if err != nil {
					values = append(values, stack.CheckAny(i).String())
				} else {
					values = append(values, val)
				}
			}
		}

		if len(values) == 0 {
			return stack.PushResults(lua.LNumber(0), lua.LNil)
		}

		cmd := conn.SAdd(ctx, key, values...)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(lua.LNumber(cmd.Val()), lua.LNil)
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

		return stack.PushResults(lua.LBool(cmd.Val()), lua.LNil)
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

		return stack.PushResults(result, lua.LNil)
	})
}

// RedisSRem removes one or more members from a set.
func (rm *RedisManager) RedisSRem(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		top := stack.GetTop()

		var values []any

		if top == 3 && stack.L.Get(3).Type() == lua.LTTable {
			tbl := stack.CheckTable(3)
			tbl.ForEach(func(_, value lua.LValue) {
				val, err := convert.LuaValue(value)
				if err != nil {
					values = append(values, value.String())
				} else {
					values = append(values, val)
				}
			})
		} else {
			for i := 3; i <= top; i++ {
				val, err := convert.LuaValue(stack.CheckAny(i))
				if err != nil {
					values = append(values, stack.CheckAny(i).String())
				} else {
					values = append(values, val)
				}
			}
		}

		if len(values) == 0 {
			return stack.PushResults(lua.LNumber(0), lua.LNil)
		}

		cmd := conn.SRem(ctx, key, values...)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(lua.LNumber(cmd.Val()), lua.LNil)
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

		return stack.PushResults(lua.LNumber(cmd.Val()), lua.LNil)
	})
}
