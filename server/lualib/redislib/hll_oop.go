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
	"errors"

	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/lualib/luastack"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

// RedisPFAdd adds the specified elements to the specified HyperLogLog (HLL) key.
func (rm *RedisManager) RedisPFAdd(L *lua.LState) int {
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

		cmd := conn.PFAdd(ctx, key, values...)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(lua.LNumber(cmd.Val()), lua.LNil)
	})
}

// RedisPFCount returns the approximated cardinality computed by the HyperLogLog at the specified keys.
func (rm *RedisManager) RedisPFCount(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		top := stack.GetTop()
		if top < 2 {
			return stack.PushError(errors.New("at least one key required"))
		}

		keys := make([]string, 0, top-1)
		for i := 2; i <= top; i++ {
			keys = append(keys, stack.CheckString(i))
		}

		cmd := conn.PFCount(ctx, keys...)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(lua.LNumber(cmd.Val()), lua.LNil)
	})
}

// RedisPFMerge merges multiple HyperLogLogs into a destination key.
func (rm *RedisManager) RedisPFMerge(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		dest := stack.CheckString(2)
		top := stack.GetTop()

		var sources []string

		if top == 3 && stack.L.Get(3).Type() == lua.LTTable {
			tbl := stack.CheckTable(3)
			tbl.ForEach(func(_, value lua.LValue) {
				sources = append(sources, value.String())
			})
		} else {
			for i := 3; i <= top; i++ {
				sources = append(sources, stack.CheckString(i))
			}
		}

		if len(sources) == 0 {
			return stack.PushResults(lua.LString("OK"), lua.LNil)
		}

		cmd := conn.PFMerge(ctx, dest, sources...)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(lua.LString(cmd.Val()), lua.LNil)
	})
}
