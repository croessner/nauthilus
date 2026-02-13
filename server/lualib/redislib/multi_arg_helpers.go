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

// collectFromStack is a generic helper that extracts values from the Lua stack
// starting at position 3, supporting both table and vararg input styles.
// The convertFn transforms each Lua value into the desired Go type.
func collectFromStack[T any](stack *luastack.Manager, convertFn func(lua.LValue) T) []T {
	top := stack.GetTop()

	var values []T

	if top == 3 && stack.L.Get(3).Type() == lua.LTTable {
		tbl := stack.CheckTable(3)

		tbl.ForEach(func(_, value lua.LValue) {
			values = append(values, convertFn(value))
		})
	} else {
		for i := 3; i <= top; i++ {
			values = append(values, convertFn(stack.CheckAny(i)))
		}
	}

	return values
}

// luaValueToAny converts a Lua value to a Go any using convert.LuaValue,
// falling back to the string representation on error.
func luaValueToAny(v lua.LValue) any {
	val, err := convert.LuaValue(v)
	if err != nil {
		return v.String()
	}

	return val
}

// luaValueToString converts a Lua value to its Go string representation.
func luaValueToString(v lua.LValue) string {
	return v.String()
}

// collectLuaValues extracts values from Lua stack position 3+ as []any,
// supporting both table and vararg input styles. Each value is converted
// via convert.LuaValue; on conversion error, the string representation is used.
func collectLuaValues(stack *luastack.Manager) []any {
	return collectFromStack(stack, luaValueToAny)
}

// collectLuaStrings extracts string arguments from Lua stack position 3+ as []string,
// supporting both table and vararg input styles.
func collectLuaStrings(stack *luastack.Manager) []string {
	return collectFromStack(stack, luaValueToString)
}

// executeWriteIntCmd handles the common pattern for Redis write commands:
// key (pos 2) + collected values (pos 3+) → IntCmd → push (count, nil).
// The collector extracts values and the cmdFn executes the Redis command.
func executeWriteIntCmd[T any](
	rm *RedisManager,
	L *lua.LState,
	collector func(*luastack.Manager) []T,
	cmdFn func(ctx context.Context, conn redis.Cmdable, key string, values []T) *redis.IntCmd,
) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		values := collector(stack)

		if len(values) == 0 {
			return stack.PushResults(lua.LNumber(0), lua.LNil)
		}

		cmd := cmdFn(ctx, conn, key, values)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(lua.LNumber(cmd.Val()), lua.LNil)
	})
}
