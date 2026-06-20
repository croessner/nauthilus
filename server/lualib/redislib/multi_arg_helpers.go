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
	"time"

	"github.com/croessner/nauthilus/v3/server/lualib/convert"
	"github.com/croessner/nauthilus/v3/server/lualib/luastack"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

type redisValueCmd[T any] interface {
	Err() error
	Val() T
}

type redisNumeric interface {
	~float64 | ~int64
}

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

// executeKeyValueCmd handles key-only Redis commands that push one Lua value.
func executeKeyValueCmd[T any](
	rm *RedisManager,
	L *lua.LState,
	writable bool,
	cmdFn func(context.Context, redis.Cmdable, string) redisValueCmd[T],
	luaValue func(T) lua.LValue,
) int {
	handler := func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)

		cmd := cmdFn(ctx, conn, key)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(luaValue(cmd.Val()), lua.LNil)
	}

	if writable {
		return rm.ExecuteWrite(L, handler)
	}

	return rm.ExecuteRead(L, handler)
}

// executeKeyCmd adapts concrete key-only Redis command types to a Lua value.
func executeKeyCmd[T any, C redisValueCmd[T]](
	rm *RedisManager,
	L *lua.LState,
	writable bool,
	cmdFn func(context.Context, redis.Cmdable, string) C,
	luaValue func(T) lua.LValue,
) int {
	return executeKeyValueCmd(rm, L, writable, func(ctx context.Context, conn redis.Cmdable, key string) redisValueCmd[T] {
		return cmdFn(ctx, conn, key)
	}, luaValue)
}

// executeTwoStringValueCmd handles Redis commands with two string arguments.
func executeTwoStringValueCmd[T any](
	rm *RedisManager,
	L *lua.LState,
	writable bool,
	cmdFn func(context.Context, redis.Cmdable, string, string) redisValueCmd[T],
	luaValue func(T) lua.LValue,
) int {
	handler := func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		first := stack.CheckString(2)
		second := stack.CheckString(3)

		cmd := cmdFn(ctx, conn, first, second)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(luaValue(cmd.Val()), lua.LNil)
	}

	if writable {
		return rm.ExecuteWrite(L, handler)
	}

	return rm.ExecuteRead(L, handler)
}

// executeTwoStringCmd adapts concrete two-string Redis command types to a Lua value.
func executeTwoStringCmd[T any, C redisValueCmd[T]](
	rm *RedisManager,
	L *lua.LState,
	writable bool,
	cmdFn func(context.Context, redis.Cmdable, string, string) C,
	luaValue func(T) lua.LValue,
) int {
	return executeTwoStringValueCmd(rm, L, writable, func(ctx context.Context, conn redis.Cmdable, first, second string) redisValueCmd[T] {
		return cmdFn(ctx, conn, first, second)
	}, luaValue)
}

// luaNumberValue pushes Redis numeric command values as Lua numbers.
func luaNumberValue[T redisNumeric](value T) lua.LValue {
	return lua.LNumber(value)
}

// luaStringValue pushes Redis string command values as Lua strings.
func luaStringValue(value string) lua.LValue {
	return lua.LString(value)
}

// luaBoolValue pushes Redis boolean command values as Lua booleans.
func luaBoolValue(value bool) lua.LValue {
	return lua.LBool(value)
}

// executeKeyTwoStringNumberCmd handles key plus two string argument commands returning a Lua number.
func executeKeyTwoStringNumberCmd[T redisNumeric](
	rm *RedisManager,
	L *lua.LState,
	writable bool,
	cmdFn func(context.Context, redis.Cmdable, string, string, string) redisValueCmd[T],
) int {
	handler := func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		first := stack.CheckString(3)
		second := stack.CheckString(4)

		cmd := cmdFn(ctx, conn, key, first, second)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(lua.LNumber(cmd.Val()), lua.LNil)
	}

	if writable {
		return rm.ExecuteWrite(L, handler)
	}

	return rm.ExecuteRead(L, handler)
}

// executeKeyIndexRangeNumberCmd handles key plus start/stop index commands returning a Lua number.
func executeKeyIndexRangeNumberCmd(
	rm *RedisManager,
	L *lua.LState,
	writable bool,
	cmdFn func(context.Context, redis.Cmdable, string, int64, int64) *redis.IntCmd,
) int {
	handler := func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		start := int64(stack.CheckInt(3))
		stop := int64(stack.CheckInt(4))

		cmd := cmdFn(ctx, conn, key, start, stop)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(lua.LNumber(cmd.Val()), lua.LNil)
	}

	if writable {
		return rm.ExecuteWrite(L, handler)
	}

	return rm.ExecuteRead(L, handler)
}

// executeRangeStringSliceCmd handles index-range Redis commands that return string slices.
func executeRangeStringSliceCmd(
	rm *RedisManager,
	L *lua.LState,
	cmdFn func(context.Context, redis.Cmdable, string, int64, int64) *redis.StringSliceCmd,
) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		start := int64(stack.CheckInt(3))
		stop := int64(stack.CheckInt(4))

		cmd := cmdFn(ctx, conn, key, start, stop)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(luaStringSliceTable(L, cmd.Val()), lua.LNil)
	})
}

// executeHashIncrementCmd handles hash increment commands that return numeric values.
func executeHashIncrementCmd[T redisNumeric](
	rm *RedisManager,
	L *lua.LState,
	readIncrement func(*luastack.Manager, int) T,
	cmdFn func(context.Context, redis.Cmdable, string, string, T) redisValueCmd[T],
) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		hash := stack.CheckString(2)
		field := stack.CheckString(3)
		incr := readIncrement(stack, 4)

		cmd := cmdFn(ctx, conn, hash, field, incr)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(lua.LNumber(cmd.Val()), lua.LNil)
	})
}

// executeExpireCmd handles key plus second-duration Redis commands.
func executeExpireCmd(
	rm *RedisManager,
	L *lua.LState,
	cmdFn func(context.Context, redis.Cmdable, string, time.Duration) *redis.BoolCmd,
) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		seconds := stack.CheckInt(3)

		cmd := cmdFn(ctx, conn, key, time.Duration(seconds)*time.Second)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(lua.LBool(cmd.Val()), lua.LNil)
	})
}

// luaStringSliceTable converts Redis string slices into array-style Lua tables.
func luaStringSliceTable(L *lua.LState, values []string) *lua.LTable {
	result := L.NewTable()
	for _, val := range values {
		result.Append(lua.LString(val))
	}

	return result
}

// luaStringSliceValue returns a converter that pushes string slices as Lua arrays.
func luaStringSliceValue(L *lua.LState) func([]string) lua.LValue {
	return func(values []string) lua.LValue {
		return luaStringSliceTable(L, values)
	}
}
