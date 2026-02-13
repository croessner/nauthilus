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

	"github.com/croessner/nauthilus/server/lualib/luastack"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

// RedisLPush prepends one or more values to a list.
func (rm *RedisManager) RedisLPush(L *lua.LState) int {
	return executeWriteIntCmd(rm, L, collectLuaValues, func(ctx context.Context, conn redis.Cmdable, key string, values []any) *redis.IntCmd {
		return conn.LPush(ctx, key, values...)
	})
}

// RedisRPush appends one or more values to a list.
func (rm *RedisManager) RedisRPush(L *lua.LState) int {
	return executeWriteIntCmd(rm, L, collectLuaValues, func(ctx context.Context, conn redis.Cmdable, key string, values []any) *redis.IntCmd {
		return conn.RPush(ctx, key, values...)
	})
}

// RedisLPop removes and gets the first element in a list.
func (rm *RedisManager) RedisLPop(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)

		cmd := conn.LPop(ctx, key)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(lua.LString(cmd.Val()), lua.LNil)
	})
}

// RedisRPop removes and gets the last element in a list.
func (rm *RedisManager) RedisRPop(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)

		cmd := conn.RPop(ctx, key)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(lua.LString(cmd.Val()), lua.LNil)
	})
}

// RedisLRange gets a range of elements from a list.
func (rm *RedisManager) RedisLRange(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		start := int64(stack.CheckInt(3))
		stop := int64(stack.CheckInt(4))

		cmd := conn.LRange(ctx, key, start, stop)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		result := L.NewTable()
		for _, val := range cmd.Val() {
			result.Append(lua.LString(val))
		}

		return stack.PushResults(result, lua.LNil)
	})
}

// RedisLLen gets the length of a list.
func (rm *RedisManager) RedisLLen(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)

		cmd := conn.LLen(ctx, key)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(lua.LNumber(cmd.Val()), lua.LNil)
	})
}
