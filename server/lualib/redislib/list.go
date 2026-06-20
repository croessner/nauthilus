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
	return executeKeyCmd(rm, L, true, func(ctx context.Context, conn redis.Cmdable, key string) *redis.StringCmd {
		return conn.LPop(ctx, key)
	}, luaStringValue)
}

// RedisRPop removes and gets the last element in a list.
func (rm *RedisManager) RedisRPop(L *lua.LState) int {
	return executeKeyCmd(rm, L, true, func(ctx context.Context, conn redis.Cmdable, key string) *redis.StringCmd {
		return conn.RPop(ctx, key)
	}, luaStringValue)
}

// RedisLRange gets a range of elements from a list.
func (rm *RedisManager) RedisLRange(L *lua.LState) int {
	return executeRangeStringSliceCmd(rm, L, func(ctx context.Context, conn redis.Cmdable, key string, start, stop int64) *redis.StringSliceCmd {
		return conn.LRange(ctx, key, start, stop)
	})
}

// RedisLLen gets the length of a list.
func (rm *RedisManager) RedisLLen(L *lua.LState) int {
	return executeKeyCmd(rm, L, false, func(ctx context.Context, conn redis.Cmdable, key string) *redis.IntCmd {
		return conn.LLen(ctx, key)
	}, luaNumberValue[int64])
}
