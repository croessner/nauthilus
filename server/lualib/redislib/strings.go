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

// RedisMGet retrieves the values of multiple keys from Redis.
func (rm *RedisManager) RedisMGet(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		top := stack.GetTop()
		var keys []string

		if top == 2 && stack.L.Get(2).Type() == lua.LTTable {
			tbl := stack.CheckTable(2)
			tbl.ForEach(func(_, value lua.LValue) {
				keys = append(keys, value.String())
			})
		} else {
			for i := 2; i <= top; i++ {
				keys = append(keys, stack.CheckString(i))
			}
		}

		if len(keys) == 0 {
			return stack.PushResults(L.NewTable(), lua.LNil)
		}

		cmd := conn.MGet(ctx, keys...)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		result := L.NewTable()
		for i, val := range cmd.Val() {
			if val == nil {
				result.RawSetString(keys[i], lua.LNil)
			} else {
				result.RawSetString(keys[i], lua.LString(val.(string)))
			}
		}

		return stack.PushResults(result, lua.LNil)
	})
}

// RedisMSet sets multiple key-value pairs in Redis.
func (rm *RedisManager) RedisMSet(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		top := stack.GetTop()
		var kvpairs []any

		if top == 2 && stack.L.Get(2).Type() == lua.LTTable {
			tbl := stack.CheckTable(2)
			tbl.ForEach(func(key, value lua.LValue) {
				k, err := convert.LuaValue(key)
				if err != nil {
					kvpairs = append(kvpairs, key.String())
				} else {
					kvpairs = append(kvpairs, k)
				}

				v, err := convert.LuaValue(value)
				if err != nil {
					kvpairs = append(kvpairs, value.String())
				} else {
					kvpairs = append(kvpairs, v)
				}
			})
		} else {
			if top < 3 || (top-1)%2 != 0 {
				return stack.PushError(errors.New("invalid number of arguments"))
			}

			for i := 2; i <= top; i++ {
				value, err := convert.LuaValue(stack.CheckAny(i))
				if err != nil {
					kvpairs = append(kvpairs, stack.CheckAny(i).String())
				} else {
					kvpairs = append(kvpairs, value)
				}
			}
		}

		if len(kvpairs) == 0 {
			return stack.PushResults(lua.LString("OK"), lua.LNil)
		}

		cmd := conn.MSet(ctx, kvpairs...)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(lua.LString(cmd.Val()), lua.LNil)
	})
}

// RedisKeys returns all keys matching a pattern.
func (rm *RedisManager) RedisKeys(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		pattern := stack.CheckString(2)

		cmd := conn.Keys(ctx, pattern)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		result := L.NewTable()
		for _, key := range cmd.Val() {
			result.Append(lua.LString(key))
		}

		return stack.PushResults(result, lua.LNil)
	})
}

// RedisScan incrementally iterates over keys in Redis.
func (rm *RedisManager) RedisScan(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		cursor := uint64(stack.CheckNumber(2))
		match := stack.OptString(3, "*")
		count := int64(stack.OptNumber(4, 10))

		keys, cursor, err := conn.Scan(ctx, cursor, match, count).Result()
		if err != nil {
			return stack.PushError(err)
		}

		result := L.NewTable()
		result.RawSetString("cursor", lua.LNumber(cursor))

		keysTable := L.NewTable()
		for i, key := range keys {
			keysTable.RawSetInt(i+1, lua.LString(key))
		}
		result.RawSetString("keys", keysTable)

		return stack.PushResults(result, lua.LNil)
	})
}
