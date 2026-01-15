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

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/lualib/luastack"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

// RedisHGet retrieves the value of a hash field.
func (rm *RedisManager) RedisHGet(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		hash := stack.CheckString(2)
		field := stack.CheckString(3)
		valueType := definitions.TypeString

		if stack.GetTop() == 4 {
			valueType = stack.CheckString(4)
		}

		err := convert.StringCmd(conn.HGet(ctx, hash, field), valueType, L)
		if err != nil {
			return stack.PushError(err)
		}

		return 2
	})
}

// RedisHSet sets the value of a hash field.
func (rm *RedisManager) RedisHSet(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		hash := stack.CheckString(2)
		top := stack.GetTop()
		var values []any

		if top < 3 {
			return stack.PushError(errors.New("Invalid number of arguments"))
		}

		if top == 3 && stack.L.Get(3).Type() == lua.LTTable {
			tbl := stack.CheckTable(3)

			tbl.ForEach(func(key, value lua.LValue) {
				values = append(values, key.String())

				val, err := convert.LuaValue(value)
				if err != nil {
					values = append(values, value.String())
				} else {
					values = append(values, val)
				}
			})
		} else {
			if top < 4 || (top-2)%2 != 0 {
				return stack.PushError(errors.New("Invalid number of arguments"))
			}

			for i := 3; i <= top; i += 2 {
				field := stack.CheckString(i)

				value, err := convert.LuaValue(stack.CheckAny(i + 1))
				if err != nil {
					values = append(values, field, stack.CheckAny(i+1).String())
				} else {
					values = append(values, field, value)
				}
			}
		}

		if len(values) == 0 {
			return stack.PushResults(lua.LNumber(0), lua.LNil)
		}

		cmd := conn.HSet(ctx, hash, values...)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(lua.LNumber(cmd.Val()), lua.LNil)
	})
}

// RedisHDel deletes one or more hash fields.
func (rm *RedisManager) RedisHDel(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		hash := stack.CheckString(2)
		top := stack.GetTop()

		var fields []string

		if top == 3 && stack.L.Get(3).Type() == lua.LTTable {
			tbl := stack.CheckTable(3)

			tbl.ForEach(func(_, value lua.LValue) {
				fields = append(fields, value.String())
			})
		} else {
			for i := 3; i <= top; i++ {
				fields = append(fields, stack.CheckString(i))
			}
		}

		if len(fields) == 0 {
			return stack.PushResults(lua.LNumber(0), lua.LNil)
		}

		cmd := conn.HDel(ctx, hash, fields...)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(lua.LNumber(cmd.Val()), lua.LNil)
	})
}

// RedisHLen returns the number of fields in a hash.
func (rm *RedisManager) RedisHLen(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		hash := stack.CheckString(2)

		cmd := conn.HLen(ctx, hash)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(lua.LNumber(cmd.Val()), lua.LNil)
	})
}

// RedisHGetAll returns all fields and values of a hash.
func (rm *RedisManager) RedisHGetAll(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		hash := stack.CheckString(2)

		cmd := conn.HGetAll(ctx, hash)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		result := L.NewTable()

		for k, v := range cmd.Val() {
			result.RawSetString(k, lua.LString(v))
		}

		return stack.PushResults(result, lua.LNil)
	})
}

// RedisHMGet retrieves the values of multiple hash fields.
func (rm *RedisManager) RedisHMGet(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		hash := stack.CheckString(2)
		top := stack.GetTop()
		var fields []string

		if top == 3 && stack.L.Get(3).Type() == lua.LTTable {
			tbl := stack.CheckTable(3)

			tbl.ForEach(func(_, value lua.LValue) {
				fields = append(fields, value.String())
			})
		} else {
			for i := 3; i <= top; i++ {
				fields = append(fields, stack.CheckString(i))
			}
		}

		if len(fields) == 0 {
			return stack.PushResults(L.NewTable(), lua.LNil)
		}

		cmd := conn.HMGet(ctx, hash, fields...)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		result := L.NewTable()

		for i, val := range cmd.Val() {
			if val == nil {
				result.RawSetString(fields[i], lua.LNil)
			} else {
				result.RawSetString(fields[i], lua.LString(val.(string)))
			}
		}

		return stack.PushResults(result, lua.LNil)
	})
}

// RedisHIncrBy increments the integer value of a hash field.
func (rm *RedisManager) RedisHIncrBy(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		hash := stack.CheckString(2)
		field := stack.CheckString(3)
		incr := int64(stack.CheckInt(4))

		cmd := conn.HIncrBy(ctx, hash, field, incr)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(lua.LNumber(cmd.Val()), lua.LNil)
	})
}

// RedisHIncrByFloat increments the float value of a hash field.
func (rm *RedisManager) RedisHIncrByFloat(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		hash := stack.CheckString(2)
		field := stack.CheckString(3)
		incr := float64(stack.CheckNumber(4))

		cmd := conn.HIncrByFloat(ctx, hash, field, incr)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(lua.LNumber(cmd.Val()), lua.LNil)
	})
}

// RedisHExists checks if a hash field exists.
func (rm *RedisManager) RedisHExists(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		hash := stack.CheckString(2)
		field := stack.CheckString(3)

		cmd := conn.HExists(ctx, hash, field)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResults(lua.LBool(cmd.Val()), lua.LNil)
	})
}
