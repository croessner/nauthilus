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

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib/convert"
	"github.com/croessner/nauthilus/v3/server/lualib/luastack"
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
			return stack.PushError(errors.New("invalid number of arguments"))
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
				return stack.PushError(errors.New("invalid number of arguments"))
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
	return executeWriteIntCmd(rm, L, collectLuaStrings, func(ctx context.Context, conn redis.Cmdable, key string, fields []string) *redis.IntCmd {
		return conn.HDel(ctx, key, fields...)
	})
}

// RedisHLen returns the number of fields in a hash.
func (rm *RedisManager) RedisHLen(L *lua.LState) int {
	return executeKeyCmd(rm, L, false, func(ctx context.Context, conn redis.Cmdable, hash string) *redis.IntCmd {
		return conn.HLen(ctx, hash)
	}, luaNumberValue[int64])
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
	return executeHashIncrementCmd(rm, L, readLuaInt64Increment, redisHIncrByCmd)
}

// RedisHIncrByFloat increments the float value of a hash field.
func (rm *RedisManager) RedisHIncrByFloat(L *lua.LState) int {
	return executeHashIncrementCmd(rm, L, readLuaFloatIncrement, redisHIncrByFloatCmd)
}

// readLuaInt64Increment reads an integer hash increment from the Lua stack.
func readLuaInt64Increment(stack *luastack.Manager, index int) int64 {
	return int64(stack.CheckInt(index))
}

// readLuaFloatIncrement reads a floating-point hash increment from the Lua stack.
func readLuaFloatIncrement(stack *luastack.Manager, index int) float64 {
	return float64(stack.CheckNumber(index))
}

// redisHIncrByCmd executes HINCRBY and exposes its value through the shared command interface.
func redisHIncrByCmd(ctx context.Context, conn redis.Cmdable, hash string, field string, incr int64) redisValueCmd[int64] {
	return conn.HIncrBy(ctx, hash, field, incr)
}

// redisHIncrByFloatCmd executes HINCRBYFLOAT and exposes its value through the shared command interface.
func redisHIncrByFloatCmd(ctx context.Context, conn redis.Cmdable, hash string, field string, incr float64) redisValueCmd[float64] {
	return conn.HIncrByFloat(ctx, hash, field, incr)
}

// RedisHExists checks if a hash field exists.
func (rm *RedisManager) RedisHExists(L *lua.LState) int {
	return executeTwoStringCmd(rm, L, false, func(ctx context.Context, conn redis.Cmdable, hash string, field string) *redis.BoolCmd {
		return conn.HExists(ctx, hash, field)
	}, luaBoolValue)
}
