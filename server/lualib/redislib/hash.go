// Copyright (C) 2024 Christian Rößner
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

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	lua "github.com/yuin/gopher-lua"
)

// RedisHGet executes the HGET command in Redis, retrieves a field from a hash, and converts it to a Lua value type.
func RedisHGet(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetReadHandle())
		key := L.CheckString(2)
		field := L.CheckString(3)
		valueType := definitions.TypeString

		// Optional 4th argument selects the return type ("string", "number", "bool", "nil").
		// Signature: redis_hget(pool, key, field[, type])
		if L.GetTop() >= 4 {
			valueType = L.CheckString(4)
		}

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx)
		defer cancel()

		err := convert.StringCmd(client.HGet(dCtx, key, field), valueType, L)
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))

			return 2
		}

		return 1
	}
}

// RedisHSet sets multiple field-value pairs in a Redis hash stored at the given key and returns the number of new fields added.
func RedisHSet(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		var kvpairs []any

		if L.GetTop() < 4 || (L.GetTop()-2)%2 != 0 {
			L.Push(lua.LNil)
			L.Push(lua.LString("Invalid number of arguments"))

			return 2
		}

		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetWriteHandle())
		key := L.CheckString(2)

		for i := 3; i <= L.GetTop(); i += 2 {
			field := L.CheckString(i)

			value, err := convert.LuaValue(L.Get(i + 1))
			if err != nil {
				L.Push(lua.LNil)
				L.Push(lua.LString(err.Error()))

				return 2
			}

			kvpairs = append(kvpairs, field, value)
		}

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx)
		defer cancel()

		cmd := client.HSet(dCtx, key, kvpairs...)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisHDel is a Lua function that deletes one or more fields from a Redis hash and returns the count of removed fields.
func RedisHDel(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		var fields []string

		if L.GetTop() < 3 {
			L.Push(lua.LNil)
			L.Push(lua.LString("Invalid number of arguments"))

			return 2
		}

		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetWriteHandle())
		key := L.CheckString(2)

		for i := 3; i <= L.GetTop(); i += 1 {
			fields = append(fields, L.CheckString(i))
		}

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx)
		defer cancel()

		cmd := client.HDel(dCtx, key, fields...)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisHLen returns a Lua function that retrieves the length of a Redis hash stored at the specified key.
func RedisHLen(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetReadHandle())
		key := L.CheckString(2)

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx)
		defer cancel()

		cmd := client.HLen(dCtx, key)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisHGetAll retrieves all fields and values of a hash stored at the specified Redis key and returns them as a Lua table.
func RedisHGetAll(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetReadHandle())
		key := L.CheckString(2)

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx)
		defer cancel()

		cmd := client.HGetAll(dCtx, key)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		table := L.NewTable()
		for field, value := range cmd.Val() {
			// We cannot make a difference for the types of the values. So, all values are returned as strings
			table.RawSetString(field, lua.LString(value))
		}

		L.Push(table)

		return 1
	}
}

// RedisHMGet retrieves values for multiple fields within a Redis hash and returns them as a Lua table.
// The function expects parameters: pool, key, field1, field2, ...
// It returns a Lua table mapping field -> value (string), with missing fields set to nil. On error it returns (nil, err).
func RedisHMGet(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		if L.GetTop() < 4 { // pool, key, at least one field
			L.Push(lua.LNil)
			L.Push(lua.LString("Invalid number of arguments"))

			return 2
		}

		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetReadHandle())
		key := L.CheckString(2)

		fields := make([]string, 0, L.GetTop()-2)
		for i := 3; i <= L.GetTop(); i++ {
			fields = append(fields, L.CheckString(i))
		}

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx)
		defer cancel()

		vals, err := client.HMGet(dCtx, key, fields...).Result()
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))

			return 2
		}

		result := L.NewTable()
		for i, v := range vals {
			if v == nil {
				result.RawSetString(fields[i], lua.LNil)

				continue
			}

			// Redis returns bulk strings for HMGET items
			if s, ok := v.(string); ok {
				result.RawSetString(fields[i], lua.LString(s))
			} else {
				// Fallback: convert non-string via Lua string representation
				result.RawSetString(fields[i], lua.LString(lua.LVAsString(convert.GoToLuaValue(L, v))))
			}
		}

		L.Push(result)

		return 1
	}
}

// RedisHIncrBy increments the numerical value of a hash field in Redis by the specified amount and returns the new value.
func RedisHIncrBy(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetWriteHandle())
		key := L.CheckString(2)
		field := L.CheckString(3)
		increment := L.CheckInt64(4)

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx)
		defer cancel()

		cmd := client.HIncrBy(dCtx, key, field, increment)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisHIncrByFloat increments the float value of a field in a hash by a specified amount and returns the new value.
func RedisHIncrByFloat(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetWriteHandle())
		key := L.CheckString(2)
		field := L.CheckString(3)
		increment := float64(L.CheckNumber(4))

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx)
		defer cancel()

		cmd := client.HIncrByFloat(dCtx, key, field, increment)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisHExists checks if a specific field exists in a hash stored at a given key in Redis. It returns true or false.
func RedisHExists(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetReadHandle())
		key := L.CheckString(2)
		field := L.CheckString(3)

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx)
		defer cancel()

		cmd := client.HExists(dCtx, key, field)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LBool(cmd.Val()))

		return 1
	}
}
