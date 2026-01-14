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

		return 1
	})
}

// RedisHSet sets the value of a hash field.
func (rm *RedisManager) RedisHSet(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		hash := stack.CheckString(2)
		field := stack.CheckString(3)
		value, err := convert.LuaValue(stack.CheckAny(4))
		if err != nil {
			return stack.PushError(err)
		}

		cmd := conn.HSet(ctx, hash, field, value)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResult(lua.LNumber(cmd.Val()))
	})
}

// RedisHDel deletes one or more hash fields.
func (rm *RedisManager) RedisHDel(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		hash := stack.CheckString(2)
		top := stack.GetTop()
		fields := make([]string, top-2)

		for i := 3; i <= top; i++ {
			fields[i-3] = stack.CheckString(i)
		}

		cmd := conn.HDel(ctx, hash, fields...)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResult(lua.LNumber(cmd.Val()))
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

		return stack.PushResult(lua.LNumber(cmd.Val()))
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

		return stack.PushResult(result)
	})
}

// RedisHMGet retrieves the values of multiple hash fields.
func (rm *RedisManager) RedisHMGet(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		hash := stack.CheckString(2)
		top := stack.GetTop()
		fields := make([]string, top-2)

		for i := 3; i <= top; i++ {
			fields[i-3] = stack.CheckString(i)
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

		return stack.PushResult(result)
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

		return stack.PushResult(lua.LNumber(cmd.Val()))
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

		return stack.PushResult(lua.LNumber(cmd.Val()))
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

		return stack.PushResult(lua.LBool(cmd.Val()))
	})
}
