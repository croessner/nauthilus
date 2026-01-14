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
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/lualib/luastack"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

// RedisPing checks the connectivity to the Redis server.
func (rm *RedisManager) RedisPing(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		cmd := conn.Ping(ctx)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResult(lua.LString(cmd.Val()))
	})
}

// RedisGet retrieves a value from Redis using the given key and pushes it to the Lua state based on a specified type.
func (rm *RedisManager) RedisGet(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		valueType := definitions.TypeString

		if stack.GetTop() == 3 {
			valueType = stack.CheckString(3)
		}

		err := convert.StringCmd(conn.Get(ctx, key), valueType, L)
		if err != nil {
			return stack.PushError(err)
		}

		return 1
	})
}

// RedisSet provides a Lua function for setting a Redis key to a given value with optional expiration time in seconds.
func (rm *RedisManager) RedisSet(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)

		value, err := convert.LuaValue(stack.CheckAny(3))
		if err != nil {
			return stack.PushError(err)
		}

		var (
			useArgs bool
			args    redis.SetArgs
		)

		if stack.GetTop() >= 4 {
			if tbl, ok := L.Get(4).(*lua.LTable); ok {
				useArgs = true

				if v := tbl.RawGetString("nx"); v.Type() == lua.LTBool && lua.LVAsBool(v) {
					args.Mode = "NX"
				}

				if v := tbl.RawGetString("xx"); v.Type() == lua.LTBool && lua.LVAsBool(v) {
					args.Mode = "XX"
				}

				if v := tbl.RawGetString("get"); v.Type() == lua.LTBool && lua.LVAsBool(v) {
					args.Get = true
				}

				if v := tbl.RawGetString("keepttl"); v.Type() == lua.LTBool && lua.LVAsBool(v) {
					args.KeepTTL = true
				}

				if v := tbl.RawGetString("exat"); v.Type() == lua.LTNumber {
					sec := int64(lua.LVAsNumber(v))
					if sec > 0 {
						args.ExpireAt = time.Unix(sec, 0)
					}
				}

				if v := tbl.RawGetString("pxat"); v.Type() == lua.LTNumber {
					ms := int64(lua.LVAsNumber(v))
					if ms > 0 {
						args.ExpireAt = time.Unix(0, ms*int64(time.Millisecond))
					}
				}

				if v := tbl.RawGetString("ex"); v.Type() == lua.LTNumber {
					sec := int64(lua.LVAsNumber(v))
					if sec > 0 {
						args.TTL = time.Duration(sec) * time.Second
					}
				}

				if v := tbl.RawGetString("px"); v.Type() == lua.LTNumber {
					ms := int64(lua.LVAsNumber(v))
					if ms > 0 {
						args.TTL = time.Duration(ms) * time.Millisecond
					}
				}
			} else if L.Get(4).Type() == lua.LTNumber {
				ttlSeconds := int64(stack.CheckInt(4))
				if ttlSeconds < 0 {
					return stack.PushError(errors.New("expiration seconds must be >= 0"))
				}

				useArgs = false
				args.TTL = time.Duration(ttlSeconds) * time.Second
			}
		}

		if useArgs {
			cmd := conn.SetArgs(ctx, key, value, args)
			if cmd.Err() != nil {
				return stack.PushError(cmd.Err())
			}

			return stack.PushResult(lua.LString(cmd.Val()))
		}

		cmd := conn.Set(ctx, key, value, args.TTL)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResult(lua.LString(cmd.Val()))
	})
}

// RedisIncr increments the value of a key in Redis.
func (rm *RedisManager) RedisIncr(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)

		cmd := conn.Incr(ctx, key)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResult(lua.LNumber(cmd.Val()))
	})
}

// RedisDel deletes a key from Redis.
func (rm *RedisManager) RedisDel(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)

		cmd := conn.Del(ctx, key)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResult(lua.LNumber(cmd.Val()))
	})
}

// RedisExpire sets an expiration time on a key.
func (rm *RedisManager) RedisExpire(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		seconds := stack.CheckInt(3)

		cmd := conn.Expire(ctx, key, time.Duration(seconds)*time.Second)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResult(lua.LBool(cmd.Val()))
	})
}

// RedisExists checks if a key exists in Redis.
func (rm *RedisManager) RedisExists(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)

		cmd := conn.Exists(ctx, key)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		return stack.PushResult(lua.LNumber(cmd.Val()))
	})
}
