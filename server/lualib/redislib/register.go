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

	"github.com/croessner/nauthilus/server/global"
	"github.com/yuin/gopher-lua"
)

// LoaderModRedis initializes a new module for Redis in Lua by setting the functions from the "exportsModRedis" map into
// a new lua.LTable. The module table is then pushed onto the top of the stack. Finally, it returns 1 to indicate that
// one value has been returned to Lua.
func LoaderModRedis(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			global.LuaFnRedisRegisterRedisPool:  RegisterRedisPool,
			global.LuaFnRedisGetRedisConnection: GetRedisConnection,

			global.LuaFnRedisPing:         RedisPing(ctx),
			global.LuaFnRedisGet:          RedisGet(ctx),
			global.LuaFnRedisSet:          RedisSet(ctx),
			global.LuaFnRedisIncr:         RedisIncr(ctx),
			global.LuaFnRedisDel:          RedisDel(ctx),
			global.LuaFnRedisExpire:       RedisExpire(ctx),
			global.LuaFnRedisHGet:         RedisHGet(ctx),
			global.LuaFnRedisHSet:         RedisHSet(ctx),
			global.LuaFnRedisHDel:         RedisHDel(ctx),
			global.LuaFnRedisHLen:         RedisHLen(ctx),
			global.LuaFnRedisHGetAll:      RedisHGetAll(ctx),
			global.LuaFnRedisHIncrBy:      RedisHIncrBy(ctx),
			global.LuaFnRedisHIncrByFloat: RedisHIncrByFloat(ctx),
			global.LuaFnRedisHExists:      RedisHExists(ctx),
			global.LuaFnRedisRename:       RedisRename(ctx),
			global.LuaFnRedisSAdd:         RedisSAdd(ctx),
			global.LuaFnRedisSIsMember:    RedisSIsMember(ctx),
			global.LuaFnRedisSMembers:     RedisSMembers(ctx),
			global.LuaFnRedisSRem:         RedisSRem(ctx),
			global.LuaFnRedisSCard:        RedisSCard(ctx),
			global.LuaFnRedisRunScript:    RedisRunScript(ctx),
			global.LuaFnRedisUploadScript: RedisUploadScript(ctx),
		})

		L.Push(mod)

		return 1
	}
}
