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
	"github.com/yuin/gopher-lua"
)

// LoaderModRedis initializes a new module for Redis in Lua by setting the functions from the "exportsModRedis" map into
// a new lua.LTable. The module table is then pushed onto the top of the stack. Finally, it returns 1 to indicate that
// one value has been returned to Lua.
func LoaderModRedis(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnRedisRegisterRedisPool:  RegisterRedisPool,
			definitions.LuaFnRedisGetRedisConnection: GetRedisConnection,

			definitions.LuaFnRedisPing:         RedisPing(ctx),
			definitions.LuaFnRedisGet:          RedisGet(ctx),
			definitions.LuaFnRedisSet:          RedisSet(ctx),
			definitions.LuaFnRedisIncr:         RedisIncr(ctx),
			definitions.LuaFnRedisDel:          RedisDel(ctx),
			definitions.LuaFnRedisExpire:       RedisExpire(ctx),
			definitions.LuaFnRedisHGet:         RedisHGet(ctx),
			definitions.LuaFnRedisHSet:         RedisHSet(ctx),
			definitions.LuaFnRedisHDel:         RedisHDel(ctx),
			definitions.LuaFnRedisHLen:         RedisHLen(ctx),
			definitions.LuaFnRedisHGetAll:      RedisHGetAll(ctx),
			definitions.LuaFnRedisHIncrBy:      RedisHIncrBy(ctx),
			definitions.LuaFnRedisHIncrByFloat: RedisHIncrByFloat(ctx),
			definitions.LuaFnRedisHExists:      RedisHExists(ctx),
			definitions.LuaFnRedisRename:       RedisRename(ctx),
			definitions.LuaFnRedisSAdd:         RedisSAdd(ctx),
			definitions.LuaFnRedisSIsMember:    RedisSIsMember(ctx),
			definitions.LuaFnRedisSMembers:     RedisSMembers(ctx),
			definitions.LuaFnRedisSRem:         RedisSRem(ctx),
			definitions.LuaFnRedisSCard:        RedisSCard(ctx),
			definitions.LuaFnRedisRunScript:    RedisRunScript(ctx),
			definitions.LuaFnRedisUploadScript: RedisUploadScript(ctx),
		})

		L.Push(mod)

		return 1
	}
}
