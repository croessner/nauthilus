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
	lua "github.com/yuin/gopher-lua"
)

// LoaderModRedis initializes and returns a Lua table with Redis-related functions registered within the provided context.
func LoaderModRedis(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnRedisRegisterRedisPool:  RegisterRedisPool,
			definitions.LuaFnRedisGetRedisConnection: GetRedisConnection,

			definitions.LuaFnRedisPing:                 RedisPing(ctx),
			definitions.LuaFnRedisGet:                  RedisGet(ctx),
			definitions.LuaFnRedisSet:                  RedisSet(ctx),
			definitions.LuaFnRedisIncr:                 RedisIncr(ctx),
			definitions.LuaFnRedisDel:                  RedisDel(ctx),
			definitions.LuaFnRedisExpire:               RedisExpire(ctx),
			definitions.LuaFnRedisExists:               RedisExists(ctx),
			definitions.LuaFnRedisHGet:                 RedisHGet(ctx),
			definitions.LuaFnRedisHSet:                 RedisHSet(ctx),
			definitions.LuaFnRedisHDel:                 RedisHDel(ctx),
			definitions.LuaFnRedisHLen:                 RedisHLen(ctx),
			definitions.LuaFnRedisHGetAll:              RedisHGetAll(ctx),
			definitions.LuaFnRedisHIncrBy:              RedisHIncrBy(ctx),
			definitions.LuaFnRedisHIncrByFloat:         RedisHIncrByFloat(ctx),
			definitions.LuaFnRedisHExists:              RedisHExists(ctx),
			definitions.LuaFnRedisRename:               RedisRename(ctx),
			definitions.LuaFnRedisSAdd:                 RedisSAdd(ctx),
			definitions.LuaFnRedisSIsMember:            RedisSIsMember(ctx),
			definitions.LuaFnRedisSMembers:             RedisSMembers(ctx),
			definitions.LuaFnRedisSRem:                 RedisSRem(ctx),
			definitions.LuaFnRedisSCard:                RedisSCard(ctx),
			definitions.LuaFnRedisRunScript:            RedisRunScript(ctx),
			definitions.LuaFnRedisUploadScript:         RedisUploadScript(ctx),
			definitions.LuaFnRedisPipeline:             RedisPipeline(ctx),
			definitions.LuaFnRedisZAdd:                 RedisZAdd(ctx),
			definitions.LuaFnRedisZRem:                 RedisZRem(ctx),
			definitions.LuaFnRedisZRank:                RedisZRank(ctx),
			definitions.LuaFNRedisZRange:               RedisZRange(ctx),
			definitions.LuaFnRedisZRevRange:            RedisZRevRange(ctx),
			definitions.LuaFnRedisZRangeByScore:        RedisZRangeByScore(ctx),
			definitions.LuaFnRedisZRemRangeByScore:     RedisZRemRangeByScore(ctx),
			definitions.LuaFnRedisRedisZRemRangeByRank: RedisZRemRangeByRank(ctx),
			definitions.LuaFnRedisZCount:               RedisZCount(ctx),
			definitions.LuaFnRedisZScore:               RedisZScore(ctx),
			definitions.LuaFnRedisRedisZRevRank:        RedisZRevRank(ctx),
			definitions.LuaFnRedisZIncrBy:              RedisZIncrBy(ctx),
			definitions.LuaFnRedisLPush:                RedisLPush(ctx),
			definitions.LuaFnRedisRPush:                RedisRPush(ctx),
			definitions.LuaFnRedisLPop:                 RedisLPop(ctx),
			definitions.LuaFnRedisRPop:                 RedisRPop(ctx),
			definitions.LuaFnRedisLRange:               RedisLRange(ctx),
			definitions.LuaFnRedisLLen:                 RedisLLen(ctx),
			definitions.LuaFnRedisMGet:                 RedisMGet(ctx),
			definitions.LuaFnRedisMSet:                 RedisMSet(ctx),
			definitions.LuaFnRedisKeys:                 RedisKeys(ctx),
			definitions.LuaFnRedisScan:                 RedisScan(ctx),
			definitions.LuaFnRedisPFAdd:                RedisPFAdd(ctx),
			definitions.LuaFnRedisPFCount:              RedisPFCount(ctx),
			definitions.LuaFnRedisPFMerge:              RedisPFMerge(ctx),
		})

		L.Push(mod)

		return 1
	}
}
