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

			definitions.LuaFnRedisPing:                 RedisPingWithCtx(ctx),
			definitions.LuaFnRedisGet:                  RedisGetWithCtx(ctx),
			definitions.LuaFnRedisSet:                  RedisSetWithCtx(ctx),
			definitions.LuaFnRedisIncr:                 RedisIncrWithCtx(ctx),
			definitions.LuaFnRedisDel:                  RedisDelWithCtx(ctx),
			definitions.LuaFnRedisExpire:               RedisExpireWithCtx(ctx),
			definitions.LuaFnRedisExists:               RedisExistsWithCtx(ctx),
			definitions.LuaFnRedisHGet:                 RedisHGetWithCtx(ctx),
			definitions.LuaFnRedisHSet:                 RedisHSetWithCtx(ctx),
			definitions.LuaFnRedisHDel:                 RedisHDelWithCtx(ctx),
			definitions.LuaFnRedisHLen:                 RedisHLenWithCtx(ctx),
			definitions.LuaFnRedisHGetAll:              RedisHGetAllWithCtx(ctx),
			definitions.LuaFnRedisHMGet:                RedisHMGetWithCtx(ctx),
			definitions.LuaFnRedisHIncrBy:              RedisHIncrByWithCtx(ctx),
			definitions.LuaFnRedisHIncrByFloat:         RedisHIncrByFloatWithCtx(ctx),
			definitions.LuaFnRedisHExists:              RedisHExistsWithCtx(ctx),
			definitions.LuaFnRedisRename:               RedisRenameWithCtx(ctx),
			definitions.LuaFnRedisSAdd:                 RedisSAddWithCtx(ctx),
			definitions.LuaFnRedisSIsMember:            RedisSIsMemberWithCtx(ctx),
			definitions.LuaFnRedisSMembers:             RedisSMembersWithCtx(ctx),
			definitions.LuaFnRedisSRem:                 RedisSRemWithCtx(ctx),
			definitions.LuaFnRedisSCard:                RedisSCardWithCtx(ctx),
			definitions.LuaFnRedisRunScript:            RedisRunScriptWithCtx(ctx),
			definitions.LuaFnRedisUploadScript:         RedisUploadScriptWithCtx(ctx),
			definitions.LuaFnRedisPipeline:             RedisPipelineWithCtx(ctx),
			definitions.LuaFnRedisZAdd:                 RedisZAddWithCtx(ctx),
			definitions.LuaFnRedisZRem:                 RedisZRemWithCtx(ctx),
			definitions.LuaFnRedisZRank:                RedisZRankWithCtx(ctx),
			definitions.LuaFNRedisZRange:               RedisZRangeWithCtx(ctx),
			definitions.LuaFnRedisZRevRange:            RedisZRevRangeWithCtx(ctx),
			definitions.LuaFnRedisZRangeByScore:        RedisZRangeByScoreWithCtx(ctx),
			definitions.LuaFnRedisZRemRangeByScore:     RedisZRemRangeByScoreWithCtx(ctx),
			definitions.LuaFnRedisRedisZRemRangeByRank: RedisZRemRangeByRankWithCtx(ctx),
			definitions.LuaFnRedisZCount:               RedisZCountWithCtx(ctx),
			definitions.LuaFnRedisZScore:               RedisZScoreWithCtx(ctx),
			definitions.LuaFnRedisRedisZRevRank:        RedisZRevRankWithCtx(ctx),
			definitions.LuaFnRedisZIncrBy:              RedisZIncrByWithCtx(ctx),
			definitions.LuaFnRedisLPush:                RedisLPushWithCtx(ctx),
			definitions.LuaFnRedisRPush:                RedisRPushWithCtx(ctx),
			definitions.LuaFnRedisLPop:                 RedisLPopWithCtx(ctx),
			definitions.LuaFnRedisRPop:                 RedisRPopWithCtx(ctx),
			definitions.LuaFnRedisLRange:               RedisLRangeWithCtx(ctx),
			definitions.LuaFnRedisLLen:                 RedisLLenWithCtx(ctx),
			definitions.LuaFnRedisMGet:                 RedisMGetWithCtx(ctx),
			definitions.LuaFnRedisMSet:                 RedisMSetWithCtx(ctx),
			definitions.LuaFnRedisKeys:                 RedisKeysWithCtx(ctx),
			definitions.LuaFnRedisScan:                 RedisScanWithCtx(ctx),
			definitions.LuaFnRedisPFAdd:                RedisPFAddWithCtx(ctx),
			definitions.LuaFnRedisPFCount:              RedisPFCountWithCtx(ctx),
			definitions.LuaFnRedisPFMerge:              RedisPFMergeWithCtx(ctx),
		})

		L.Push(mod)

		return 1
	}
}
