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

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	lua "github.com/yuin/gopher-lua"
)

// LoaderModRedis returns a function that can be used to load the Redis module into a Lua state.
// It creates a new Lua table, sets the exported Redis functions, and pushes the table onto the stack.
func LoaderModRedis(ctx context.Context, cfg config.File) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnRedisRegisterRedisPool:  RegisterRedisPool,
			definitions.LuaFnRedisGetRedisConnection: GetRedisConnection,

			definitions.LuaFnRedisPing:                 RedisPingWithCtx(ctx, cfg),
			definitions.LuaFnRedisGet:                  RedisGetWithCtx(ctx, cfg),
			definitions.LuaFnRedisSet:                  RedisSetWithCtx(ctx, cfg),
			definitions.LuaFnRedisIncr:                 RedisIncrWithCtx(ctx, cfg),
			definitions.LuaFnRedisDel:                  RedisDelWithCtx(ctx, cfg),
			definitions.LuaFnRedisExpire:               RedisExpireWithCtx(ctx, cfg),
			definitions.LuaFnRedisExists:               RedisExistsWithCtx(ctx, cfg),
			definitions.LuaFnRedisHGet:                 RedisHGetWithCtx(ctx, cfg),
			definitions.LuaFnRedisHSet:                 RedisHSetWithCtx(ctx, cfg),
			definitions.LuaFnRedisHDel:                 RedisHDelWithCtx(ctx, cfg),
			definitions.LuaFnRedisHLen:                 RedisHLenWithCtx(ctx, cfg),
			definitions.LuaFnRedisHGetAll:              RedisHGetAllWithCtx(ctx, cfg),
			definitions.LuaFnRedisHMGet:                RedisHMGetWithCtx(ctx, cfg),
			definitions.LuaFnRedisHIncrBy:              RedisHIncrByWithCtx(ctx, cfg),
			definitions.LuaFnRedisHIncrByFloat:         RedisHIncrByFloatWithCtx(ctx, cfg),
			definitions.LuaFnRedisHExists:              RedisHExistsWithCtx(ctx, cfg),
			definitions.LuaFnRedisRename:               RedisRenameWithCtx(ctx, cfg),
			definitions.LuaFnRedisSAdd:                 RedisSAddWithCtx(ctx, cfg),
			definitions.LuaFnRedisSIsMember:            RedisSIsMemberWithCtx(ctx, cfg),
			definitions.LuaFnRedisSMembers:             RedisSMembersWithCtx(ctx, cfg),
			definitions.LuaFnRedisSRem:                 RedisSRemWithCtx(ctx, cfg),
			definitions.LuaFnRedisSCard:                RedisSCardWithCtx(ctx, cfg),
			definitions.LuaFnRedisRunScript:            RedisRunScriptWithCtx(ctx, cfg),
			definitions.LuaFnRedisUploadScript:         RedisUploadScriptWithCtx(ctx, cfg),
			definitions.LuaFnRedisPipeline:             RedisPipelineWithCtx(ctx, cfg),
			definitions.LuaFnRedisZAdd:                 RedisZAddWithCtx(ctx, cfg),
			definitions.LuaFnRedisZRem:                 RedisZRemWithCtx(ctx, cfg),
			definitions.LuaFnRedisZRank:                RedisZRankWithCtx(ctx, cfg),
			definitions.LuaFNRedisZRange:               RedisZRangeWithCtx(ctx, cfg),
			definitions.LuaFnRedisZRevRange:            RedisZRevRangeWithCtx(ctx, cfg),
			definitions.LuaFnRedisZRangeByScore:        RedisZRangeByScoreWithCtx(ctx, cfg),
			definitions.LuaFnRedisZRemRangeByScore:     RedisZRemRangeByScoreWithCtx(ctx, cfg),
			definitions.LuaFnRedisRedisZRemRangeByRank: RedisZRemRangeByRankWithCtx(ctx, cfg),
			definitions.LuaFnRedisZCount:               RedisZCountWithCtx(ctx, cfg),
			definitions.LuaFnRedisZScore:               RedisZScoreWithCtx(ctx, cfg),
			definitions.LuaFnRedisRedisZRevRank:        RedisZRevRankWithCtx(ctx, cfg),
			definitions.LuaFnRedisZIncrBy:              RedisZIncrByWithCtx(ctx, cfg),
			definitions.LuaFnRedisLPush:                RedisLPushWithCtx(ctx, cfg),
			definitions.LuaFnRedisRPush:                RedisRPushWithCtx(ctx, cfg),
			definitions.LuaFnRedisLPop:                 RedisLPopWithCtx(ctx, cfg),
			definitions.LuaFnRedisRPop:                 RedisRPopWithCtx(ctx, cfg),
			definitions.LuaFnRedisLRange:               RedisLRangeWithCtx(ctx, cfg),
			definitions.LuaFnRedisLLen:                 RedisLLenWithCtx(ctx, cfg),
			definitions.LuaFnRedisMGet:                 RedisMGetWithCtx(ctx, cfg),
			definitions.LuaFnRedisMSet:                 RedisMSetWithCtx(ctx, cfg),
			definitions.LuaFnRedisKeys:                 RedisKeysWithCtx(ctx, cfg),
			definitions.LuaFnRedisScan:                 RedisScanWithCtx(ctx, cfg),
			definitions.LuaFnRedisPFAdd:                RedisPFAddWithCtx(ctx, cfg),
			definitions.LuaFnRedisPFCount:              RedisPFCountWithCtx(ctx, cfg),
			definitions.LuaFnRedisPFMerge:              RedisPFMergeWithCtx(ctx, cfg),
		})

		L.Push(mod)

		return 1
	}
}
