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
	"github.com/croessner/nauthilus/server/rediscli"
	lua "github.com/yuin/gopher-lua"
)

// LoaderModRedis returns a function that can be used to load the Redis module into a Lua state.
// It creates a new Lua table, sets the exported Redis functions, and pushes the table onto the stack.
func LoaderModRedis(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnRedisRegisterRedisPool:  RegisterRedisPool,
			definitions.LuaFnRedisGetRedisConnection: GetRedisConnection,

			definitions.LuaFnRedisPing:                 RedisPingWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisGet:                  RedisGetWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisSet:                  RedisSetWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisIncr:                 RedisIncrWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisDel:                  RedisDelWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisExpire:               RedisExpireWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisExists:               RedisExistsWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisHGet:                 RedisHGetWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisHSet:                 RedisHSetWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisHDel:                 RedisHDelWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisHLen:                 RedisHLenWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisHGetAll:              RedisHGetAllWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisHMGet:                RedisHMGetWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisHIncrBy:              RedisHIncrByWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisHIncrByFloat:         RedisHIncrByFloatWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisHExists:              RedisHExistsWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisRename:               RedisRenameWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisSAdd:                 RedisSAddWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisSIsMember:            RedisSIsMemberWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisSMembers:             RedisSMembersWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisSRem:                 RedisSRemWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisSCard:                RedisSCardWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisRunScript:            RedisRunScriptWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisUploadScript:         RedisUploadScriptWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisPipeline:             RedisPipelineWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisZAdd:                 RedisZAddWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisZRem:                 RedisZRemWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisZRank:                RedisZRankWithCtx(ctx, cfg, client),
			definitions.LuaFNRedisZRange:               RedisZRangeWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisZRevRange:            RedisZRevRangeWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisZRangeByScore:        RedisZRangeByScoreWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisZRemRangeByScore:     RedisZRemRangeByScoreWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisRedisZRemRangeByRank: RedisZRemRangeByRankWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisZCount:               RedisZCountWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisZScore:               RedisZScoreWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisRedisZRevRank:        RedisZRevRankWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisZIncrBy:              RedisZIncrByWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisLPush:                RedisLPushWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisRPush:                RedisRPushWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisLPop:                 RedisLPopWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisRPop:                 RedisRPopWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisLRange:               RedisLRangeWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisLLen:                 RedisLLenWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisMGet:                 RedisMGetWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisMSet:                 RedisMSetWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisKeys:                 RedisKeysWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisScan:                 RedisScanWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisPFAdd:                RedisPFAddWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisPFCount:              RedisPFCountWithCtx(ctx, cfg, client),
			definitions.LuaFnRedisPFMerge:              RedisPFMergeWithCtx(ctx, cfg, client),
		})

		L.Push(mod)

		return 1
	}
}
