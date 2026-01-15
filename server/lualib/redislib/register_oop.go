//go:build redislib_oop

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
		rm := NewRedisManager(ctx, cfg, client)

		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnRedisRegisterRedisPool:  RegisterRedisPool,
			definitions.LuaFnRedisGetRedisConnection: GetRedisConnection,

			definitions.LuaFnRedisPing:   rm.RedisPing,
			definitions.LuaFnRedisGet:    rm.RedisGet,
			definitions.LuaFnRedisSet:    rm.RedisSet,
			definitions.LuaFnRedisIncr:   rm.RedisIncr,
			definitions.LuaFnRedisDel:    rm.RedisDel,
			definitions.LuaFnRedisRename: rm.RedisRename,
			definitions.LuaFnRedisExpire: rm.RedisExpire,
			definitions.LuaFnRedisExists: rm.RedisExists,

			definitions.LuaFnRedisRunScript:    rm.RedisRunScript,
			definitions.LuaFnRedisUploadScript: rm.RedisUploadScript,
			definitions.LuaFnRedisPipeline:     rm.RedisPipeline,

			definitions.LuaFnRedisMGet: rm.RedisMGet,
			definitions.LuaFnRedisMSet: rm.RedisMSet,
			definitions.LuaFnRedisKeys: rm.RedisKeys,
			definitions.LuaFnRedisScan: rm.RedisScan,

			definitions.LuaFnRedisHGet:         rm.RedisHGet,
			definitions.LuaFnRedisHSet:         rm.RedisHSet,
			definitions.LuaFnRedisHDel:         rm.RedisHDel,
			definitions.LuaFnRedisHLen:         rm.RedisHLen,
			definitions.LuaFnRedisHGetAll:      rm.RedisHGetAll,
			definitions.LuaFnRedisHMGet:        rm.RedisHMGet,
			definitions.LuaFnRedisHIncrBy:      rm.RedisHIncrBy,
			definitions.LuaFnRedisHIncrByFloat: rm.RedisHIncrByFloat,
			definitions.LuaFnRedisHExists:      rm.RedisHExists,

			definitions.LuaFnRedisZAdd:                 rm.RedisZAdd,
			definitions.LuaFnRedisZRem:                 rm.RedisZRem,
			definitions.LuaFnRedisZRank:                rm.RedisZRank,
			definitions.LuaFNRedisZRange:               rm.RedisZRange,
			definitions.LuaFnRedisZRevRange:            rm.RedisZRevRange,
			definitions.LuaFnRedisZRangeByScore:        rm.RedisZRangeByScore,
			definitions.LuaFnRedisZRemRangeByScore:     rm.RedisZRemRangeByScore,
			definitions.LuaFnRedisRedisZRemRangeByRank: rm.RedisZRemRangeByRank,
			definitions.LuaFnRedisZCount:               rm.RedisZCount,
			definitions.LuaFnRedisZScore:               rm.RedisZScore,
			definitions.LuaFnRedisRedisZRevRank:        rm.RedisZRevRank,
			definitions.LuaFnRedisZIncrBy:              rm.RedisZIncrBy,

			definitions.LuaFnRedisLPush:  rm.RedisLPush,
			definitions.LuaFnRedisRPush:  rm.RedisRPush,
			definitions.LuaFnRedisLPop:   rm.RedisLPop,
			definitions.LuaFnRedisRPop:   rm.RedisRPop,
			definitions.LuaFnRedisLRange: rm.RedisLRange,
			definitions.LuaFnRedisLLen:   rm.RedisLLen,

			definitions.LuaFnRedisPFAdd:   rm.RedisPFAdd,
			definitions.LuaFnRedisPFCount: rm.RedisPFCount,
			definitions.LuaFnRedisPFMerge: rm.RedisPFMerge,

			definitions.LuaFnRedisSAdd:      rm.RedisSAdd,
			definitions.LuaFnRedisSIsMember: rm.RedisSIsMember,
			definitions.LuaFnRedisSMembers:  rm.RedisSMembers,
			definitions.LuaFnRedisSRem:      rm.RedisSRem,
			definitions.LuaFnRedisSCard:     rm.RedisSCard,
		})

		L.Push(mod)

		return 1
	}
}
