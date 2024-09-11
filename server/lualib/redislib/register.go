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
	"github.com/croessner/nauthilus/server/global"
	lua "github.com/yuin/gopher-lua"
)

// exportsModRedis is a map that contains the names of Lua functions and their corresponding Go function pointers.
// These functions provide the implementation for Redis operations such as getting, setting, incrementing,
// deleting, and expiring keys, as well as interacting with Redis hashes.
// The Go functions are defined in separate functions and are not included in this documentation.
// Each Go function takes a Lua state (L) as a parameter and returns the number of values pushed to the Lua stack.
// If an error occurs during the execution of a Go function, it pushes a nil value and an error message to the Lua stack
// and returns 2. Otherwise, it pushes the result(s) to the Lua stack and returns the number of values pushed (1).
// The Lua function names and their corresponding Go functions are listed below:
// - "redis_get": RedisGet
// - "redis_set": RedisSet
// - "redis_incr": RedisIncr
// - "redis_del": RedisDel
// - "redis_expire": RedisExpire
// - "redis_hget": RedisHGet
// - "redis_hset": RedisHSet
// - "redis_hdel": RedisHDel
// - "redis_hlen": RedisHLen
// - "redis_hgetall": RedisHGetAll
// - "redis_hincrby": RedisHIncrBy
// - "redis_hincrbyfloat": RedisHIncrByFloat
// - "redis_hexists": RedisHExists
// - "redis_rename": RedisRename
// - "redis_sadd": RedisSAdd
// - "redis_sismember": RedisSIsMember
// - "redis_smembers": RedisSMembers
// - "redis_srem": RedisSRem
// - "redis_scard": RedisSCard
var exportsModRedis = map[string]lua.LGFunction{
	global.LuaFnRedisGet:          RedisGet,
	global.LuaFnRedisSet:          RedisSet,
	global.LuaFnRedisIncr:         RedisIncr,
	global.LuaFnRedisDel:          RedisDel,
	global.LuaFnRedisExpire:       RedisExpire,
	global.LuaFnRedisHGet:         RedisHGet,
	global.LuaFnRedisHSet:         RedisHSet,
	global.LuaFnRedisHDel:         RedisHDel,
	global.LuaFnRedisHLen:         RedisHLen,
	global.LuaFnRedisHGetAll:      RedisHGetAll,
	global.LuaFnRedisHIncrBy:      RedisHIncrBy,
	global.LuaFnRedisHIncrByFloat: RedisHIncrByFloat,
	global.LuaFnRedisHExists:      RedisHExists,
	global.LuaFnRedisRename:       RedisRename,
	global.LuaFnRedisSAdd:         RedisSAdd,
	global.LuaFnRedisSIsMember:    RedisSIsMember,
	global.LuaFnRedisSMembers:     RedisSMembers,
	global.LuaFnRedisSRem:         RedisSRem,
	global.LuaFnRedisSCard:        RedisSCard,
}

// LoaderModRedis initializes a new module for Redis in Lua by setting the functions from the "exportsModRedis" map into
// a new lua.LTable. The module table is then pushed onto the top of the stack. Finally, it returns 1 to indicate that
// one value has been returned to Lua.
func LoaderModRedis(L *lua.LState) int {
	mod := L.SetFuncs(L.NewTable(), exportsModRedis)

	L.Push(mod)

	return 1
}
