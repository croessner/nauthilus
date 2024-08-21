package redislib

import (
	"github.com/croessner/nauthilus/server/global"
	lua "github.com/yuin/gopher-lua"
)

// SetUPRedisFunctions is a function that associates a set of Redis-related functions to a Lua table.
// Each function is linked to a string that corresponds to its name in the global Lua functions namespace.
// The provided Lua state `L` and the Lua table `table` are used to facilitate this setting up process.
// Here are the functions that this function sets up:
// - RedisGet
// - RedisSet
// - RedisIncr
// - RedisDel
// - RedisExpire
// - RedisHGet
// - RedisHSet
// - RedisHDel
// - RedisHLen
// - RedisHGetAll
// - RedisHIncrBy
func SetUPRedisFunctions(table *lua.LTable, L *lua.LState) {
	table.RawSetString(global.LuaFnRedisGet, L.NewFunction(RedisGet))
	table.RawSetString(global.LuaFnRedisSet, L.NewFunction(RedisSet))
	table.RawSetString(global.LuaFnRedisIncr, L.NewFunction(RedisIncr))
	table.RawSetString(global.LuaFnRedisDel, L.NewFunction(RedisDel))
	table.RawSetString(global.LuaFnRedisExpire, L.NewFunction(RedisExpire))
	table.RawSetString(global.LuaFnRedisHGet, L.NewFunction(RedisHGet))
	table.RawSetString(global.LuaFnRedisHSet, L.NewFunction(RedisHSet))
	table.RawSetString(global.LuaFnRedisHDel, L.NewFunction(RedisHDel))
	table.RawSetString(global.LuaFnRedisHLen, L.NewFunction(RedisHLen))
	table.RawSetString(global.LuaFnRedisHGetAll, L.NewFunction(RedisHGetAll))
	table.RawSetString(global.LuaFnRedisHIncrBy, L.NewFunction(RedisHIncrBy))
	table.RawSetString(global.LuaFnRedisHIncrByFloat, L.NewFunction(RedisHIncrByFloat))
	table.RawSetString(global.LuaFnRedisHExists, L.NewFunction(RedisHExists))
	table.RawSetString(global.LuaFnRedisRename, L.NewFunction(RedisRename))
	table.RawSetString(global.LuaFnRedisSAdd, L.NewFunction(RedisSAdd))
	table.RawSetString(global.LuaFnRedisSIsMember, L.NewFunction(RedisSIsMember))
	table.RawSetString(global.LuaFnRedisSMembers, L.NewFunction(RedisSMembers))
	table.RawSetString(global.LuaFnRedisSRem, L.NewFunction(RedisSRem))
	table.RawSetString(global.LuaFnRedisSCard, L.NewFunction(RedisSCard))
}
