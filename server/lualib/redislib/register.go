package redislib

import (
	"github.com/croessner/nauthilus/server/global"
	lua "github.com/yuin/gopher-lua"
)

// SetupRedisFunctions sets up the Redis functions in the Lua table.
// It takes a Lua table and a Lua state as arguments.
// It assigns the Redis functions to the corresponding keys in the Lua table.
// Each Redis function is implemented as a Lua function that interacts with the Redis server.
// The Redis functions include:
//   - RedisGet: Retrieves the value associated with a key from the Redis server.
//   - RedisSet: Sets the value of a key in the Redis server.
//   - RedisIncr: Increments the value associated with a key in the Redis server.
//   - RedisDel: Deletes the value associated with a key from the Redis server.
//   - RedisExpire: Sets a timeout on a key in the Redis server.
//   - RedisHGet: Retrieves the value associated with a field in a Hash stored at a key in the Redis server.
//   - RedisHSet: Sets the value of a field in a Hash stored at a key in the Redis server.
//   - RedisHDel: Deletes a field from a Hash stored at a key in the Redis server.
//   - RedisHLen: Returns the number of fields in a Hash stored at a key in the Redis server.
//   - RedisHGetAll: Returns all the fields and values in a Hash stored at a key in the Redis server.
//   - RedisHIncrBy: Increments the value of a field in a Hash stored at a key in the Redis server by a specified amount.
//   - RedisHIncrByFloat: Increments the value of a field in a Hash stored at a key in the Redis server by a specified floating-point number.
//   - RedisHExists: Checks if a field exists in a Hash stored at a key in the Redis server.
//   - RedisRename: Renames a key in the Redis server.
//   - RedisSAdd: Adds one or more members to a set stored at a key in the Redis server.
//   - RedisSIsMember: Checks if a member is a member of a set stored at a key in the Redis server.
//   - RedisSMembers: Returns all the members of a set stored at a key in the Redis server.
//   - RedisSRem: Removes one or more members from a set stored at a key in the Redis server.
//   - RedisSCard: Returns the number of members in a set stored at a key in the Redis server.
func SetupRedisFunctions(table *lua.LTable, L *lua.LState) {
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
