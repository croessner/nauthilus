package redislib

import (
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/yuin/gopher-lua"
)

// evaluateRedisScript executes a given Lua script on the Redis server with specified keys and arguments.
func evaluateRedisScript(scriptOrSha1 string, useSha1 bool, keys []string, args ...any) (any, error) {
	var (
		err    error
		result any
	)

	evalArgs := make([]any, len(args))

	for i, arg := range args {
		evalArgs[len(keys)+i] = arg
	}

	if useSha1 {
		result, err = rediscli.WriteHandle.EvalSha(ctx, scriptOrSha1, keys, evalArgs...).Result()
	} else {
		result, err = rediscli.WriteHandle.Eval(ctx, scriptOrSha1, keys, evalArgs...).Result()
	}

	if err != nil {
		return nil, err
	}

	return result, nil
}

// uploadRedisScript uploads a Lua script to Redis and returns its SHA1 hash or an error if the upload fails.
func uploadRedisScript(script string) (any, error) {
	sha1, err := rediscli.WriteHandle.ScriptLoad(ctx, script).Result()
	if err != nil {
		return nil, err
	}

	return sha1, nil
}

// RedisRunScript executes a Redis script with the provided keys and arguments, returning the result or an error as Lua values.
// It expects three arguments: the script string, a table of keys, and a table of arguments. It returns two values: an error message (or nil) and the script result (or nil).
func RedisRunScript(L *lua.LState) int {
	var (
		keyList  []string
		argsList []any
	)

	scriptOrSha1 := L.CheckString(1)
	useSha1 := L.CheckBool(2)
	keys := L.CheckTable(3)
	args := L.CheckTable(4)

	keys.ForEach(func(k, v lua.LValue) {
		keyList = append(keyList, v.String())
	})

	args.ForEach(func(k, v lua.LValue) {
		argsList = append(argsList, v.String())
	})

	result, err := evaluateRedisScript(scriptOrSha1, useSha1, keyList, argsList...)
	if err != nil {
		L.Push(lua.LString(err.Error()))
		L.Push(lua.LNil)

		return 2
	}

	L.Push(lua.LNil)
	L.Push(convert.GoToLuaValue(L, result))

	return 2
}

func RedisUploadScript(L *lua.LState) int {
	script := L.CheckString(1)

	sha1, err := uploadRedisScript(script)
	if err != nil {
		L.Push(lua.LString(err.Error()))
		L.Push(lua.LNil)

		return 2
	}

	L.Push(lua.LNil)
	L.Push(convert.GoToLuaValue(L, sha1))

	return 2
}
