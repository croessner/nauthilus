package redislib

import (
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/yuin/gopher-lua"
)

// executeRedisScript executes a given Lua script on the Redis server with specified keys and arguments.
func executeRedisScript(script string, keys []string, args ...any) (any, error) {
	evalArgs := make([]any, len(args))

	for i, arg := range args {
		evalArgs[len(keys)+i] = arg
	}

	result, err := rediscli.WriteHandle.Eval(ctx, script, keys, evalArgs...).Result()
	if err != nil {
		return nil, err
	}

	return result, nil
}

// RedisRunScript executes a Redis script with the provided keys and arguments, returning the result or an error as Lua values.
// It expects three arguments: the script string, a table of keys, and a table of arguments. It returns two values: an error message (or nil) and the script result (or nil).
func RedisRunScript(L *lua.LState) int {
	var (
		keyList  []string
		argsList []any
	)

	script := L.CheckString(1)
	keys := L.CheckTable(2)
	args := L.CheckTable(3)

	keys.ForEach(func(k, v lua.LValue) {
		keyList = append(keyList, v.String())
	})

	args.ForEach(func(k, v lua.LValue) {
		argsList = append(argsList, v.String())
	})

	result, err := executeRedisScript(script, keyList, argsList...)
	if err != nil {
		L.Push(lua.LString(err.Error()))
		L.Push(lua.LNil)

		return 2
	}

	lResult := convert.GoToLuaValue(L, result)

	L.Push(lua.LNil)
	L.Push(lResult)

	return 2
}
