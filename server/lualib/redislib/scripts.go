package redislib

import (
	"context"
	"fmt"
	"sync"

	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/redis/go-redis/v9"
	"github.com/yuin/gopher-lua"
)

// Uploads is a concurrency-safe type for managing script uploads, utilizing a map to store key-value pairs securely.
type Uploads struct {
	// scripts stores key-value pairs where the key is the name of the upload script, and the value is its associated SHA-1 hash.
	scripts map[string]string

	// mu provides mutual exclusion to ensure that concurrent access to the scripts map is synchronized.
	mu sync.Mutex
}

// Set stores the provided SHA-1 hash associated with the given upload script name in a concurrency-safe manner.
func (u *Uploads) Set(uploadScriptName string, sha1 string) {
	u.mu.Lock()

	defer u.mu.Unlock()

	u.scripts[uploadScriptName] = sha1
}

// Get retrieves the SHA-1 hash associated with the given upload script name in a concurrency-safe manner.
func (u *Uploads) Get(uploadScriptName string) string {
	u.mu.Lock()

	defer u.mu.Unlock()

	if sha1, okay := u.scripts[uploadScriptName]; okay {
		return sha1
	}

	return ""
}

// uploads is an instance of the Uploads struct that manages script uploads with their associated SHA-1 hashes.
var uploads = &Uploads{
	scripts: make(map[string]string),
}

// evaluateRedisScript executes a given Lua script on the Redis server with specified keys and arguments.
func evaluateRedisScript(ctx context.Context, client redis.UniversalClient, script string, uploadScriptName string, keys []string, args ...any) (any, error) {
	var (
		err    error
		result any
	)

	evalArgs := make([]any, len(args))

	for i, arg := range args {
		evalArgs[len(keys)+i] = arg
	}

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	if uploadScriptName != "" {
		script = uploads.Get(uploadScriptName)
		if script == "" {
			return fmt.Errorf("could not find script with name %s", uploadScriptName), nil
		}

		result, err = client.EvalSha(ctx, script, keys, evalArgs...).Result()
	} else {
		result, err = client.Eval(ctx, script, keys, evalArgs...).Result()
	}

	if err != nil {
		return nil, err
	}

	return result, nil
}

// uploadRedisScript uploads a Lua script to Redis and returns its SHA1 hash or an error if the upload fails.
func uploadRedisScript(ctx context.Context, client redis.UniversalClient, script string) (any, error) {
	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	sha1, err := client.ScriptLoad(ctx, script).Result()
	if err != nil {
		return nil, err
	}

	return sha1, nil
}

// RedisRunScript executes a Redis script with the provided keys and arguments, returning the result or an error as Lua values.
// It expects three arguments: the script string, a table of keys, and a table of arguments. It returns two values: an error message (or nil) and the script result (or nil).
func RedisRunScript(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		var (
			keyList  []string
			argsList []any
		)

		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetWriteHandle())
		script := L.CheckString(2)
		uploadScriptName := L.CheckString(3)
		keys := L.CheckTable(4)
		args := L.CheckTable(5)

		keys.ForEach(func(k, v lua.LValue) {
			keyList = append(keyList, v.String())
		})

		args.ForEach(func(k, v lua.LValue) {
			argsList = append(argsList, v.String())
		})

		result, err := evaluateRedisScript(ctx, client, script, uploadScriptName, keyList, argsList...)
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))

			return 2
		}

		L.Push(convert.GoToLuaValue(L, result))
		L.Push(lua.LNil)

		return 2
	}
}

// RedisUploadScript uploads a Lua script to Redis, returns the SHA1 hash of the script or an error message on failure.
func RedisUploadScript(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetWriteHandle())
		script := L.CheckString(2)
		uploadScriptName := L.CheckString(3)

		sha1, err := uploadRedisScript(ctx, client, script)
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))

			return 2
		}

		if scriptSha1, okay := sha1.(string); okay {
			uploads.Set(uploadScriptName, scriptSha1)

			L.Push(lua.LString(scriptSha1))
			L.Push(lua.LNil)

			return 2
		}

		L.Push(lua.LNil)
		L.Push(lua.LString(fmt.Sprintf("Could not convert script SHA1 to string: %v", sha1)))

		return 2
	}
}
