package luatest

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/redislib"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

type redisRuntime struct {
	mini   *miniredis.Miniredis
	client *redis.Client
}

// newRedisRuntime starts an isolated in-memory Redis instance and seeds it from fixture data.
func newRedisRuntime(mockData *RedisMock) (*redisRuntime, error) {
	mini, err := miniredis.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to start miniredis: %w", err)
	}

	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	runtime := &redisRuntime{mini: mini, client: client}

	if err = runtime.seed(mockData); err != nil {
		runtime.Close()

		return nil, err
	}

	return runtime, nil
}

// Close releases all Redis resources used by the test runtime.
func (rt *redisRuntime) Close() {
	if rt == nil {
		return
	}

	if rt.client != nil {
		_ = rt.client.Close()
	}

	if rt.mini != nil {
		rt.mini.Close()
	}
}

// Loader returns a Lua module loader for the real Redis library, wrapped with expected-calls validation.
func (rt *redisRuntime) Loader(ctx context.Context, cfg config.File, mockData *RedisMock) lua.LGFunction {
	baseLoader := redislib.LoaderModRedis(ctx, cfg, rediscli.NewTestClient(rt.client))

	return func(L *lua.LState) int {
		count := baseLoader(L)
		if count != 1 {
			return count
		}

		mod, ok := L.Get(-1).(*lua.LTable)
		if !ok || mockData == nil {
			return count
		}

		if reqEnv, reqOK := L.GetGlobal("__NAUTH_REQ_ENV").(*lua.LTable); reqOK {
			lualib.BindRequestValuesToEnv(L, reqEnv, mod)
		}

		wrapRedisModuleFunctions(L, mod, mockData)

		return count
	}
}

// seed applies redis fixture seed data to the in-memory Redis instance.
func (rt *redisRuntime) seed(mockData *RedisMock) error {
	if rt == nil || rt.client == nil || mockData == nil {
		return nil
	}

	ctx := context.Background()

	if mockData.InitialData != nil {
		if err := seedInitialRedisData(ctx, rt.client, mockData.InitialData); err != nil {
			return err
		}
	}

	if len(mockData.Responses) > 0 {
		if err := seedLegacyRedisResponses(ctx, rt.client, mockData.Responses); err != nil {
			return err
		}
	}

	return nil
}

// seedInitialRedisData writes typed Redis seed structures into miniredis.
func seedInitialRedisData(ctx context.Context, client *redis.Client, initialData *RedisInitialData) error {
	if initialData == nil {
		return nil
	}

	for key, value := range initialData.Strings {
		if err := client.Set(ctx, key, value, 0).Err(); err != nil {
			return fmt.Errorf("failed to seed redis string key %q: %w", key, err)
		}
	}

	for key, fields := range initialData.Hashes {
		values := make(map[string]any, len(fields))
		for field, value := range fields {
			values[field] = value
		}

		if len(values) == 0 {
			continue
		}

		if err := client.HSet(ctx, key, values).Err(); err != nil {
			return fmt.Errorf("failed to seed redis hash key %q: %w", key, err)
		}
	}

	for key, members := range initialData.Sets {
		if len(members) == 0 {
			continue
		}

		values := make([]any, 0, len(members))
		for _, member := range members {
			values = append(values, member)
		}

		if err := client.SAdd(ctx, key, values...).Err(); err != nil {
			return fmt.Errorf("failed to seed redis set key %q: %w", key, err)
		}
	}

	for key, entries := range initialData.Lists {
		if len(entries) == 0 {
			continue
		}

		values := make([]any, 0, len(entries))
		for _, entry := range entries {
			values = append(values, entry)
		}

		if err := client.RPush(ctx, key, values...).Err(); err != nil {
			return fmt.Errorf("failed to seed redis list key %q: %w", key, err)
		}
	}

	for key, members := range initialData.ZSets {
		if len(members) == 0 {
			continue
		}

		values := make([]redis.Z, 0, len(members))
		for _, member := range members {
			values = append(values, redis.Z{Member: member.Member, Score: member.Score})
		}

		if err := client.ZAdd(ctx, key, values...).Err(); err != nil {
			return fmt.Errorf("failed to seed redis sorted set key %q: %w", key, err)
		}
	}

	for key, elements := range initialData.HyperLogLogs {
		if len(elements) == 0 {
			continue
		}

		values := make([]any, 0, len(elements))
		for _, element := range elements {
			values = append(values, element)
		}

		if err := client.PFAdd(ctx, key, values...).Err(); err != nil {
			return fmt.Errorf("failed to seed redis hyperloglog key %q: %w", key, err)
		}
	}

	for key, seconds := range initialData.TTLSeconds {
		if err := client.Expire(ctx, key, secondsAsDuration(seconds)).Err(); err != nil {
			return fmt.Errorf("failed to set redis ttl for key %q: %w", key, err)
		}
	}

	return nil
}

// seedLegacyRedisResponses preserves compatibility for old fixtures using the responses map.
func seedLegacyRedisResponses(ctx context.Context, client *redis.Client, responses map[string]any) error {
	for key, value := range responses {
		switch typedValue := value.(type) {
		case map[string]any:
			if len(typedValue) == 0 {
				continue
			}

			hash := make(map[string]any, len(typedValue))
			for hashKey, hashValue := range typedValue {
				hash[hashKey] = fmt.Sprint(hashValue)
			}

			if err := client.HSet(ctx, key, hash).Err(); err != nil {
				return fmt.Errorf("failed to seed legacy redis hash key %q: %w", key, err)
			}
		default:
			if err := client.Set(ctx, key, fmt.Sprint(value), 0).Err(); err != nil {
				return fmt.Errorf("failed to seed legacy redis string key %q: %w", key, err)
			}
		}
	}

	return nil
}

// wrapRedisModuleFunctions decorates each Redis Lua function to track ordered expected_calls.
func wrapRedisModuleFunctions(L *lua.LState, mod *lua.LTable, mockData *RedisMock) {
	mod.ForEach(func(key, value lua.LValue) {
		methodName := key.String()
		originalFn, ok := value.(*lua.LFunction)
		if !ok {
			return
		}

		wrappedOriginal := originalFn
		wrappedMethodName := methodName

		mod.RawSet(key, L.NewFunction(func(L *lua.LState) int {
			if err := mockData.RecordCall(wrappedMethodName, joinLuaArgs(L)); err != nil {
				L.RaiseError("%s", err.Error())
				return 0
			}

			if wrappedOriginal.IsG && wrappedOriginal.GFunction != nil {
				return wrappedOriginal.GFunction(L)
			}

			top := L.GetTop()
			args := make([]lua.LValue, 0, top)
			for i := 1; i <= top; i++ {
				args = append(args, L.Get(i))
			}

			if err := L.CallByParam(lua.P{Fn: wrappedOriginal, NRet: lua.MultRet, Protect: true}, args...); err != nil {
				L.RaiseError("%s", err.Error())
				return 0
			}

			return L.GetTop() - top
		}))
	})
}

// joinLuaArgs builds a compact argument string used by expected_calls arg_contains matching.
func joinLuaArgs(L *lua.LState) string {
	parts := make([]string, 0, L.GetTop())
	for i := 1; i <= L.GetTop(); i++ {
		parts = append(parts, L.Get(i).String())
	}

	return strings.Join(parts, ",")
}

// secondsAsDuration converts fixture TTL seconds into a non-negative Go duration.
func secondsAsDuration(seconds int64) time.Duration {
	if seconds < 0 {
		return 0
	}

	return time.Duration(seconds) * time.Second
}

// resolveLuaTestConfig returns the loaded runtime config or a minimal fallback used in tests.
func resolveLuaTestConfig() config.File {
	if config.IsFileLoaded() {
		return config.GetFile()
	}

	return &config.FileSettings{Server: &config.ServerSection{}}
}
