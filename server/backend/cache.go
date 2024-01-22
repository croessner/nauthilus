package backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	"github.com/go-redis/redis/v8"
)

var (
	RedisHandle        redis.UniversalClient //nolint:gochecknoglobals // System wide redis pool
	RedisHandleReplica redis.UniversalClient //nolint:gochecknoglobals // System wide redis pool
)

// BruteForceBucketCache is a Redis cache. It is a union member of RedisCache.
type BruteForceBucketCache uint

// PasswordHistory is a map of hashed passwords with their failure counter.
type PasswordHistory map[string]uint

// PositivePasswordCache is a container that stores all kinds of user information upon a successful authentication. It
// is used for Redis as a short cache object and as proxy structure between Nauthilus instances. The cache object is not
// refreshed upon continuous requests. If the Redis TTL has expired, the object is removed from cache to force a refresh
// of the user data from underlying databases.
type PositivePasswordCache struct {
	Backend           global.Backend `redis:"passdb_backend"`
	Password          string         `redis:"password"`
	AccountField      *string        `redis:"account_field"`
	TOTPSecretField   *string        `redis:"totp_secret_field"`
	UniqueUserIDField *string        `redis:"webauth_userid_field"`
	DisplayNameField  *string        `redis:"display_name_field"`
	Attributes        DatabaseResult `redis:"attributes"`
}

// RedisCache is a union that is used for LoadCacheFromRedis and SaveUserDataToRedis Redis routines. These routines are
// generics.
type RedisCache interface {
	PositivePasswordCache | BruteForceBucketCache
}

// LookupUserAccountFromRedis returns the user account value from the user Redis hash.
func LookupUserAccountFromRedis(username string) (accountName string, err error) {
	key := config.EnvConfig.RedisPrefix + global.RedisUserHashKey

	accountName, err = RedisHandleReplica.HGet(RedisHandleReplica.Context(), key, username).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return
		}

		err = nil
	}

	return
}

// LoadCacheFromRedis is a generic routine to load a cache object from Redis. The type is a RedisCache, which is a
// union.
func LoadCacheFromRedis[T RedisCache](key string, cache **T) (err error) {
	var redisValue []byte

	if redisValue, err = RedisHandleReplica.Get(RedisHandleReplica.Context(), key).Bytes(); err != nil {
		if errors.Is(err, redis.Nil) {
			return nil
		}

		level.Error(logging.DefaultErrLogger).Log(global.LogKeyError, err)

		return
	}

	*cache = new(T)

	if err = json.Unmarshal(redisValue, *cache); err != nil {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyError, err)

		return
	}

	util.DebugModule(
		global.DbgCache,
		global.LogKeyMsg, "Load password history from redis", "type", fmt.Sprintf("%T", **cache))

	return nil
}

// SaveUserDataToRedis is a generic routine to store a cache object on Redis. The type is a RedisCache, which is a
// union.
func SaveUserDataToRedis[T RedisCache](guid string, key string, ttl uint, cache *T) {
	var result string

	util.DebugModule(
		global.DbgCache,
		global.LogKeyGUID, guid,
		global.LogKeyMsg, "Save password history to redis", "type", fmt.Sprintf("%T", *cache),
	)

	redisValue, err := json.Marshal(cache)
	if err != nil {
		level.Error(logging.DefaultErrLogger).Log(
			global.LogKeyGUID, guid,
			global.LogKeyError, err,
		)

		return
	}

	//nolint:lll // Ignore
	if result, err = RedisHandle.Set(RedisHandle.Context(), key, redisValue, time.Duration(ttl)*time.Second).Result(); err != nil {
		level.Error(logging.DefaultErrLogger).Log(
			global.LogKeyGUID, guid,
			global.LogKeyError, err,
		)
	}

	util.DebugModule(
		global.DbgCache,
		global.LogKeyGUID, guid,
		"redis", result)
}

func GetCacheNames(requestedProtocol string, backends global.CacheNameBackend) (cacheNames config.StringSet) {
	var (
		cacheName    string
		protocolLDAP *config.LDAPSearchProtocol
		protocolSQL  *config.SQLSearchProtocol
		protocolLua  *config.LuaSearchProtocol
	)

	cacheNames = config.NewStringSet()

	if backends == global.CacheAll || backends == global.CacheLDAP {
		if protocolLDAP, _ = config.LoadableConfig.GetLDAPSearchProtocol(requestedProtocol); protocolLDAP != nil {
			if cacheName, _ = protocolLDAP.GetCacheName(); cacheName != "" {
				cacheNames.Set(cacheName)
			}
		}
	}

	if backends == global.CacheAll || backends == global.CacheSQL {
		if protocolSQL, _ = config.LoadableConfig.GetSQLSearchProtocol(requestedProtocol); protocolSQL != nil {
			if cacheName, _ = protocolSQL.GetCacheName(); cacheName != "" {
				cacheNames.Set(cacheName)
			}
		}
	}

	if backends == global.CacheAll || backends == global.CacheLua {
		if protocolLua, _ = config.LoadableConfig.GetLuaSearchProtocol(requestedProtocol); protocolLua != nil {
			if cacheName, _ = protocolLua.GetCacheName(); cacheName != "" {
				cacheNames.Set(cacheName)
			}
		}
	}

	if len(cacheNames) == 0 {
		cacheNames.Set("__default__")
	}

	return
}

func GetWebAuthnFromRedis(uniqueUserId string) (user *User, err error) {
	var redisValue []byte

	key := "as_webauthn:user:" + uniqueUserId

	if redisValue, err = RedisHandleReplica.Get(RedisHandleReplica.Context(), key).Bytes(); err != nil {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyError, err)

		return nil, err
	}

	user = &User{}

	if err = json.Unmarshal(redisValue, user); err != nil {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyError, err)

		return nil, err
	}

	return
}

func SaveWebAuthnToRedis(user *User, ttl uint) error {
	var result string

	redisValue, err := json.Marshal(user)
	if err != nil {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyError, err)

		return err
	}

	key := "as_webauthn:user:" + user.Id

	//nolint:lll // Ignore
	if result, err = RedisHandle.Set(RedisHandle.Context(), key, redisValue, time.Duration(ttl)*time.Second).Result(); err != nil {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyError, err)
	}

	util.DebugModule(global.DbgCache, "redis", result)

	return err
}
