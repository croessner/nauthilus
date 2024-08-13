package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	"github.com/redis/go-redis/v9"
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
	key := config.LoadableConfig.Server.Redis.Prefix + global.RedisUserHashKey

	accountName, err = rediscli.ReadHandle.HGet(context.Background(), key, username).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return
		}

		err = nil
	}

	return
}

// LoadCacheFromRedis loads the cache value from Redis and unmarshals it into the provided cache pointer.
// If the key does not exist in Redis, it returns isRedisErr=true and err=nil.
// If there is an error retrieving the value from Redis, it returns isRedisErr=true and err.
// Otherwise, it unmarshals the value into the cache pointer and returns isRedisErr=false and err=nil.
// It also logs any error messages using the Logger.
func LoadCacheFromRedis[T RedisCache](key string, cache **T) (isRedisErr bool, err error) {
	var redisValue []byte

	if redisValue, err = rediscli.ReadHandle.Get(context.Background(), key).Bytes(); err != nil {
		if errors.Is(err, redis.Nil) {
			return true, nil
		}

		level.Error(log.Logger).Log(global.LogKeyError, err)

		return true, err
	}

	*cache = new(T)

	if err = json.Unmarshal(redisValue, *cache); err != nil {
		level.Error(log.Logger).Log(global.LogKeyError, err)

		return
	}

	util.DebugModule(
		global.DbgCache,
		global.LogKeyMsg, "Load password history from redis", "type", fmt.Sprintf("%T", **cache))

	return false, nil
}

// SaveUserDataToRedis is a generic routine to store a cache object on Redis. The type is a RedisCache, which is a
// union.
func SaveUserDataToRedis[T RedisCache](guid string, key string, ttl uint, cache *T) error {
	var result string

	util.DebugModule(
		global.DbgCache,
		global.LogKeyGUID, guid,
		global.LogKeyMsg, "Save password history to redis", "type", fmt.Sprintf("%T", *cache),
	)

	redisValue, err := json.Marshal(cache)
	if err != nil {
		level.Error(log.Logger).Log(
			global.LogKeyGUID, guid,
			global.LogKeyError, err,
		)

		return err
	}

	//nolint:lll // Ignore
	if result, err = rediscli.WriteHandle.Set(context.Background(), key, redisValue, time.Duration(ttl)*time.Second).Result(); err != nil {
		level.Error(log.Logger).Log(
			global.LogKeyGUID, guid,
			global.LogKeyError, err,
		)
	}

	util.DebugModule(
		global.DbgCache,
		global.LogKeyGUID, guid,
		"redis", result)

	return err
}

// GetCacheNames returns the set of cache names for the requested protocol and cache backends.
// It searches for cache names based on the requested protocol and cache backends provided.
// If backends is CacheAll or CacheLDAP:
//   - It retrieves the LDAP search protocol configuration for the requested protocol.
//   - If a cache name is found in the LDAP search protocol configuration, it adds it to the cacheNames set.
//
// If backends is CacheAll or CacheSQL:
//   - It retrieves the SQL search protocol configuration for the requested protocol.
//   - If a cache name is found in the SQL search protocol configuration, it adds it to the cacheNames set.
//
// If backends is CacheAll or CacheLua:
//   - It retrieves the Lua search protocol configuration for the requested protocol.
//   - If a cache name is found in the Lua search protocol configuration, it adds it to the cacheNames set.
//
// If no cache names are found in the above steps, it sets the default cache name "__default__".
//
// Parameters:
// - requestedProtocol: The protocol to search for cache names.
// - backends: The cache backends to include in the search. This can be CacheAll, CacheLDAP, CacheSQL, or CacheLua.
//
// Returns:
// - cacheNames: The set of cache names found for the requested protocol and cache backends.
// It can be obtained as a string slice using the GetStringSlice() method.
func GetCacheNames(requestedProtocol string, backends global.CacheNameBackend) (cacheNames config.StringSet) {
	var (
		cacheName    string
		protocolLDAP *config.LDAPSearchProtocol
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

// GetWebAuthnFromRedis returns the user object from Redis based on the unique user ID.
// It retrieves the Redis value based on the provided key and unmarshals it into a User object.
// If there is an error during the process, it logs the error and returns nil with the error.
// Otherwise, it returns the user object.
func GetWebAuthnFromRedis(uniqueUserId string) (user *User, err error) {
	var redisValue []byte

	key := "as_webauthn:user:" + uniqueUserId

	if redisValue, err = rediscli.ReadHandle.Get(context.Background(), key).Bytes(); err != nil {
		level.Error(log.Logger).Log(global.LogKeyError, err)

		return nil, err
	}

	user = &User{}

	if err = json.Unmarshal(redisValue, user); err != nil {
		level.Error(log.Logger).Log(global.LogKeyError, err)

		return nil, err
	}

	return
}

// SaveWebAuthnToRedis saves the user's WebAuthn data to Redis with the specified time-to-live (TTL) duration.
// It serializes the user object using JSON and stores it in Redis under the key "as_webauthn:user:<user id>".
// If serialization fails, it logs the error and returns it. If saving to Redis fails, it logs the error.
// Note: User is a struct representing a user in the system.
func SaveWebAuthnToRedis(user *User, ttl uint) error {
	var result string

	redisValue, err := json.Marshal(user)
	if err != nil {
		level.Error(log.Logger).Log(global.LogKeyError, err)

		return err
	}

	key := "as_webauthn:user:" + user.Id

	//nolint:lll // Ignore
	if result, err = rediscli.WriteHandle.Set(context.Background(), key, redisValue, time.Duration(ttl)*time.Second).Result(); err != nil {
		level.Error(log.Logger).Log(global.LogKeyError, err)
	}

	util.DebugModule(global.DbgCache, "redis", result)

	return err
}
