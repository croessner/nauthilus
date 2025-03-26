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

package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	"github.com/redis/go-redis/v9"
)

// PasswordHistory is a map of hashed passwords with their failure counter.
type PasswordHistory map[string]uint

// PositivePasswordCache is a container that stores all kinds of user information upon a successful authentication. It
// is used for Redis as a short cache object and as a proxy structure between Nauthilus instances. The cache object is not
// refreshed upon continuous requests. If the Redis TTL has expired, the object is removed from the cache to force a refresh
// of the user data from underlying databases.
type PositivePasswordCache struct {
	Backend           definitions.Backend `json:"passdb_backend"`
	Password          string              `json:"password,omitempty"`
	AccountField      *string             `json:"account_field"`
	TOTPSecretField   *string             `json:"totp_secret_field"`
	UniqueUserIDField *string             `json:"webauth_userid_field"`
	DisplayNameField  *string             `json:"display_name_field"`
	Attributes        DatabaseResult      `json:"attributes"`
}

// LookupUserAccountFromRedis returns the user account value from the user Redis hash.
func LookupUserAccountFromRedis(ctx context.Context, username string) (accountName string, err error) {
	key := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisUserHashKey

	defer stats.RedisReadCounter.Inc()

	accountName, err = rediscli.GetClient().GetReadHandle().HGet(ctx, key, username).Result()
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
func LoadCacheFromRedis(ctx context.Context, key string, ucp *PositivePasswordCache) (isRedisErr bool, err error) {
	var redisValue []byte

	defer stats.RedisReadCounter.Inc()

	if redisValue, err = rediscli.GetClient().GetReadHandle().Get(ctx, key).Bytes(); err != nil {
		if errors.Is(err, redis.Nil) {
			return true, nil
		}

		level.Error(log.Logger).Log(definitions.LogKeyMsg, err)

		return true, err
	}

	if err = json.Unmarshal(redisValue, ucp); err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, err)

		return
	}

	util.DebugModule(
		definitions.DbgCache,
		definitions.LogKeyMsg, "Load password history from redis", "type", fmt.Sprintf("%T", *ucp))

	return false, nil
}

// SaveUserDataToRedis is a generic routine to store a cache object on Redis. The type is a RedisCache, which is a
// union.
func SaveUserDataToRedis(ctx context.Context, guid string, key string, ttl time.Duration, cache *PositivePasswordCache) {
	var result string

	util.DebugModule(
		definitions.DbgCache,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, "Save password history to redis", "type", fmt.Sprintf("%T", *cache),
	)

	redisValue, err := json.Marshal(cache)
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, err,
		)

		return
	}

	defer stats.RedisWriteCounter.Inc()

	//nolint:lll // Ignore
	if result, err = rediscli.GetClient().GetWriteHandle().Set(ctx, key, redisValue, ttl).Result(); err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, err,
		)
	}

	util.DebugModule(
		definitions.DbgCache,
		definitions.LogKeyGUID, guid,
		"redis", result)

	return
}

// GetCacheNames returns the set of cache names for the requested protocol and cache backends.
// It searches for cache names based on the requested protocol and cache backends provided.
// If backends is CacheAll or CacheLDAP:
//   - It retrieves the LDAP search protocol configuration for the requested protocol.
//   - If a cache name is found in the LDAP search protocol configuration, it adds it to the cacheNames set.
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
func GetCacheNames(requestedProtocol string, backends definitions.CacheNameBackend) (cacheNames config.StringSet) {
	var (
		cacheName    string
		protocolLDAP *config.LDAPSearchProtocol
		protocolLua  *config.LuaSearchProtocol
	)

	cacheNames = config.NewStringSet()

	if backends == definitions.CacheAll || backends == definitions.CacheLDAP {
		if protocolLDAP, _ = config.GetFile().GetLDAPSearchProtocol(requestedProtocol); protocolLDAP != nil {
			if cacheName, _ = protocolLDAP.GetCacheName(); cacheName != "" {
				cacheNames.Set(cacheName)
			}
		}
	}

	if backends == definitions.CacheAll || backends == definitions.CacheLua {
		if protocolLua, _ = config.GetFile().GetLuaSearchProtocol(requestedProtocol); protocolLua != nil {
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
func GetWebAuthnFromRedis(ctx context.Context, uniqueUserId string) (user *User, err error) {
	var redisValue []byte

	key := config.GetFile().GetServer().GetRedis().GetPrefix() + "webauthn:user:" + uniqueUserId

	defer stats.RedisReadCounter.Inc()

	if redisValue, err = rediscli.GetClient().GetReadHandle().Get(ctx, key).Bytes(); err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, err)

		return nil, err
	}

	user = &User{}

	if err = json.Unmarshal(redisValue, user); err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, err)

		return nil, err
	}

	return
}

// SaveWebAuthnToRedis saves the user's WebAuthn data to Redis with the specified time-to-live (TTL) duration.
// It serializes the user object using JSON and stores it in Redis under the key "as_webauthn:user:<user id>".
// If serialization fails, it logs the error and returns it.
// If saving to "Redis" fails, it logs the error.
// Note: User is a struct representing a user in the system.
func SaveWebAuthnToRedis(ctx context.Context, user *User, ttl time.Duration) error {
	var result string

	redisValue, err := json.Marshal(user)
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, err)

		return err
	}

	key := config.GetFile().GetServer().GetRedis().GetPrefix() + "webauthn:user:" + user.Id

	defer stats.RedisWriteCounter.Inc()

	//nolint:lll // Ignore
	if result, err = rediscli.GetClient().GetWriteHandle().Set(ctx, key, redisValue, ttl).Result(); err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, err)
	}

	util.DebugModule(definitions.DbgCache, "redis", result)

	return err
}
