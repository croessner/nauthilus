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

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	"github.com/redis/go-redis/v9"
)

// LookupUserAccountFromRedis returns the user account value from the user Redis hash.
func LookupUserAccountFromRedis(ctx context.Context, username string) (accountName string, err error) {
	key := config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisUserHashKey

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	accountName, err = rediscli.GetClient().GetReadHandle().HGet(ctx, key, username).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return
		}

		err = nil
	}

	return
}

// LoadCacheFromRedis retrieves cache data from Redis based on a provided key and unmarshals it into the given structure.
// It increments Redis read metrics and logs errors or debug information appropriately during the operation.
// Returns whether the error originated from Redis and any encountered error during retrieval or unmarshaling.
func LoadCacheFromRedis(ctx context.Context, key string, ucp *bktype.PositivePasswordCache) (isRedisErr bool, err error) {
	var redisValue []byte

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

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
func SaveUserDataToRedis(ctx context.Context, guid string, key string, ttl time.Duration, cache *bktype.PositivePasswordCache) {
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

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

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

// GetCacheNames retrieves cache names for the specified protocol from either LDAP, Lua, or both backends as per the input.
// If no cache names are found, a default cache name "__default__" is returned.
func GetCacheNames(requestedProtocol string, backends definitions.CacheNameBackend) (cacheNames config.StringSet) {
	var (
		cacheName    string
		protocolLDAP *config.LDAPSearchProtocol
		protocolLua  *config.LuaSearchProtocol
	)

	cacheNames = config.NewStringSet()

	if backends == definitions.CacheAll || backends == definitions.CacheLDAP {
		for _, poolName := range GetChannel().GetLdapChannel().GetPoolNames() {
			if protocolLDAP, _ = config.GetFile().GetLDAPSearchProtocol(requestedProtocol, poolName); protocolLDAP != nil {
				if cacheName, _ = protocolLDAP.GetCacheName(); cacheName != "" {
					cacheNames.Set(cacheName)
				}
			}
		}
	}

	if backends == definitions.CacheAll || backends == definitions.CacheLua {
		for _, backendName := range GetChannel().GetLuaChannel().GetBackendNames() {
			if protocolLua, _ = config.GetFile().GetLuaSearchProtocol(requestedProtocol, backendName); protocolLua != nil {
				if cacheName, _ = protocolLua.GetCacheName(); cacheName != "" {
					cacheNames.Set(cacheName)
				}
			}
		}
	}

	if len(cacheNames) == 0 {
		cacheNames.Set("__default__")
	}

	return
}

// GetWebAuthnFromRedis retrieves a User object from Redis using the provided unique user ID and unmarshals it from JSON.
// Returns the User object or an error if retrieval or unmarshaling fails.
func GetWebAuthnFromRedis(ctx context.Context, uniqueUserId string) (user *User, err error) {
	var redisValue []byte

	key := config.GetFile().GetServer().GetRedis().GetPrefix() + "webauthn:user:" + uniqueUserId

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

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

// SaveWebAuthnToRedis saves a user's WebAuthn credentials to Redis with a specified TTL.
// Returns an error if serialization or Redis storage operation fails.
func SaveWebAuthnToRedis(ctx context.Context, user *User, ttl time.Duration) error {
	var result string

	redisValue, err := json.Marshal(user)
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, err)

		return err
	}

	key := config.GetFile().GetServer().GetRedis().GetPrefix() + "webauthn:user:" + user.Id

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	//nolint:lll // Ignore
	if result, err = rediscli.GetClient().GetWriteHandle().Set(ctx, key, redisValue, ttl).Result(); err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, err)
	}

	util.DebugModule(definitions.DbgCache, "redis", result)

	return err
}
