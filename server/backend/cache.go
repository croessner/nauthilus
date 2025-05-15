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
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	"github.com/go-webauthn/webauthn/webauthn"
	jsoniter "github.com/json-iterator/go"
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

// LoadCacheFromRedis retrieves cache data from Redis Hash based on a provided key and populates the given structure.
// It increments Redis read metrics and logs errors or debug information appropriately during the operation.
// Returns whether the error originated from Redis and any encountered error during retrieval or unmarshaling.
func LoadCacheFromRedis(ctx context.Context, key string, ucp *bktype.PositivePasswordCache) (isRedisErr bool, err error) {
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	// Get all fields from the hash
	hashValues, err := rediscli.GetClient().GetReadHandle().HGetAll(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return true, nil
		}

		level.Error(log.Logger).Log(definitions.LogKeyMsg, err)

		return true, err
	}

	// If the hash is empty, treat it as a Redis nil error
	if len(hashValues) == 0 {
		return true, nil
	}

	// Parse backend field
	if backendStr, ok := hashValues["backend"]; ok {
		backendInt, err := strconv.Atoi(backendStr)
		if err != nil {
			level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("Failed to parse backend value: %v", err))

			return false, err
		}

		ucp.Backend = definitions.Backend(backendInt)
	}

	// Parse simple string fields
	if password, ok := hashValues["password"]; ok {
		ucp.Password = password
	}

	if accountField, ok := hashValues["account_field"]; ok {
		ucp.AccountField = &accountField
	}

	if totpSecretField, ok := hashValues["totp_secret_field"]; ok {
		ucp.TOTPSecretField = &totpSecretField
	}

	if uniqueUserIDField, ok := hashValues["webauth_userid_field"]; ok {
		ucp.UniqueUserIDField = &uniqueUserIDField
	}

	if displayNameField, ok := hashValues["display_name_field"]; ok {
		ucp.DisplayNameField = &displayNameField
	}

	// Parse attributes JSON
	if attributesJSON, ok := hashValues["attributes"]; ok && attributesJSON != "" {
		var attributes bktype.AttributeMapping
		if err = jsoniter.ConfigFastest.Unmarshal([]byte(attributesJSON), &attributes); err != nil {
			level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("Failed to unmarshal attributes: %v", err))

			return false, err
		}

		ucp.Attributes = attributes
	} else {
		// Initialize empty attributes map if not present
		ucp.Attributes = make(bktype.AttributeMapping)
	}

	util.DebugModule(
		definitions.DbgCache,
		definitions.LogKeyMsg, "Load password history from redis", "type", fmt.Sprintf("%T", *ucp))

	return false, nil
}

// SaveUserDataToRedis is a generic routine to store a cache object on Redis using Redis Hash for better memory efficiency.
// It stores each field of the PositivePasswordCache structure as a separate hash field, with complex fields serialized as JSON.
func SaveUserDataToRedis(ctx context.Context, guid string, key string, ttl time.Duration, cache *bktype.PositivePasswordCache) {
	util.DebugModule(
		definitions.DbgCache,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, "Save password history to redis", "type", fmt.Sprintf("%T", *cache),
	)

	// Create a map for the hash fields
	hashFields := make(map[string]any)

	// Add simple fields
	hashFields["backend"] = int(cache.Backend)

	if cache.Password != "" {
		hashFields["password"] = cache.Password
	}

	if cache.AccountField != nil {
		hashFields["account_field"] = *cache.AccountField
	}

	if cache.TOTPSecretField != nil {
		hashFields["totp_secret_field"] = *cache.TOTPSecretField
	}

	if cache.UniqueUserIDField != nil {
		hashFields["webauth_userid_field"] = *cache.UniqueUserIDField
	}

	if cache.DisplayNameField != nil {
		hashFields["display_name_field"] = *cache.DisplayNameField
	}

	// Serialize the attributes map as JSON since it's complex
	if len(cache.Attributes) > 0 {
		attributesJSON, err := jsoniter.ConfigFastest.Marshal(cache.Attributes)
		if err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, err,
			)

			return
		}

		hashFields["attributes"] = string(attributesJSON)
	}

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	// Use HSet to store the hash fields
	pipe := rediscli.GetClient().GetWriteHandle().Pipeline()
	pipe.HSet(ctx, key, hashFields)
	pipe.Expire(ctx, key, ttl) // Set expiration on the hash

	cmds, err := pipe.Exec(ctx)
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, err,
		)

		return
	}

	// Get the result of the HSet operation
	hsetCmd := cmds[0].(*redis.IntCmd)
	result := fmt.Sprintf("Fields set: %d", hsetCmd.Val())

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

// GetWebAuthnFromRedis retrieves a User object from Redis Hash using the provided unique user ID.
// Returns the User object or an error if retrieval or unmarshaling fails.
func GetWebAuthnFromRedis(ctx context.Context, uniqueUserId string) (user *User, err error) {
	key := config.GetFile().GetServer().GetRedis().GetPrefix() + "webauthn:user:" + uniqueUserId

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	// Get all fields from the hash
	hashValues, err := rediscli.GetClient().GetReadHandle().HGetAll(ctx, key).Result()
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, err)
		return nil, err
	}

	// If the hash is empty, treat it as a Redis nil error
	if len(hashValues) == 0 {
		err = redis.Nil
		level.Error(log.Logger).Log(definitions.LogKeyMsg, err)

		return nil, err
	}

	// Create a new user object
	user = &User{}

	// Set simple fields
	if id, ok := hashValues["id"]; ok {
		user.Id = id
	} else {
		// Use the uniqueUserId if id field is not present
		user.Id = uniqueUserId
	}

	if name, ok := hashValues["name"]; ok {
		user.Name = name
	}

	if displayName, ok := hashValues["display_name"]; ok {
		user.DisplayName = displayName
	}

	// Parse credentials JSON
	if credentialsJSON, ok := hashValues["credentials"]; ok && credentialsJSON != "" {
		var credentials []webauthn.Credential
		if err = jsoniter.ConfigFastest.Unmarshal([]byte(credentialsJSON), &credentials); err != nil {
			level.Error(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("Failed to unmarshal credentials: %v", err))

			return nil, err
		}

		user.Credentials = credentials
	} else {
		// Initialize empty credentials slice if not present
		user.Credentials = []webauthn.Credential{}
	}

	return user, nil
}

// SaveWebAuthnToRedis saves a user's WebAuthn credentials to Redis with a specified TTL using Redis Hash.
// Returns an error if serialization or Redis storage operation fails.
func SaveWebAuthnToRedis(ctx context.Context, user *User, ttl time.Duration) error {
	key := config.GetFile().GetServer().GetRedis().GetPrefix() + "webauthn:user:" + user.Id

	// Create a map for the hash fields
	hashFields := make(map[string]any)

	// Add simple fields
	hashFields["id"] = user.Id
	hashFields["name"] = user.Name
	hashFields["display_name"] = user.DisplayName

	// Serialize the credentials as JSON since it's a complex slice
	if len(user.Credentials) > 0 {
		credentialsJSON, err := jsoniter.ConfigFastest.Marshal(user.Credentials)
		if err != nil {
			level.Error(log.Logger).Log(definitions.LogKeyMsg, err)

			return err
		}

		hashFields["credentials"] = string(credentialsJSON)
	}

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	// Use pipeline to set hash and expiration in a single operation
	pipe := rediscli.GetClient().GetWriteHandle().Pipeline()
	pipe.HSet(ctx, key, hashFields)
	pipe.Expire(ctx, key, ttl) // Set expiration on the hash

	cmds, err := pipe.Exec(ctx)
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, err)

		return err
	}

	// Get the result of the HSet operation
	hsetCmd := cmds[0].(*redis.IntCmd)
	result := fmt.Sprintf("Fields set: %d", hsetCmd.Val())

	util.DebugModule(definitions.DbgCache, "redis", result)

	return nil
}

// GetUserAccountFromCache fetches the user account name from Redis cache using the provided username.
// Logs errors and increments Redis read counter. Returns an empty string if the account name is not found or an error occurs.
func GetUserAccountFromCache(ctx context.Context, username string, guid string) (accountName string) {
	var err error

	accountName, err = LookupUserAccountFromRedis(ctx, username)
	if err != nil || accountName == "" {
		if err != nil {
			level.Error(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, err)
		}

		return ""
	}

	return accountName
}
