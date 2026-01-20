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
	"log/slog"
	"strconv"
	"time"

	"github.com/croessner/nauthilus/server/backend/accountcache"
	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/go-webauthn/webauthn/webauthn"
	jsoniter "github.com/json-iterator/go"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/sync/singleflight"
)

var (
	accountSF singleflight.Group
	cacheSF   singleflight.Group
)

// LookupUserAccountFromRedis returns the user account value from the user Redis hash.
func LookupUserAccountFromRedis(ctx context.Context, cfg config.File, redisClient rediscli.Client, username, protocol, oidcClientID string) (accountName string, err error) {
	// Tracing span for a user account lookup in the generic backend layer
	tr := monittrace.New("nauthilus/backend")
	sctx, sp := tr.Start(ctx, "backend.lookup_user_account",
		attribute.String("username", username),
		attribute.String("protocol", protocol),
		attribute.String("oidc_client_id", oidcClientID),
	)

	defer sp.End()

	key := rediscli.GetUserHashKey(cfg.GetServer().GetRedis().GetPrefix(), username)

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	// Use span context for Redis read deadline
	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(sctx, cfg)
	defer cancel()

	field := accountcache.GetAccountMappingField(username, protocol, oidcClientID)

	accountName, err = redisClient.GetReadHandle().HGet(dCtx, key, field).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			// Record real Redis errors (not a miss)
			sp.RecordError(err)

			return
		}

		err = nil
	}

	sp.SetAttributes(attribute.Bool("found", accountName != ""))

	return
}

// LoadCacheFromRedisWithSF is a wrapper around LoadCacheFromRedis that uses singleflight to avoid redundant Redis lookups.
func LoadCacheFromRedisWithSF(ctx context.Context, cfg config.File, logger *slog.Logger, redisClient rediscli.Client, key string, ucp *bktype.PositivePasswordCache) (isRedisErr bool, err error) {
	type result struct {
		isRedisErr bool
		ucp        *bktype.PositivePasswordCache
	}

	val, err, _ := cacheSF.Do(key, func() (any, error) {
		resUCP := &bktype.PositivePasswordCache{}
		isRErr, loadErr := LoadCacheFromRedis(ctx, cfg, logger, redisClient, key, resUCP)
		if loadErr != nil {
			return nil, loadErr
		}

		return &result{isRedisErr: isRErr, ucp: resUCP}, nil
	})

	if err != nil {
		return false, err
	}

	res := val.(*result)
	*ucp = *res.ucp // Copy scalar values

	// Deep copy attributes map to avoid shared mutation between concurrent requests
	ucp.Attributes = res.ucp.Attributes.Clone()

	return res.isRedisErr, nil
}

// LoadCacheFromRedis retrieves cache data from Redis Hash based on a provided key and populates the given structure.
// It increments Redis read metrics and logs errors or debug information appropriately during the operation.
// Returns whether the error originated from Redis and any encountered error during retrieval or unmarshaling.
func LoadCacheFromRedis(ctx context.Context, cfg config.File, logger *slog.Logger, redisClient rediscli.Client, key string, ucp *bktype.PositivePasswordCache) (isRedisErr bool, err error) {
	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, cfg)
	defer cancel()

	// Get all fields from the hash
	hashValues, err := redisClient.GetReadHandle().HGetAll(dCtx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return true, nil
		}

		level.Error(logger).Log(
			definitions.LogKeyMsg, "Failed to get cache from redis",
			definitions.LogKeyError, err,
		)

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
			level.Error(logger).Log(
				definitions.LogKeyMsg, "Failed to parse backend value",
				definitions.LogKeyError, err,
			)

			return false, err
		}

		ucp.Backend = definitions.Backend(backendInt)
	}

	// Parse simple string fields
	if password, ok := hashValues["password"]; ok {
		ucp.Password = password
	}

	if accountField, ok := hashValues["account_field"]; ok {
		ucp.AccountField = accountField
	}

	if totpSecretField, ok := hashValues["totp_secret_field"]; ok {
		ucp.TOTPSecretField = totpSecretField
	}

	if uniqueUserIDField, ok := hashValues["webauth_userid_field"]; ok {
		ucp.UniqueUserIDField = uniqueUserIDField
	}

	if displayNameField, ok := hashValues["display_name_field"]; ok {
		ucp.DisplayNameField = displayNameField
	}

	// Parse attributes JSON
	if attributesJSON, ok := hashValues["attributes"]; ok && attributesJSON != "" {
		var attributes bktype.AttributeMapping
		if err = jsoniter.ConfigFastest.Unmarshal([]byte(attributesJSON), &attributes); err != nil {
			level.Error(logger).Log(
				definitions.LogKeyMsg, "Failed to unmarshal attributes",
				definitions.LogKeyError, err,
			)

			return false, err
		}

		ucp.Attributes = attributes
	} else {
		// Initialize empty attributes map if not present
		ucp.Attributes = make(bktype.AttributeMapping)
	}

	util.DebugModuleWithCfg(ctx, cfg, logger,
		definitions.DbgCache,
		definitions.LogKeyMsg, "Load password history from redis", "type", fmt.Sprintf("%T", *ucp))

	return false, nil
}

// SaveUserDataToRedis is a generic routine to store a cache object on Redis using Redis Hash for better memory efficiency.
// It stores each field of the PositivePasswordCache structure as a separate hash field, with complex fields serialized as JSON.
func SaveUserDataToRedis(ctx context.Context, cfg config.File, logger *slog.Logger, redisClient rediscli.Client, guid string, key string, ttl time.Duration, cache *bktype.PositivePasswordCache) {
	util.DebugModuleWithCfg(ctx, cfg, logger,
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

	if cache.AccountField != "" {
		hashFields["account_field"] = cache.AccountField
	}

	if cache.TOTPSecretField != "" {
		hashFields["totp_secret_field"] = cache.TOTPSecretField
	}

	if cache.UniqueUserIDField != "" {
		hashFields["webauth_userid_field"] = cache.UniqueUserIDField
	}

	if cache.DisplayNameField != "" {
		hashFields["display_name_field"] = cache.DisplayNameField
	}

	// Serialize the attributes map as JSON since it's complex
	if len(cache.Attributes) > 0 {
		attributesJSON, err := jsoniter.ConfigFastest.Marshal(cache.Attributes)
		if err != nil {
			level.Error(logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "Failed to marshal attributes",
				definitions.LogKeyError, err,
			)

			return
		}

		hashFields["attributes"] = string(attributesJSON)
	}

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, cfg)
	defer cancel()

	// Use HSet to store the hash fields
	pipe := redisClient.GetWriteHandle().Pipeline()
	pipe.HSet(dCtx, key, hashFields)
	pipe.Expire(dCtx, key, ttl) // Set expiration on the hash

	cmds, err := pipe.Exec(dCtx)
	if err != nil {
		level.Error(logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "Failed to store password history to redis",
			definitions.LogKeyError, err,
		)

		return
	}

	// Get the result of the HSet operation
	hsetCmd := cmds[0].(*redis.IntCmd)
	result := fmt.Sprintf("Fields set: %d", hsetCmd.Val())

	util.DebugModuleWithCfg(ctx, cfg, logger,
		definitions.DbgCache,
		definitions.LogKeyGUID, guid,
		"redis", result)

	return
}

// cacheNamer is a minimal interface implemented by protocol configs that expose a cache name.
// Both LDAPSearchProtocol and LuaSearchProtocol provide GetCacheName().
type cacheNamer interface {
	GetCacheName() (string, error)
}

// collectCacheNames iterates over provided names, resolves protocol via get(),
// and, if a non-empty cache name is available, adds it to out.
func collectCacheNames(
	names []string,
	requestedProtocol string,
	get func(requested, name string) (cacheNamer, error),
	out config.StringSet,
) {
	for _, name := range names {
		proto, _ := get(requestedProtocol, name)
		if proto == nil {
			continue
		}

		if cacheName, _ := proto.GetCacheName(); cacheName != "" {
			out.Set(cacheName)
		}
	}
}

// GetCacheNames retrieves cache names for the specified protocol from either LDAP, Lua, or both backends as per the input.
// If no cache names are found, a default cache name "__default__" is returned.
func GetCacheNames(cfg config.File, channel Channel, requestedProtocol string, backends definitions.CacheNameBackend) (cacheNames config.StringSet) {
	cacheNames = config.NewStringSet()

	if (backends == definitions.CacheAll || backends == definitions.CacheLDAP) && channel != nil && channel.GetLdapChannel() != nil {
		collectCacheNames(
			channel.GetLdapChannel().GetPoolNames(),
			requestedProtocol,
			func(req, pool string) (cacheNamer, error) {
				return cfg.GetLDAPSearchProtocol(req, pool)
			},
			cacheNames,
		)
	}

	if (backends == definitions.CacheAll || backends == definitions.CacheLua) && channel != nil && channel.GetLuaChannel() != nil {
		collectCacheNames(
			channel.GetLuaChannel().GetBackendNames(),
			requestedProtocol,
			func(req, backend string) (cacheNamer, error) {
				return cfg.GetLuaSearchProtocol(req, backend)
			},
			cacheNames,
		)
	}

	if len(cacheNames) == 0 {
		cacheNames.Set("__default__")
	}

	return
}

// GetWebAuthnFromRedis retrieves a User object from Redis Hash using the provided unique user ID.
// Returns the User object or an error if retrieval or unmarshaling fails.
func GetWebAuthnFromRedis(ctx context.Context, cfg config.File, logger *slog.Logger, redisClient rediscli.Client, uniqueUserId string) (user *User, err error) {
	key := cfg.GetServer().GetRedis().GetPrefix() + "webauthn:user:" + uniqueUserId

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, cfg)
	defer cancel()

	// Get all fields from the hash
	hashValues, err := redisClient.GetReadHandle().HGetAll(dCtx, key).Result()
	if err != nil {
		level.Error(logger).Log(
			definitions.LogKeyMsg, "Failed to get WebAuthn user from redis",
			definitions.LogKeyError, err,
		)

		return nil, err
	}

	// If the hash is empty, treat it as a Redis nil error
	if len(hashValues) == 0 {
		err = redis.Nil
		level.Error(logger).Log(
			definitions.LogKeyMsg, "WebAuthn user not found in redis",
			definitions.LogKeyError, err,
		)

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
			level.Error(logger).Log(
				definitions.LogKeyMsg, "Failed to unmarshal credentials",
				definitions.LogKeyError, err,
			)

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
func SaveWebAuthnToRedis(ctx context.Context, logger *slog.Logger, cfg config.File, redisClient rediscli.Client, user *User, ttl time.Duration) error {
	key := cfg.GetServer().GetRedis().GetPrefix() + "webauthn:user:" + user.Id

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
			level.Error(logger).Log(
				definitions.LogKeyMsg, "Failed to marshal credentials",
				definitions.LogKeyError, err,
			)

			return err
		}

		hashFields["credentials"] = string(credentialsJSON)
	}

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, cfg)
	defer cancel()

	// Use pipeline to set hash and expiration in a single operation
	pipe := redisClient.GetWriteHandle().Pipeline()
	pipe.HSet(dCtx, key, hashFields)
	pipe.Expire(dCtx, key, ttl) // Set expiration on the hash

	cmds, err := pipe.Exec(dCtx)
	if err != nil {
		level.Error(logger).Log(
			definitions.LogKeyMsg, "Failed to store WebAuthn user to redis",
			definitions.LogKeyError, err,
		)

		return err
	}

	// Get the result of the HSet operation
	hsetCmd := cmds[0].(*redis.IntCmd)
	result := fmt.Sprintf("Fields set: %d", hsetCmd.Val())

	util.DebugModuleWithCfg(ctx, cfg, logger, definitions.DbgCache, "redis", result)

	return nil
}

// GetUserAccountFromCache fetches the user account name from Redis cache using the provided username.
// Logs errors and increments Redis read counter. Returns an empty string if the account name is not found or an error occurs.
func GetUserAccountFromCache(ctx context.Context, cfg config.File, logger *slog.Logger, redisClient rediscli.Client, accountCache *accountcache.Manager, username, protocol, oidcClientID, guid string) (accountName string) {
	// First try in-process account cache when enabled
	if acc, ok := accountCache.Get(username, protocol, oidcClientID); ok && acc != "" {
		return acc
	}

	sfKey := accountcache.GetAccountMappingField(username, protocol, oidcClientID)

	// Use singleflight to avoid redundant Redis lookups for the same user under high concurrency
	val, err, _ := accountSF.Do(sfKey, func() (any, error) {
		res, lookupErr := LookupUserAccountFromRedis(ctx, cfg, redisClient, username, protocol, oidcClientID)
		if lookupErr != nil {
			return "", lookupErr
		}

		if res != "" {
			// Store positive result in in-process cache
			accountCache.Set(cfg, username, protocol, oidcClientID, res)
		}

		return res, nil
	})

	if err != nil {
		level.Error(logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "Failed to get user account from cache",
			definitions.LogKeyError, err,
		)

		return ""
	}

	return val.(string)
}

// ResolveAccountIdentifier resolves an identifier that may be either a username or an account name.
// It first tries to look up a mapping in the USER hash; if not found, it treats the identifier as an account name.
func ResolveAccountIdentifier(ctx context.Context, cfg config.File, logger *slog.Logger, redisClient rediscli.Client, identifier, protocol, oidcClientID, guid string) (accountName string) {
	var err error

	// Try to resolve username -> account name mapping
	accountName, err = LookupUserAccountFromRedis(ctx, cfg, redisClient, identifier, protocol, oidcClientID)
	if err != nil {
		level.Error(logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "Failed to resolve account identifier",
			definitions.LogKeyError, err)
	}

	// If no mapping exists, assume the provided identifier is already an account name
	if accountName == "" {
		accountName = identifier
	}

	return accountName
}
