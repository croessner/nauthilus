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

package rediscli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	"github.com/redis/go-redis/v9"
)

var (
	// scripts is a map that stores script names and their SHA1 hashes
	scripts = make(map[string]string)

	// scriptsMutex provides mutual exclusion for concurrent access to the scripts map
	scriptsMutex sync.RWMutex

	// ErrScriptNotFound is returned when a script is not found in the scripts map
	ErrScriptNotFound = errors.New("script not found")

	// defaultHashTag is the default hash tag used for Redis Cluster keys
	defaultHashTag = "{nauthilus}"
)

// isClusterClient checks if the Redis client is a cluster client (unexported version)
func isClusterClient(client redis.UniversalClient) bool {
	return IsClusterClient(client)
}

// IsClusterClient checks if the Redis client is a cluster client (exported version)
func IsClusterClient(client redis.UniversalClient) bool {
	_, isCluster := client.(*redis.ClusterClient)

	return isCluster
}

// ensureKeysInSameSlot ensures that all keys hash to the same slot in Redis Cluster
// by adding a common hash tag if needed (unexported version)
func ensureKeysInSameSlot(keys []string) []string {
	return EnsureKeysInSameSlot(keys, defaultHashTag)
}

// EnsureKeysInSameSlot ensures that all keys hash to the same slot in Redis Cluster
// by adding a common hash tag if needed (exported version)
// The hashTag parameter allows specifying a custom hash tag to use
func EnsureKeysInSameSlot(keys []string, hashTag string) []string {
	if len(keys) <= 1 {
		return keys
	}

	// Check if all keys already have the same hash tag
	hasCommonTag := true
	var commonTag string

	for i, key := range keys {
		startIdx := strings.Index(key, "{")
		endIdx := strings.Index(key, "}")

		// If a key has a hash tag
		if startIdx != -1 && endIdx != -1 && startIdx < endIdx {
			tag := key[startIdx : endIdx+1]
			if i == 0 {
				commonTag = tag
			} else if tag != commonTag {
				hasCommonTag = false

				break
			}
		} else {
			hasCommonTag = false

			break
		}
	}

	// If all keys already have the same hash tag, return the original keys
	if hasCommonTag {
		return keys
	}

	// Add the specified hash tag to all keys
	modifiedKeys := make([]string, len(keys))

	for i, key := range keys {
		// Check if the key already has a hash tag
		if strings.Contains(key, "{") && strings.Contains(key, "}") {
			// Replace existing hash tag with the specified one
			startIdx := strings.Index(key, "{")
			endIdx := strings.Index(key, "}")
			if startIdx != -1 && endIdx != -1 && startIdx < endIdx {
				modifiedKeys[i] = key[:startIdx] + hashTag + key[endIdx+1:]
			} else {
				modifiedKeys[i] = hashTag + ":" + key
			}
		} else {
			// Add the specified hash tag as a prefix
			modifiedKeys[i] = hashTag + ":" + key
		}
	}

	return modifiedKeys
}

// UploadScript uploads a Lua script to Redis and stores its SHA1 hash.
// If the script is already uploaded, it returns the existing SHA1 hash.
// This function is thread-safe and can be called concurrently.
func UploadScript(ctx context.Context, scriptName, scriptContent string) (string, error) {
	// Check if the script is already uploaded
	scriptsMutex.RLock()
	sha1, exists := scripts[scriptName]
	scriptsMutex.RUnlock()

	if exists {
		return sha1, nil
	}

	// Script not found, acquire write lock and upload
	scriptsMutex.Lock()
	defer scriptsMutex.Unlock()

	// Check again in case another goroutine uploaded the script while we were waiting
	sha1, exists = scripts[scriptName]
	if exists {
		return sha1, nil
	}

	// Upload the script to Redis
	stats.GetMetrics().GetRedisWriteCounter().Inc()

	sha1, err := GetClient().GetWriteHandle().ScriptLoad(ctx, scriptContent).Result()
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to upload Redis Lua script '%s'. This may affect Redis operations. Check Redis connectivity and permissions.", scriptName),
			definitions.LogKeyError, err,
		)

		return "", err
	}

	// Store the SHA1 hash
	scripts[scriptName] = sha1
	util.DebugModule(definitions.DbgStats,
		definitions.LogKeyMsg, fmt.Sprintf("Uploaded Redis Lua script '%s' with SHA1 %s", scriptName, sha1),
	)

	return sha1, nil
}

// ExecuteScript executes a Lua script on Redis using its SHA1 hash.
// If the script is not found or Redis returns NOSCRIPT, it attempts to re-upload the script.
// This function is thread-safe and can be called concurrently.
//
// If scriptContent is empty and the script is not found in the local cache, ErrScriptNotFound is returned.
// This allows callers to handle the case where a script needs to be uploaded first.
//
// In Redis Cluster mode, this function ensures that all keys hash to the same slot by adding
// a common hash tag if needed.
func ExecuteScript(ctx context.Context, scriptName, scriptContent string, keys []string, args ...interface{}) (interface{}, error) {
	// Get the SHA1 hash for the script
	scriptsMutex.RLock()
	sha1, exists := scripts[scriptName]
	scriptsMutex.RUnlock()

	if !exists {
		// If no script content is provided, we can't upload it
		if scriptContent == "" {
			return nil, ErrScriptNotFound
		}

		// Script not found, upload it
		var err error
		sha1, err = UploadScript(ctx, scriptName, scriptContent)
		if err != nil {
			return nil, err
		}
	}

	// Get the Redis client
	client := GetClient().GetWriteHandle()

	// Check if we're using Redis Cluster and ensure keys hash to the same slot if needed
	if isClusterClient(client) && len(keys) > 1 {
		keys = ensureKeysInSameSlot(keys)
	}

	// Execute the script
	stats.GetMetrics().GetRedisWriteCounter().Inc()

	result, err := client.EvalSha(ctx, sha1, keys, args...).Result()
	if err != nil {
		// Check if the error is NOSCRIPT
		if err.Error() == "NOSCRIPT No matching script. Please use EVAL." {
			level.Warn(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Script '%s' not found on Redis server, re-uploading. If this happens frequently, Redis scripts might have been administratively deleted. Consider restarting Nauthilus.", scriptName),
			)

			// Re-upload the script
			sha1, err = UploadScript(ctx, scriptName, scriptContent)
			if err != nil {
				return nil, err
			}

			// Try executing again
			stats.GetMetrics().GetRedisWriteCounter().Inc()

			result, err = client.EvalSha(ctx, sha1, keys, args...).Result()
			if err != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Failed to execute Redis Lua script '%s' after re-upload. Redis scripts might have been administratively deleted. Consider restarting Nauthilus.", scriptName),
					definitions.LogKeyError, err,
				)

				return nil, err
			}
		} else if strings.Contains(err.Error(), "CROSSSLOT Keys in request don't hash to the same slot") {
			// If we get a CROSSSLOT error, log it with more details
			level.Warn(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("CROSSSLOT error executing script '%s' with keys %v, attempting to fix", scriptName, keys),
				"caller", "scripts.go:ExecuteScript",
			)

			// Force keys to use the same hash tag
			keys = ensureKeysInSameSlot(keys)

			// Try executing again with modified keys
			stats.GetMetrics().GetRedisWriteCounter().Inc()

			result, err = client.EvalSha(ctx, sha1, keys, args...).Result()
			if err != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Failed to execute Redis Lua script '%s' after fixing keys", scriptName),
					definitions.LogKeyError, err,
					"keys", fmt.Sprintf("%v", keys),
				)

				return nil, err
			}
		} else {
			level.Error(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Failed to execute Redis Lua script '%s'", scriptName),
				definitions.LogKeyError, err,
			)

			return nil, err
		}
	}

	return result, nil
}

// AuthPreflight performs a combined account lookup (HGET USER) and brute-force repeat check (HEXISTS BF)
// using the registered AuthPreflight Lua script. It returns the mapped account (may be empty) and whether
// the client network is considered repeating (true/false).
func AuthPreflight(ctx context.Context, username, clientNet string) (account string, repeating bool, err error) {
	// Build keys with proper prefix
	prefix := config.GetFile().GetServer().GetRedis().GetPrefix()
	userKey := prefix + definitions.RedisUserHashKey
	bfKey := prefix + definitions.RedisBruteForceHashKey

	keys := []string{userKey, bfKey}
	// Ensure hash slot alignment if cluster
	if isClusterClient(GetClient().GetWriteHandle()) {
		keys = ensureKeysInSameSlot(keys)
	}

	// Use bounded context
	dctx, cancel := util.GetCtxWithDeadlineRedisRead(ctx)
	defer cancel()

	res, e := ExecuteScript(dctx, "AuthPreflight", LuaScripts["AuthPreflight"], keys, username, clientNet)
	if e != nil {
		err = e

		return
	}

	// Expect array reply: {account(string), repeating(number)}
	if arr, ok := res.([]interface{}); ok && len(arr) == 2 {
		if s, ok2 := arr[0].(string); ok2 {
			account = s
		}
		// go-redis may decode integers as int64
		switch v := arr[1].(type) {
		case int64:
			repeating = v == 1
		case int:
			repeating = v == 1
		case string:
			repeating = v == "1"
		default:
			repeating = false
		}
	} else {
		err = fmt.Errorf("invalid preflight reply: %#v", res)
	}

	return
}

// UploadAllScripts uploads all Lua scripts defined in lua_scripts.go to Redis.
// This function should be called at program startup to ensure all scripts are available.
func UploadAllScripts(ctx context.Context) error {
	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, "Uploading all Redis Lua scripts",
	)

	// Create a context with timeout to prevent hanging indefinitely
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	for scriptName, scriptContent := range LuaScripts {
		// Use the context with timeout for each script upload
		_, err := UploadScript(ctxWithTimeout, scriptName, scriptContent)
		if err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Failed to upload Redis Lua script '%s'. This may cause issues with Redis operations. If the problem persists, check Redis connectivity and permissions.", scriptName),
				definitions.LogKeyError, err,
			)

			return err
		}

		// Check if the context has been canceled or timed out
		if ctxWithTimeout.Err() != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Timeout or cancellation while uploading Redis Lua scripts"),
				definitions.LogKeyError, ctxWithTimeout.Err(),
			)

			return ctxWithTimeout.Err()
		}
	}

	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("Successfully uploaded %d Redis Lua scripts", len(LuaScripts)),
	)

	return nil
}
