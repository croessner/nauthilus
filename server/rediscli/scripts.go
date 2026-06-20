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
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/util"

	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
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

	if keysShareCommonHashTag(keys) {
		return keys
	}

	modifiedKeys := make([]string, len(keys))

	for i, key := range keys {
		modifiedKeys[i] = keyWithHashTag(key, hashTag)
	}

	return modifiedKeys
}

// keysShareCommonHashTag reports whether every key already uses the same Redis hash tag.
func keysShareCommonHashTag(keys []string) bool {
	var commonTag string

	for i, key := range keys {
		tag, ok := redisKeyHashTag(key)
		if !ok {
			return false
		}

		if i == 0 {
			commonTag = tag

			continue
		}

		if tag != commonTag {
			return false
		}
	}

	return true
}

// redisKeyHashTag returns the brace-delimited Redis cluster hash tag for a key.
func redisKeyHashTag(key string) (string, bool) {
	startIdx, endIdx, ok := redisKeyHashTagBounds(key)
	if !ok {
		return "", false
	}

	return key[startIdx : endIdx+1], true
}

// redisKeyHashTagBounds returns the byte offsets for a valid Redis cluster hash tag.
func redisKeyHashTagBounds(key string) (int, int, bool) {
	startIdx := strings.Index(key, "{")
	endIdx := strings.Index(key, "}")

	return startIdx, endIdx, startIdx != -1 && endIdx != -1 && startIdx < endIdx
}

// keyWithHashTag replaces an existing hash tag or prefixes the key with one.
func keyWithHashTag(key string, hashTag string) string {
	startIdx, endIdx, ok := redisKeyHashTagBounds(key)
	if ok {
		return key[:startIdx] + hashTag + key[endIdx+1:]
	}

	return hashTag + ":" + key
}

// uploadScriptToHandle loads a Lua script onto a single Redis handle and returns its SHA1 hash.
func uploadScriptToHandle(ctx context.Context, handle redis.UniversalClient, scriptContent string) (string, error) {
	stats.GetMetrics().GetRedisWriteCounter().Inc()

	return handle.ScriptLoad(ctx, scriptContent).Result()
}

// uploadScriptToReadHandles distributes a Lua script to all distinct read handles
// so that EvalSha calls on read pipelines succeed. Errors are logged but not fatal,
// because the write-handle upload is the authoritative one.
func uploadScriptToReadHandles(ctx context.Context, client Client, scriptName, scriptContent string) {
	for _, rh := range client.GetReadHandles() {
		_, err := uploadScriptToHandle(ctx, rh, scriptContent)
		if err != nil {
			level.Warn(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Failed to upload Redis Lua script '%s' to read handle (non-fatal)", scriptName),
				definitions.LogKeyError, err,
			)
		}
	}
}

// UploadScript uploads a Lua script to Redis and stores its SHA1 hash.
// The script is loaded on the write handle first, then distributed to all
// distinct read handles so that EvalSha works on read pipelines as well.
// If the script is already uploaded, it returns the existing SHA1 hash.
// This function is thread-safe and can be called concurrently.
func UploadScript(ctx context.Context, client Client, scriptName, scriptContent string) (string, error) {
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

	// Upload the script to the write handle (authoritative)
	var err error

	sha1, err = uploadScriptToHandle(ctx, client.GetWriteHandle(), scriptContent)
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to upload Redis Lua script '%s'. This may affect Redis operations. Check Redis connectivity and permissions.", scriptName),
			definitions.LogKeyError, err,
		)

		return "", err
	}

	// Distribute to all read handles (replicas / read-only cluster nodes)
	uploadScriptToReadHandles(ctx, client, scriptName, scriptContent)

	// Store the SHA1 hash
	scripts[scriptName] = sha1
	util.DebugModuleWithCfg(ctx, config.GetFile(), log.Logger, definitions.DbgStats,
		definitions.LogKeyMsg, fmt.Sprintf("Uploaded Redis Lua script '%s' with SHA1 %s", scriptName, sha1),
	)

	return sha1, nil
}

// InvalidateScript removes a single script from the local SHA1 cache so that
// the next UploadScript call will re-upload it to all Redis handles.
// This is used by NOSCRIPT retry paths to force a fresh upload.
func InvalidateScript(scriptName string) {
	scriptsMutex.Lock()
	defer scriptsMutex.Unlock()

	delete(scripts, scriptName)
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
func ExecuteScript(ctx context.Context, client Client, scriptName, scriptContent string, keys []string, args ...any) (any, error) {
	// Tracing: cover a Redis Lua script execution including retries
	tr := monittrace.New("nauthilus/redis_batch")
	sctx, sp := tr.Start(ctx, "redis.script",
		attribute.String("script", scriptName),
		attribute.Int("keys_count", len(keys)),
		attribute.Int("args_count", len(args)),
	)

	// Attach context for downstream EvalSha/Upload
	_ = sctx

	defer sp.End()

	sha1, err := resolveScriptSHA(sctx, client, scriptName, scriptContent)
	if err != nil {
		sp.RecordError(err)

		return nil, err
	}

	writeHandle := client.GetWriteHandle()
	keys = scriptKeysForClient(writeHandle, keys)

	result, err := evalRedisScript(sctx, writeHandle, sha1, keys, args...)
	if err != nil {
		result, err = handleScriptEvalError(sctx, client, writeHandle, scriptName, scriptContent, sha1, keys, args, err, sp)
		if err != nil {
			return nil, err
		}
	}

	// Attach basic result hints
	sp.SetAttributes(attribute.Bool("ok", true))

	return result, nil
}

// resolveScriptSHA returns a cached script SHA or uploads the script when needed.
func resolveScriptSHA(ctx context.Context, client Client, scriptName string, scriptContent string) (string, error) {
	scriptsMutex.RLock()

	sha1, exists := scripts[scriptName]

	scriptsMutex.RUnlock()

	if !exists {
		// If no script content is provided, we can't upload it
		if scriptContent == "" {
			return "", ErrScriptNotFound
		}

		// Script not found, upload it
		var err error

		sha1, err = UploadScript(ctx, client, scriptName, scriptContent)
		if err != nil {
			return "", err
		}
	}

	return sha1, nil
}

// scriptKeysForClient normalizes script keys for Redis Cluster clients.
func scriptKeysForClient(writeHandle redis.UniversalClient, keys []string) []string {
	if isClusterClient(writeHandle) && len(keys) > 1 {
		return ensureKeysInSameSlot(keys)
	}

	return keys
}

// evalRedisScript executes an EvalSha call and accounts for Redis write metrics.
func evalRedisScript(ctx context.Context, writeHandle redis.UniversalClient, sha1 string, keys []string, args ...any) (any, error) {
	stats.GetMetrics().GetRedisWriteCounter().Inc()

	return writeHandle.EvalSha(ctx, sha1, keys, args...).Result()
}

// handleScriptEvalError dispatches script execution retries for known Redis errors.
func handleScriptEvalError(
	ctx context.Context,
	client Client,
	writeHandle redis.UniversalClient,
	scriptName string,
	scriptContent string,
	sha1 string,
	keys []string,
	args []any,
	err error,
	sp trace.Span,
) (any, error) {
	switch {
	case err.Error() == "NOSCRIPT No matching script. Please use EVAL.":
		return retryScriptAfterNoScript(ctx, client, writeHandle, scriptName, scriptContent, keys, args, sp)
	case strings.Contains(err.Error(), "CROSSSLOT Keys in request don't hash to the same slot"):
		return retryScriptAfterCrossSlot(ctx, writeHandle, scriptName, sha1, keys, args, sp)
	default:
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to execute Redis Lua script '%s'", scriptName),
			definitions.LogKeyError, err,
		)

		sp.RecordError(err)

		return nil, err
	}
}

// retryScriptAfterNoScript re-uploads a missing script and executes it again.
func retryScriptAfterNoScript(
	ctx context.Context,
	client Client,
	writeHandle redis.UniversalClient,
	scriptName string,
	scriptContent string,
	keys []string,
	args []any,
	sp trace.Span,
) (any, error) {
	level.Warn(log.Logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("Script '%s' not found on Redis server, re-uploading. If this happens frequently, Redis scripts might have been administratively deleted. Consider restarting Nauthilus.", scriptName),
	)

	sp.SetAttributes(attribute.String("retry_reason", "noscript"))
	InvalidateScript(scriptName)

	sha1, err := UploadScript(ctx, client, scriptName, scriptContent)
	if err != nil {
		sp.RecordError(err)

		return nil, err
	}

	result, err := evalRedisScript(ctx, writeHandle, sha1, keys, args...)
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to execute Redis Lua script '%s' after re-upload. Redis scripts might have been administratively deleted. Consider restarting Nauthilus.", scriptName),
			definitions.LogKeyError, err,
		)

		sp.RecordError(err)

		return nil, err
	}

	return result, nil
}

// retryScriptAfterCrossSlot normalizes keys and retries a Redis Cluster script call.
func retryScriptAfterCrossSlot(
	ctx context.Context,
	writeHandle redis.UniversalClient,
	scriptName string,
	sha1 string,
	keys []string,
	args []any,
	sp trace.Span,
) (any, error) {
	level.Warn(log.Logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("CROSSSLOT error executing script '%s' with keys %v, attempting to fix", scriptName, keys),
		"caller", "scripts.go:ExecuteScript",
	)

	sp.SetAttributes(attribute.String("retry_reason", "crossslot"))

	keys = ensureKeysInSameSlot(keys)

	result, err := evalRedisScript(ctx, writeHandle, sha1, keys, args...)
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to execute Redis Lua script '%s' after fixing keys", scriptName),
			definitions.LogKeyError, err,
			"keys", fmt.Sprintf("%v", keys),
		)

		sp.RecordError(err)

		return nil, err
	}

	return result, nil
}

// UploadAllScripts uploads all Lua scripts defined in lua_scripts.go to Redis.
// This function should be called at program startup to ensure all scripts are available.
func UploadAllScripts(ctx context.Context, logger *slog.Logger, client Client) error {
	level.Info(logger).Log(
		definitions.LogKeyMsg, "Uploading all Redis Lua scripts",
	)

	for scriptName, scriptContent := range LuaScripts {
		// Use a dedicated context with timeout for each script upload to prevent one slow
		// upload from failing the entire batch or hanging indefinitely.
		uploadCtx, cancel := context.WithTimeout(ctx, 5*time.Second)

		_, err := UploadScript(uploadCtx, client, scriptName, scriptContent)

		cancel()

		if err != nil {
			level.Error(logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Failed to upload Redis Lua script '%s'. This may cause issues with Redis operations. If the problem persists, check Redis connectivity and permissions.", scriptName),
				definitions.LogKeyError, err,
			)

			return err
		}
	}

	level.Info(logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("Successfully uploaded %d Redis Lua scripts", len(LuaScripts)),
	)

	return nil
}

// ClearScriptCache clears the local script SHA1 cache.
// This is primarily used for testing purposes to ensure scripts are re-uploaded.
func ClearScriptCache() {
	scriptsMutex.Lock()
	defer scriptsMutex.Unlock()

	scripts = make(map[string]string)
}
