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
	"sync"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
)

var (
	// scripts is a map that stores script names and their SHA1 hashes
	scripts = make(map[string]string)

	// scriptsMutex provides mutual exclusion for concurrent access to the scripts map
	scriptsMutex sync.RWMutex

	// ErrScriptNotFound is returned when a script is not found in the scripts map
	ErrScriptNotFound = errors.New("script not found")
)

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
			definitions.LogKeyMsg, fmt.Sprintf("Failed to upload Redis Lua script '%s': %v", scriptName, err),
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

	// Execute the script
	stats.GetMetrics().GetRedisWriteCounter().Inc()
	result, err := GetClient().GetWriteHandle().EvalSha(ctx, sha1, keys, args...).Result()
	if err != nil {
		// Check if the error is NOSCRIPT
		if err.Error() == "NOSCRIPT No matching script. Please use EVAL." {
			level.Warn(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Script '%s' not found on Redis server, re-uploading", scriptName),
			)

			// Re-upload the script
			sha1, err = UploadScript(ctx, scriptName, scriptContent)
			if err != nil {
				return nil, err
			}

			// Try executing again
			stats.GetMetrics().GetRedisWriteCounter().Inc()

			result, err = GetClient().GetWriteHandle().EvalSha(ctx, sha1, keys, args...).Result()
			if err != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Failed to execute Redis Lua script '%s' after re-upload: %v", scriptName, err),
				)

				return nil, err
			}
		} else {
			level.Error(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Failed to execute Redis Lua script '%s': %v", scriptName, err),
			)

			return nil, err
		}
	}

	return result, nil
}

// UploadAllScripts uploads all Lua scripts defined in lua_scripts.go to Redis.
// This function should be called at program startup to ensure all scripts are available.
func UploadAllScripts(ctx context.Context) error {
	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, "Uploading all Redis Lua scripts",
	)

	for scriptName, scriptContent := range LuaScripts {
		_, err := UploadScript(ctx, scriptName, scriptContent)
		if err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Failed to upload Redis Lua script '%s': %v", scriptName, err),
			)

			return err
		}
	}

	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("Successfully uploaded %d Redis Lua scripts", len(LuaScripts)),
	)

	return nil
}
