// Copyright (C) 2026 Christian Roessner
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

package pluginruntime

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/rediscli"

	"github.com/redis/go-redis/v9"
)

var _ pluginapi.Redis = (*redisFacade)(nil)

const defaultPluginScriptHashTag = "{nauthilus-plugin}"

var redisScriptNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

// RedisFacadeOption customizes the Redis facade.
type RedisFacadeOption func(*redisFacade)

// NewRedisFacade exposes read and write handles from the host Redis client.
func NewRedisFacade(client rediscli.Client, options ...RedisFacadeOption) pluginapi.Redis {
	if client == nil {
		return nil
	}

	facade := &redisFacade{
		client: client,
		keys:   newRedisKeyBuilder(""),
	}
	facade.scripts = newRedisScriptRegistry(client, 5*time.Second)

	for _, option := range options {
		option(facade)
	}

	return facade
}

// RedisFacadePrefix configures the Redis key prefix applied by the key builder.
func RedisFacadePrefix(prefix string) RedisFacadeOption {
	return func(facade *redisFacade) {
		if facade == nil {
			return
		}

		facade.keys = newRedisKeyBuilder(prefix)
	}
}

// RedisFacadeScriptTimeout configures the default timeout for script operations.
func RedisFacadeScriptTimeout(timeout time.Duration) RedisFacadeOption {
	return func(facade *redisFacade) {
		if facade == nil || timeout <= 0 {
			return
		}

		facade.scripts = newRedisScriptRegistry(facade.client, timeout)
	}
}

type redisFacade struct {
	scripts pluginapi.RedisScriptRegistry
	client  rediscli.Client
	keys    pluginapi.RedisKeyBuilder
}

// Read returns the host-selected read Redis handle.
func (r *redisFacade) Read() redis.Cmdable {
	if r == nil || r.client == nil {
		return nil
	}

	return r.client.GetReadHandle()
}

// Write returns the host write Redis handle.
func (r *redisFacade) Write() redis.Cmdable {
	if r == nil || r.client == nil {
		return nil
	}

	return r.client.GetWriteHandle()
}

// ReadPipeline returns a host read pipeline.
func (r *redisFacade) ReadPipeline() redis.Pipeliner {
	if r == nil || r.client == nil {
		return nil
	}

	return r.client.GetReadPipeline()
}

// WritePipeline returns a host write pipeline.
func (r *redisFacade) WritePipeline() redis.Pipeliner {
	if r == nil || r.client == nil {
		return nil
	}

	return r.client.GetWritePipeline()
}

// Keys returns the host-owned Redis key builder.
func (r *redisFacade) Keys() pluginapi.RedisKeyBuilder {
	if r == nil || r.keys == nil {
		return newRedisKeyBuilder("")
	}

	return r.keys
}

// Scripts returns the host-owned named Redis script registry.
func (r *redisFacade) Scripts() pluginapi.RedisScriptRegistry {
	if r == nil || r.scripts == nil {
		return newRedisScriptRegistry(nil, 0)
	}

	return r.scripts
}

type redisKeyBuilder struct {
	prefix string
}

// newRedisKeyBuilder returns a Redis key builder for one configured prefix.
func newRedisKeyBuilder(prefix string) pluginapi.RedisKeyBuilder {
	return redisKeyBuilder{prefix: prefix}
}

// Key applies the configured Redis prefix to one key.
func (b redisKeyBuilder) Key(key string) string {
	return rediscli.BuildKey(b.prefix, key)
}

// Keys applies the configured Redis prefix to all keys.
func (b redisKeyBuilder) Keys(keys ...string) []string {
	return rediscli.BuildKeys(b.prefix, keys)
}

// SameSlot returns keys adjusted to share the same Redis Cluster hash slot.
func (b redisKeyBuilder) SameSlot(keys []string, hashTag string) []string {
	return rediscli.EnsureKeysInSameSlot(keys, normalizeHashTag(hashTag))
}

type redisScriptRegistry struct {
	client  rediscli.Client
	timeout time.Duration
	scripts map[string]registeredRedisScript
	mu      sync.RWMutex
}

type registeredRedisScript struct {
	source string
	sha    string
}

// newRedisScriptRegistry creates a named script registry for a Redis facade.
func newRedisScriptRegistry(client rediscli.Client, timeout time.Duration) pluginapi.RedisScriptRegistry {
	return &redisScriptRegistry{
		client:  client,
		timeout: timeout,
		scripts: make(map[string]registeredRedisScript),
	}
}

// Upload loads source into Redis and stores SHA plus source under name.
func (r *redisScriptRegistry) Upload(ctx context.Context, name string, source string) (string, error) {
	if err := validateRedisScript(name, source); err != nil {
		return "", err
	}

	if r == nil || r.client == nil || r.client.GetWriteHandle() == nil {
		return "", fmt.Errorf("redis script registry unavailable")
	}

	ctx, cancel := r.operationContext(ctx)
	defer cancel()

	sha, err := r.loadScript(ctx, source)
	if err != nil {
		return "", err
	}

	r.mu.Lock()
	r.scripts[name] = registeredRedisScript{source: source, sha: sha}
	r.mu.Unlock()

	return sha, nil
}

// Run executes a previously uploaded script by name.
func (r *redisScriptRegistry) Run(ctx context.Context, name string, keys []string, args ...any) (any, error) {
	if !redisScriptNamePattern.MatchString(name) {
		return nil, fmt.Errorf("%w: %q", pluginapi.ErrInvalidRedisScriptName, name)
	}

	script, ok := r.getScript(name)
	if !ok {
		return nil, fmt.Errorf("%w: %q", pluginapi.ErrRedisScriptNotFound, name)
	}

	if r == nil || r.client == nil || r.client.GetWriteHandle() == nil {
		return nil, fmt.Errorf("redis script registry unavailable")
	}

	ctx, cancel := r.operationContext(ctx)
	defer cancel()

	writeHandle := r.client.GetWriteHandle()
	if rediscli.IsClusterClient(writeHandle) && len(keys) > 1 {
		keys = rediscli.EnsureKeysInSameSlot(keys, defaultPluginScriptHashTag)
	}

	result, err := writeHandle.EvalSha(ctx, script.sha, keys, args...).Result()
	if isRedisNoScript(err) {
		return r.reloadAndRun(ctx, name, script.source, keys, args...)
	}

	if isRedisCrossSlot(err) {
		keys = rediscli.EnsureKeysInSameSlot(keys, defaultPluginScriptHashTag)
		result, err = writeHandle.EvalSha(ctx, script.sha, keys, args...).Result()

		if isRedisNoScript(err) {
			return r.reloadAndRun(ctx, name, script.source, keys, args...)
		}
	}

	return result, err
}

// getScript returns a copy of the registered script metadata.
func (r *redisScriptRegistry) getScript(name string) (registeredRedisScript, bool) {
	if r == nil {
		return registeredRedisScript{}, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	script, ok := r.scripts[name]

	return script, ok
}

// loadScript loads source on the write handle and best-effort read handles.
func (r *redisScriptRegistry) loadScript(ctx context.Context, source string) (string, error) {
	sha, err := r.client.GetWriteHandle().ScriptLoad(ctx, source).Result()
	if err != nil {
		return "", err
	}

	for _, readHandle := range r.client.GetReadHandles() {
		_, _ = readHandle.ScriptLoad(ctx, source).Result()
	}

	return sha, nil
}

// operationContext applies a default timeout when the caller did not set one.
func (r *redisScriptRegistry) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}

	if r == nil || r.timeout <= 0 {
		return ctx, func() {}
	}

	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}

	return context.WithTimeout(ctx, r.timeout)
}

// reloadAndRun restores a named script after Redis lost its script cache and retries once.
func (r *redisScriptRegistry) reloadAndRun(ctx context.Context, name string, source string, keys []string, args ...any) (any, error) {
	sha, err := r.loadScript(ctx, source)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	r.scripts[name] = registeredRedisScript{source: source, sha: sha}
	r.mu.Unlock()

	return r.client.GetWriteHandle().EvalSha(ctx, sha, keys, args...).Result()
}

// validateRedisScript checks that name is stable and source can restore NOSCRIPT state.
func validateRedisScript(name string, source string) error {
	if !redisScriptNamePattern.MatchString(name) {
		return fmt.Errorf("%w: %q", pluginapi.ErrInvalidRedisScriptName, name)
	}

	if strings.TrimSpace(source) == "" {
		return fmt.Errorf("redis script source is empty")
	}

	return nil
}

// normalizeHashTag ensures the caller-provided hash tag is wrapped for Redis Cluster.
func normalizeHashTag(hashTag string) string {
	hashTag = strings.TrimSpace(hashTag)
	if hashTag == "" {
		return defaultPluginScriptHashTag
	}

	if strings.HasPrefix(hashTag, "{") && strings.HasSuffix(hashTag, "}") {
		return hashTag
	}

	return "{" + hashTag + "}"
}

// isRedisNoScript reports whether Redis returned a NOSCRIPT error.
func isRedisNoScript(err error) bool {
	return err != nil && strings.HasPrefix(strings.ToUpper(err.Error()), "NOSCRIPT")
}

// isRedisCrossSlot reports whether Redis rejected a multi-key script across slots.
func isRedisCrossSlot(err error) bool {
	return err != nil && strings.Contains(err.Error(), "CROSSSLOT")
}
