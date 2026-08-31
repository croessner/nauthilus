// Copyright (C) 2026 Christian Rößner
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

package callerauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/redis/go-redis/v9"
)

const (
	defaultRedisBasicFailures     int64 = 5
	defaultRedisBasicTTL                = 5 * time.Minute
	maximumRedisBasicFailures     int64 = 1000
	maximumRedisBasicTTL                = 24 * time.Hour
	redisBasicThrottlePrefix            = "nauthilus:policy:basic:{"
	redisBasicThrottleKeyDomain         = "nauthilus-policy-basic-throttle-v1"
	redisBasicFailureScriptSource       = `
local current = tonumber(redis.call("GET", KEYS[1]) or "0")
local maximum = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])

if current >= maximum then
  redis.call("PEXPIRE", KEYS[1], ttl)
  return maximum
end

current = redis.call("INCR", KEYS[1])
redis.call("PEXPIRE", KEYS[1], ttl)

if current > maximum then
  redis.call("SET", KEYS[1], maximum, "PX", ttl)
  return maximum
end

return current
`
)

// RedisBasicThrottler owns bounded Policy-Basic failure state over one explicit Redis dependency.
type RedisBasicThrottler struct {
	client        rediscli.Client
	handle        redis.UniversalClient
	failureScript *redis.Script
	maxFailures   int64
	ttlMillis     int64
}

var _ BasicThrottler = (*RedisBasicThrottler)(nil)

// NewDefaultRedisBasicThrottler retains the managed Redis facade with finite code-owned bounds.
func NewDefaultRedisBasicThrottler(client rediscli.Client) (*RedisBasicThrottler, error) {
	if client == nil || typedNilInterface(client) {
		return nil, configurationError("Policy-Basic throttler requires a Redis client")
	}

	return newRedisBasicThrottler(client, client.GetWriteHandle(), defaultRedisBasicFailures, defaultRedisBasicTTL)
}

// NewRedisBasicThrottler validates and captures one Redis handle and bounded failure window.
func NewRedisBasicThrottler(
	handle redis.UniversalClient,
	maxFailures int64,
	ttl time.Duration,
) (*RedisBasicThrottler, error) {
	return newRedisBasicThrottler(nil, handle, maxFailures, ttl)
}

// newRedisBasicThrottler validates one explicit Redis source and bounded failure window.
func newRedisBasicThrottler(
	client rediscli.Client,
	handle redis.UniversalClient,
	maxFailures int64,
	ttl time.Duration,
) (*RedisBasicThrottler, error) {
	if handle == nil || typedNilInterface(handle) {
		return nil, configurationError("Policy-Basic throttler requires a Redis write handle")
	}

	if maxFailures <= 0 || maxFailures > maximumRedisBasicFailures {
		return nil, configurationError("Policy-Basic throttle failure bound is invalid")
	}

	ttlMillis := ttl.Milliseconds()
	if ttlMillis <= 0 || ttl > maximumRedisBasicTTL {
		return nil, configurationError("Policy-Basic throttle TTL is invalid")
	}

	return &RedisBasicThrottler{
		client:        client,
		handle:        handle,
		failureScript: redis.NewScript(redisBasicFailureScriptSource),
		maxFailures:   maxFailures,
		ttlMillis:     ttlMillis,
	}, nil
}

// BeforeAttempt rejects identities whose bounded Redis failure window is full.
func (t *RedisBasicThrottler) BeforeAttempt(ctx context.Context, key BasicThrottleKey) error {
	handle := t.writeHandle()
	if handle == nil || ctx == nil {
		return ErrBasicThrottleState
	}

	count, err := handle.Get(ctx, redisBasicThrottleKey(key)).Int64()
	if errors.Is(err, redis.Nil) {
		return nil
	}

	if err != nil {
		return err
	}

	if count < 0 {
		return ErrBasicThrottleState
	}

	if count >= t.maxFailures {
		return ErrBasicThrottleLimit
	}

	return nil
}

// RecordFailure atomically increments, caps, and refreshes one failure window.
func (t *RedisBasicThrottler) RecordFailure(ctx context.Context, key BasicThrottleKey) error {
	handle := t.writeHandle()
	if handle == nil || t.failureScript == nil || ctx == nil {
		return ErrBasicThrottleState
	}

	count, err := t.failureScript.Run(
		ctx,
		handle,
		[]string{redisBasicThrottleKey(key)},
		t.maxFailures,
		t.ttlMillis,
	).Int64()
	if err != nil {
		return err
	}

	if count <= 0 || count > t.maxFailures {
		return ErrBasicThrottleState
	}

	return nil
}

// RecordSuccess clears the complete failure window after accepted Policy-Basic evidence.
func (t *RedisBasicThrottler) RecordSuccess(ctx context.Context, key BasicThrottleKey) error {
	handle := t.writeHandle()
	if handle == nil || ctx == nil {
		return ErrBasicThrottleState
	}

	return handle.Del(ctx, redisBasicThrottleKey(key)).Err()
}

// writeHandle resolves the active handle through the injected managed facade when available.
func (t *RedisBasicThrottler) writeHandle() redis.UniversalClient {
	if t == nil {
		return nil
	}

	if t.client != nil && !typedNilInterface(t.client) {
		return t.client.GetWriteHandle()
	}

	return t.handle
}

// redisBasicThrottleKey reduces all caller evidence to one fixed-size cluster-safe digest key.
func redisBasicThrottleKey(key BasicThrottleKey) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(redisBasicThrottleKeyDomain))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write(key.identityDigest[:])
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(key.peer))

	return redisBasicThrottlePrefix + hex.EncodeToString(hasher.Sum(nil)) + "}"
}
