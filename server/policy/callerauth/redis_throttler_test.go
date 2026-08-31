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
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	redismock "github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
)

const (
	policyThrottlePeer     = "192.0.2.44"
	policyThrottleUsername = "private-policy-user"
)

func TestRedisBasicThrottlerRejectsInvalidConstruction(t *testing.T) {
	t.Parallel()

	var typedNilHandle *redis.Client

	tests := []struct {
		name        string
		handle      redis.UniversalClient
		maxFailures int64
		ttl         time.Duration
	}{
		{name: "missing handle", maxFailures: 1, ttl: time.Second},
		{name: "typed nil handle", handle: typedNilHandle, maxFailures: 1, ttl: time.Second},
		{name: "zero failures", handle: redismockHandle(t), ttl: time.Second},
		{name: "excessive failures", handle: redismockHandle(t), maxFailures: maximumRedisBasicFailures + 1, ttl: time.Second},
		{name: "zero ttl", handle: redismockHandle(t), maxFailures: 1},
		{name: "excessive ttl", handle: redismockHandle(t), maxFailures: 1, ttl: maximumRedisBasicTTL + time.Millisecond},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			throttler, err := NewRedisBasicThrottler(test.handle, test.maxFailures, test.ttl)
			if throttler != nil || !errors.Is(err, ErrConfiguration) {
				t.Fatalf("NewRedisBasicThrottler() = %T, %v", throttler, err)
			}
		})
	}
}

func TestDefaultRedisBasicThrottlerCapturesInjectedWriteHandle(t *testing.T) {
	t.Parallel()

	db, _ := redismock.NewClientMock()
	client := &policyRedisClient{handle: db}

	throttler, err := NewDefaultRedisBasicThrottler(client)
	if err != nil {
		t.Fatalf("NewDefaultRedisBasicThrottler() error = %v", err)
	}

	if throttler.client != client || throttler.writeHandle() != db || throttler.maxFailures != defaultRedisBasicFailures || throttler.ttlMillis != defaultRedisBasicTTL.Milliseconds() {
		t.Fatalf("default throttler did not capture the injected bounded dependency")
	}
}

func TestDefaultRedisBasicThrottlerFollowsInjectedManagedClientSwap(t *testing.T) {
	t.Parallel()

	first, firstMock := redismock.NewClientMock()
	second, secondMock := redismock.NewClientMock()
	client := &policyRedisClient{handle: first}

	throttler, err := NewDefaultRedisBasicThrottler(client)
	if err != nil {
		t.Fatalf("NewDefaultRedisBasicThrottler() error = %v", err)
	}

	client.handle = second
	key := redisBasicThrottleKey(policyRedisThrottleKey())
	secondMock.ExpectGet(key).RedisNil()

	if err = throttler.BeforeAttempt(t.Context(), policyRedisThrottleKey()); err != nil {
		t.Fatalf("BeforeAttempt() after managed client swap = %v", err)
	}

	if err = firstMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("retired Redis handle was used: %v", err)
	}

	if err = secondMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("active Redis handle expectations: %v", err)
	}
}

func TestRedisBasicThrottlerUsesSecretFreeFixedKey(t *testing.T) {
	t.Parallel()

	key := BasicThrottleKey{
		peer:           policyThrottlePeer,
		identityDigest: sha256.Sum256([]byte(policyThrottleUsername)),
	}
	redisKey := redisBasicThrottleKey(key)

	if strings.Contains(redisKey, policyThrottlePeer) || strings.Contains(redisKey, policyThrottleUsername) {
		t.Fatalf("Redis key exposed caller evidence: %q", redisKey)
	}

	if len(redisKey) != len(redisBasicThrottlePrefix)+sha256.Size*2+1 {
		t.Fatalf("Redis key length = %d, want fixed digest form", len(redisKey))
	}
}

func TestRedisBasicThrottlerBoundsFailuresAndClearsSuccess(t *testing.T) {
	t.Parallel()

	db, mock := redismock.NewClientMock()
	throttler := mustRedisBasicThrottler(t, db, 2, 90*time.Second)
	key := redisBasicThrottleKey(policyRedisThrottleKey())

	mock.ExpectGet(key).RedisNil()

	if err := throttler.BeforeAttempt(context.Background(), policyRedisThrottleKey()); err != nil {
		t.Fatalf("BeforeAttempt() initial error = %v", err)
	}

	mock.ExpectEvalSha(throttler.failureScript.Hash(), []string{key}, int64(2), int64(90000)).SetVal(int64(1))

	if err := throttler.RecordFailure(context.Background(), policyRedisThrottleKey()); err != nil {
		t.Fatalf("RecordFailure() first error = %v", err)
	}

	mock.ExpectEvalSha(throttler.failureScript.Hash(), []string{key}, int64(2), int64(90000)).SetVal(int64(2))

	if err := throttler.RecordFailure(context.Background(), policyRedisThrottleKey()); err != nil {
		t.Fatalf("RecordFailure() second error = %v", err)
	}

	mock.ExpectGet(key).SetVal("2")

	if err := throttler.BeforeAttempt(context.Background(), policyRedisThrottleKey()); !errors.Is(err, ErrBasicThrottleLimit) {
		t.Fatalf("BeforeAttempt() bounded error = %v, want ErrBasicThrottleLimit", err)
	}

	mock.ExpectDel(key).SetVal(1)

	if err := throttler.RecordSuccess(context.Background(), policyRedisThrottleKey()); err != nil {
		t.Fatalf("RecordSuccess() error = %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis expectations: %v", err)
	}
}

func TestRedisBasicThrottlerEnforcesAtomicSlidingWindow(t *testing.T) {
	t.Parallel()

	server := miniredis.RunT(t)
	db := redis.NewClient(&redis.Options{Addr: server.Addr()})

	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close Redis client: %v", err)
		}
	})

	throttler := mustRedisBasicThrottler(t, db, 2, 90*time.Second)
	key := policyRedisThrottleKey()

	if err := throttler.RecordFailure(context.Background(), key); err != nil {
		t.Fatalf("RecordFailure() first error = %v", err)
	}

	server.FastForward(89 * time.Second)

	if err := throttler.RecordFailure(context.Background(), key); err != nil {
		t.Fatalf("RecordFailure() second error = %v", err)
	}

	if err := throttler.RecordFailure(context.Background(), key); err != nil {
		t.Fatalf("RecordFailure() bounded repeat error = %v", err)
	}

	count, err := db.Get(context.Background(), redisBasicThrottleKey(key)).Int64()
	if err != nil || count != 2 {
		t.Fatalf("bounded failure count = %d, %v, want 2", count, err)
	}

	server.FastForward(2 * time.Second)

	if err = throttler.BeforeAttempt(context.Background(), key); !errors.Is(err, ErrBasicThrottleLimit) {
		t.Fatalf("BeforeAttempt() after refreshed TTL = %v, want limit", err)
	}

	server.FastForward(89 * time.Second)

	if err = throttler.BeforeAttempt(context.Background(), key); err != nil {
		t.Fatalf("BeforeAttempt() after expiry = %v", err)
	}

	if err = throttler.RecordFailure(context.Background(), key); err != nil {
		t.Fatalf("RecordFailure() after expiry = %v", err)
	}

	if err = throttler.RecordSuccess(context.Background(), key); err != nil {
		t.Fatalf("RecordSuccess() error = %v", err)
	}

	if server.Exists(redisBasicThrottleKey(key)) {
		t.Fatal("successful Policy-Basic authentication retained failure state")
	}
}

func TestRedisBasicThrottlerPropagatesStateErrorsExactly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		invoke func(*RedisBasicThrottler, redismock.ClientMock, string) error
	}{
		{
			name: "gate",
			invoke: func(throttler *RedisBasicThrottler, mock redismock.ClientMock, key string) error {
				stateErr := errors.New("gate state unavailable")
				mock.ExpectGet(key).SetErr(stateErr)

				return requireExactThrottleError(t, stateErr, throttler.BeforeAttempt(context.Background(), policyRedisThrottleKey()))
			},
		},
		{
			name: "failure",
			invoke: func(throttler *RedisBasicThrottler, mock redismock.ClientMock, key string) error {
				stateErr := errors.New("failure state unavailable")
				mock.ExpectEvalSha(throttler.failureScript.Hash(), []string{key}, int64(2), int64(90000)).SetErr(stateErr)

				return requireExactThrottleError(t, stateErr, throttler.RecordFailure(context.Background(), policyRedisThrottleKey()))
			},
		},
		{
			name: "success",
			invoke: func(throttler *RedisBasicThrottler, mock redismock.ClientMock, key string) error {
				stateErr := errors.New("success state unavailable")
				mock.ExpectDel(key).SetErr(stateErr)

				return requireExactThrottleError(t, stateErr, throttler.RecordSuccess(context.Background(), policyRedisThrottleKey()))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			db, mock := redismock.NewClientMock()
			throttler := mustRedisBasicThrottler(t, db, 2, 90*time.Second)
			key := redisBasicThrottleKey(policyRedisThrottleKey())

			if err := test.invoke(throttler, mock, key); err != nil {
				t.Fatal(err)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("Redis expectations: %v", err)
			}
		})
	}
}

// redismockHandle creates an isolated constructor-valid handle.
func redismockHandle(t *testing.T) redis.UniversalClient {
	t.Helper()

	db, _ := redismock.NewClientMock()

	return db
}

// policyRedisThrottleKey returns the stable opaque test identity.
func policyRedisThrottleKey() BasicThrottleKey {
	return BasicThrottleKey{
		peer:           policyThrottlePeer,
		identityDigest: sha256.Sum256([]byte(policyThrottleUsername)),
	}
}

// mustRedisBasicThrottler constructs the focused Redis throttle fixture.
func mustRedisBasicThrottler(
	t *testing.T,
	handle redis.UniversalClient,
	maxFailures int64,
	ttl time.Duration,
) *RedisBasicThrottler {
	t.Helper()

	throttler, err := NewRedisBasicThrottler(handle, maxFailures, ttl)
	if err != nil {
		t.Fatalf("NewRedisBasicThrottler() error = %v", err)
	}

	return throttler
}

// requireExactThrottleError compares one state error without wrapping.
func requireExactThrottleError(t *testing.T, want error, got error) error {
	t.Helper()

	if got != want {
		return errors.New("throttle state error was not propagated exactly")
	}

	return nil
}

type policyRedisClient struct {
	rediscli.Client
	handle redis.UniversalClient
}

// GetWriteHandle returns the only dependency used by the production constructor.
func (c policyRedisClient) GetWriteHandle() redis.UniversalClient {
	return c.handle
}
