// Copyright (C) 2025 Christian Rößner
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

package idp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

const redisCommandSet = "set"

func TestRedisTokenStorage(t *testing.T) {
	db, mock := redismock.NewClientMock()
	client := rediscli.NewTestClient(db)
	prefix := "test:"
	storage := NewRedisTokenStorage(client, prefix)
	ctx := context.Background()

	t.Run("StoreSession", func(t *testing.T) {
		code := "test-code"
		session := &OIDCSession{
			ClientID: "test-client",
			UserID:   "user123",
		}
		ttl := time.Minute
		key := prefix + "oidc:code:" + code

		data, _ := json.Marshal(session)
		mock.ExpectSet(key, string(data), ttl).SetVal("OK")

		err := storage.StoreSession(ctx, code, session, ttl)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("GetSession", func(t *testing.T) {
		code := "test-code"
		session := &OIDCSession{
			ClientID: "test-client",
			UserID:   "user123",
		}
		key := prefix + "oidc:code:" + code

		data, _ := json.Marshal(session)
		mock.ExpectGet(key).SetVal(string(data))

		retrieved, err := storage.GetSession(ctx, code)
		assert.NoError(t, err)
		assert.Equal(t, session.ClientID, retrieved.ClientID)
		assert.Equal(t, session.UserID, retrieved.UserID)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("DeleteSession", func(t *testing.T) {
		code := "test-code"
		key := prefix + "oidc:code:" + code

		mock.ExpectDel(key).SetVal(1)

		err := storage.DeleteSession(ctx, code)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("DeleteUserRefreshTokens", func(t *testing.T) {
		userID := "user123"
		userKey := prefix + "oidc:user_refresh_tokens:" + userID
		tokens := []string{"rt1", "rt2"}

		mock.ExpectSMembers(userKey).SetVal(tokens)
		mock.ExpectDel(prefix + "oidc:refresh_token:rt1").SetVal(1)
		mock.ExpectDel(prefix + "oidc:refresh_token:rt2").SetVal(1)
		mock.ExpectDel(userKey).SetVal(1)

		err := storage.DeleteUserRefreshTokens(ctx, userID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("DenyJWTAccessToken", func(t *testing.T) {
		token := "header.payload.signature"
		ttl := 2 * time.Hour
		key := prefix + "oidc:denied_access_token:" + token

		mock.ExpectSet(key, "1", ttl).SetVal("OK")

		err := storage.DenyJWTAccessToken(ctx, token, ttl)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("DenyJWTAccessToken_EmptyToken", func(t *testing.T) {
		err := storage.DenyJWTAccessToken(ctx, "", time.Hour)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("DenyJWTAccessToken_ZeroTTL", func(t *testing.T) {
		err := storage.DenyJWTAccessToken(ctx, "some-token", 0)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("IsJWTAccessTokenDenied_True", func(t *testing.T) {
		token := "denied-jwt-token"
		key := prefix + "oidc:denied_access_token:" + token

		mock.ExpectGet(key).SetVal("1")

		denied := storage.IsJWTAccessTokenDenied(ctx, token)
		assert.True(t, denied)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("IsJWTAccessTokenDenied_False", func(t *testing.T) {
		token := "valid-jwt-token"
		key := prefix + "oidc:denied_access_token:" + token

		mock.ExpectGet(key).RedisNil()

		denied := storage.IsJWTAccessTokenDenied(ctx, token)
		assert.False(t, denied)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("DeleteUserAccessTokens", func(t *testing.T) {
		userID := "user123"
		userKey := prefix + "oidc:user_access_tokens:" + userID
		tokens := []string{"at1", "at2"}

		mock.ExpectSMembers(userKey).SetVal(tokens)
		mock.ExpectDel(prefix + "oidc:access_token:at1").SetVal(1)
		mock.ExpectDel(prefix + "oidc:access_token:at2").SetVal(1)
		mock.ExpectDel(userKey).SetVal(1)

		err := storage.DeleteUserAccessTokens(ctx, userID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("DeleteUserAccessTokens_EmptyUser", func(t *testing.T) {
		err := storage.DeleteUserAccessTokens(ctx, "")
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("DeleteUserAccessTokens_NoTokens", func(t *testing.T) {
		userID := "user-no-tokens"
		userKey := prefix + "oidc:user_access_tokens:" + userID

		mock.ExpectSMembers(userKey).SetVal([]string{})

		err := storage.DeleteUserAccessTokens(ctx, userID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("FlushUserTokens", func(t *testing.T) {
		userID := "user-flush"
		accessKey := prefix + "oidc:user_access_tokens:" + userID
		refreshKey := prefix + "oidc:user_refresh_tokens:" + userID

		// Access tokens
		mock.ExpectSMembers(accessKey).SetVal([]string{"at1"})
		mock.ExpectDel(prefix + "oidc:access_token:at1").SetVal(1)
		mock.ExpectDel(accessKey).SetVal(1)

		// Refresh tokens
		mock.ExpectSMembers(refreshKey).SetVal([]string{"rt1"})
		mock.ExpectDel(prefix + "oidc:refresh_token:rt1").SetVal(1)
		mock.ExpectDel(refreshKey).SetVal(1)

		err := storage.FlushUserTokens(ctx, userID)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("FlushUserTokens_EmptyUser", func(t *testing.T) {
		err := storage.FlushUserTokens(ctx, "")
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestRedisTokenStorageUsesConfiguredRedisDeadlines(t *testing.T) {
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Timeouts: config.Timeouts{
				RedisRead: 25 * time.Millisecond,
			},
		},
	}

	storage := NewRedisTokenStorage(nil, "test:")
	storage.cfg = cfg

	readCtx, cancel := storage.redisReadContext(context.Background())
	defer cancel()

	deadline, ok := readCtx.Deadline()

	assert.True(t, ok, "expected Redis read context to carry a deadline")
	assert.WithinDuration(t, time.Now().Add(25*time.Millisecond), deadline, 10*time.Millisecond)
}

func TestRedisTokenStorage_ReserveClientAssertionJWTID(t *testing.T) {
	const (
		prefix   = "test:"
		clientID = "client-a"
		audience = "https://issuer.example.com/oidc/token"
		jwtID    = "assertion-1"
	)

	t.Run("stores first reservation with SETNX", func(t *testing.T) {
		storage, mock := newClientAssertionReplayStorage(prefix)
		expiresAt := time.Now().Add(time.Minute)
		expectedKey := expectedClientAssertionReplayKey(prefix, clientID, audience, jwtID)

		expectClientAssertionReplaySetNX(t, mock, expectedKey, "1", 89*time.Second, 91*time.Second).SetVal(true)

		err := storage.ReserveClientAssertionJWTID(context.Background(), clientID, audience, jwtID, expiresAt)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("detects repeated reservation for same scoped tuple", func(t *testing.T) {
		storage, mock := newClientAssertionReplayStorage(prefix)
		expiresAt := time.Now().Add(time.Minute)
		expectedKey := expectedClientAssertionReplayKey(prefix, clientID, audience, jwtID)

		expectClientAssertionReplaySetNX(t, mock, expectedKey, "1", 89*time.Second, 91*time.Second).SetVal(false)

		err := storage.ReserveClientAssertionJWTID(context.Background(), clientID, audience, jwtID, expiresAt)
		assert.ErrorIs(t, err, ErrClientAssertionReplayDetected)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("maps Redis write errors to unavailable", func(t *testing.T) {
		storage, mock := newClientAssertionReplayStorage(prefix)
		expiresAt := time.Now().Add(time.Minute)
		expectedKey := expectedClientAssertionReplayKey(prefix, clientID, audience, jwtID)

		expectClientAssertionReplaySetNX(t, mock, expectedKey, "1", 89*time.Second, 91*time.Second).
			SetErr(errors.New("redis write failed"))

		err := storage.ReserveClientAssertionJWTID(context.Background(), clientID, audience, jwtID, expiresAt)
		assert.ErrorIs(t, err, ErrClientAssertionReplayUnavailable)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("hashes replay scope instead of embedding raw values", func(t *testing.T) {
		storage, _ := newClientAssertionReplayStorage(prefix)
		key := storage.clientAssertionReplayKey(clientID, audience, jwtID)

		assert.Equal(t, expectedClientAssertionReplayKey(prefix, clientID, audience, jwtID), key)
		assert.NotContains(t, key, clientID)
		assert.NotContains(t, key, audience)
		assert.NotContains(t, key, jwtID)
		assert.Regexp(t, `^test:oidc:client_assertion:replay:[0-9a-f]{64}$`, key)
	})
}

// newClientAssertionReplayStorage creates an isolated Redis storage mock for replay tests.
func newClientAssertionReplayStorage(prefix string) (*RedisTokenStorage, redismock.ClientMock) {
	db, mock := redismock.NewClientMock()
	client := rediscli.NewTestClient(db)

	return NewRedisTokenStorage(client, prefix), mock
}

// expectedClientAssertionReplayKey mirrors the documented replay scope hash.
func expectedClientAssertionReplayKey(prefix string, clientID string, audience string, jwtID string) string {
	replayScope := clientID + "\x1f" + audience + "\x1f" + jwtID
	sum := sha256.Sum256([]byte(replayScope))

	return prefix + "oidc:client_assertion:replay:" + hex.EncodeToString(sum[:])
}

// expectClientAssertionReplaySetNX matches replay SETNX calls with a tolerant TTL window.
func expectClientAssertionReplaySetNX(
	t testing.TB,
	mock redismock.ClientMock,
	key string,
	value string,
	minTTL time.Duration,
	maxTTL time.Duration,
) *redismock.ExpectedBool {
	t.Helper()

	return mock.CustomMatch(func(_ []any, actual []any) error {
		if len(actual) != 6 {
			return fmt.Errorf("unexpected Redis command args: %v", actual)
		}

		if actual[0] != redisCommandSet || actual[1] != key || actual[2] != value || actual[3] != "px" || actual[5] != "nx" {
			return fmt.Errorf("unexpected Redis SETNX command args: %v", actual)
		}

		ttlMillis, ok := actual[4].(int64)
		if !ok {
			return fmt.Errorf("unexpected Redis TTL type %T", actual[4])
		}

		ttl := time.Duration(ttlMillis) * time.Millisecond
		if ttl < minTTL || ttl > maxTTL {
			return fmt.Errorf("unexpected Redis TTL %s, want between %s and %s", ttl, minTTL, maxTTL)
		}

		return nil
	}).ExpectSetNX(key, value, minTTL)
}
