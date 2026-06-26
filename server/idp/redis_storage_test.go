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
	fixture := newRedisTokenStorageFixture()

	t.Run("StoreSession", func(t *testing.T) {
		assertStoreSession(t, fixture)
	})

	t.Run("GetSession", func(t *testing.T) {
		assertGetSession(t, fixture)
	})

	t.Run("DeleteSession", func(t *testing.T) {
		assertDeleteSession(t, fixture)
	})

	t.Run("DeleteUserRefreshTokens", func(t *testing.T) {
		assertDeleteUserTokens(t, fixture.mock, fixture.prefix, "refresh_token", "user_refresh_tokens", []string{"rt1", "rt2"}, fixture.storage.DeleteUserRefreshTokens)
	})

	t.Run("DenyJWTAccessToken", func(t *testing.T) {
		assertDenyJWTAccessToken(t, fixture)
	})

	t.Run("DenyJWTAccessToken_EmptyToken", func(t *testing.T) {
		assertDenyJWTAccessTokenNoop(t, fixture, "", time.Hour)
	})

	t.Run("DenyJWTAccessToken_ZeroTTL", func(t *testing.T) {
		assertDenyJWTAccessTokenNoop(t, fixture, "some-token", 0)
	})

	t.Run("IsJWTAccessTokenDenied_True", func(t *testing.T) {
		assertJWTAccessTokenDenied(t, fixture, "denied-jwt-token", true)
	})

	t.Run("IsJWTAccessTokenDenied_False", func(t *testing.T) {
		assertJWTAccessTokenDenied(t, fixture, "valid-jwt-token", false)
	})

	t.Run("DeleteUserAccessTokens", func(t *testing.T) {
		assertDeleteUserTokens(t, fixture.mock, fixture.prefix, "access_token", "user_access_tokens", []string{"at1", "at2"}, fixture.storage.DeleteUserAccessTokens)
	})

	t.Run("DeleteUserAccessTokens_EmptyUser", func(t *testing.T) {
		assertDeleteUserAccessTokensEmptyUser(t, fixture)
	})

	t.Run("DeleteUserAccessTokens_NoTokens", func(t *testing.T) {
		assertDeleteUserAccessTokensNoTokens(t, fixture)
	})

	t.Run("FlushUserTokens", func(t *testing.T) {
		assertFlushUserTokens(t, fixture)
	})

	t.Run("FlushUserTokens_EmptyUser", func(t *testing.T) {
		assertFlushUserTokensEmptyUser(t, fixture)
	})
}

type redisTokenStorageFixture struct {
	storage *RedisTokenStorage
	mock    redismock.ClientMock
	ctx     context.Context
	prefix  string
}

// newRedisTokenStorageFixture builds a mocked Redis token storage fixture.
func newRedisTokenStorageFixture() redisTokenStorageFixture {
	db, mock := redismock.NewClientMock()
	client := rediscli.NewTestClient(db)
	prefix := "test:"

	return redisTokenStorageFixture{
		storage: NewRedisTokenStorage(client, prefix),
		mock:    mock,
		ctx:     context.Background(),
		prefix:  prefix,
	}
}

// assertStoreSession verifies authorization-code session storage.
func assertStoreSession(t *testing.T, fixture redisTokenStorageFixture) {
	t.Helper()

	code := "test-code"
	session := &OIDCSession{
		ClientID: "test-client",
		UserID:   "user123",
	}
	ttl := time.Minute
	key := fixture.prefix + "oidc:code:" + code

	data, _ := json.Marshal(session)
	fixture.mock.ExpectSet(key, string(data), ttl).SetVal("OK")

	err := fixture.storage.StoreSession(fixture.ctx, code, session, ttl)
	assert.NoError(t, err)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

// assertGetSession verifies authorization-code session retrieval.
func assertGetSession(t *testing.T, fixture redisTokenStorageFixture) {
	t.Helper()

	code := "test-code"
	session := &OIDCSession{
		ClientID: "test-client",
		UserID:   "user123",
	}
	key := fixture.prefix + "oidc:code:" + code

	data, _ := json.Marshal(session)
	fixture.mock.ExpectGet(key).SetVal(string(data))

	retrieved, err := fixture.storage.GetSession(fixture.ctx, code)
	assert.NoError(t, err)
	assert.Equal(t, session.ClientID, retrieved.ClientID)
	assert.Equal(t, session.UserID, retrieved.UserID)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

// assertDeleteSession verifies authorization-code session deletion.
func assertDeleteSession(t *testing.T, fixture redisTokenStorageFixture) {
	t.Helper()

	code := "test-code"
	key := fixture.prefix + "oidc:code:" + code

	fixture.mock.ExpectDel(key).SetVal(1)

	err := fixture.storage.DeleteSession(fixture.ctx, code)
	assert.NoError(t, err)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

// assertDenyJWTAccessToken verifies storing a denied JWT access token.
func assertDenyJWTAccessToken(t *testing.T, fixture redisTokenStorageFixture) {
	t.Helper()

	token := "header.payload.signature"
	ttl := 2 * time.Hour
	key := fixture.prefix + "oidc:denied_access_token:" + token

	fixture.mock.ExpectSet(key, "1", ttl).SetVal("OK")

	err := fixture.storage.DenyJWTAccessToken(fixture.ctx, token, ttl)
	assert.NoError(t, err)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

// assertDenyJWTAccessTokenNoop verifies no-op denial inputs.
func assertDenyJWTAccessTokenNoop(t *testing.T, fixture redisTokenStorageFixture, token string, ttl time.Duration) {
	t.Helper()

	err := fixture.storage.DenyJWTAccessToken(fixture.ctx, token, ttl)
	assert.NoError(t, err)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

// assertJWTAccessTokenDenied verifies denied-token lookup behavior.
func assertJWTAccessTokenDenied(t *testing.T, fixture redisTokenStorageFixture, token string, want bool) {
	t.Helper()

	key := fixture.prefix + "oidc:denied_access_token:" + token
	if want {
		fixture.mock.ExpectGet(key).SetVal("1")
	} else {
		fixture.mock.ExpectGet(key).RedisNil()
	}

	denied := fixture.storage.IsJWTAccessTokenDenied(fixture.ctx, token)
	assert.Equal(t, want, denied)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

// assertDeleteUserAccessTokensEmptyUser verifies no-op deletion for empty users.
func assertDeleteUserAccessTokensEmptyUser(t *testing.T, fixture redisTokenStorageFixture) {
	t.Helper()

	err := fixture.storage.DeleteUserAccessTokens(fixture.ctx, "")
	assert.NoError(t, err)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

// assertDeleteUserAccessTokensNoTokens verifies deletion when the user set is empty.
func assertDeleteUserAccessTokensNoTokens(t *testing.T, fixture redisTokenStorageFixture) {
	t.Helper()

	userID := "user-no-tokens"
	userKey := fixture.prefix + "oidc:user_access_tokens:" + userID

	fixture.mock.ExpectSMembers(userKey).SetVal([]string{})

	err := fixture.storage.DeleteUserAccessTokens(fixture.ctx, userID)
	assert.NoError(t, err)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

// assertFlushUserTokens verifies access and refresh token cleanup for a user.
func assertFlushUserTokens(t *testing.T, fixture redisTokenStorageFixture) {
	t.Helper()

	userID := "user-flush"
	accessKey := fixture.prefix + "oidc:user_access_tokens:" + userID
	refreshKey := fixture.prefix + "oidc:user_refresh_tokens:" + userID

	fixture.mock.ExpectSMembers(accessKey).SetVal([]string{"at1"})
	fixture.mock.ExpectDel(fixture.prefix + "oidc:access_token:at1").SetVal(1)
	fixture.mock.ExpectDel(accessKey).SetVal(1)
	fixture.mock.ExpectSMembers(refreshKey).SetVal([]string{"rt1"})
	fixture.mock.ExpectDel(fixture.prefix + "oidc:refresh_token:rt1").SetVal(1)
	fixture.mock.ExpectDel(refreshKey).SetVal(1)

	err := fixture.storage.FlushUserTokens(fixture.ctx, userID)
	assert.NoError(t, err)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

// assertFlushUserTokensEmptyUser verifies no-op flush for empty users.
func assertFlushUserTokensEmptyUser(t *testing.T, fixture redisTokenStorageFixture) {
	t.Helper()

	err := fixture.storage.FlushUserTokens(fixture.ctx, "")
	assert.NoError(t, err)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

func TestRedisTokenStorageUsesConfiguredRedisDeadlines(t *testing.T) {
	storage := NewRedisTokenStorage(nil, "test:")
	storage.cfg = newRedisReadDeadlineTestConfig(25 * time.Millisecond)

	assertConfiguredRedisReadDeadline(t, storage, 25*time.Millisecond)
}

func TestRefreshTokenUserIndexTTLTracksTokenLifetime(t *testing.T) {
	fixture := newRedisTokenStorageFixture()
	token := "long-lived-refresh"
	userID := "user-long-lived"
	userKey := fixture.prefix + "oidc:user_refresh_tokens:" + userID
	ttl := 45 * 24 * time.Hour
	session := &OIDCSession{
		ClientID: "test-client",
		UserID:   userID,
	}
	data, _ := json.Marshal(session)

	fixture.mock.ExpectSet(fixture.prefix+"oidc:refresh_token:"+token, string(data), ttl).SetVal("OK")
	fixture.mock.ExpectSAdd(userKey, token).SetVal(1)
	fixture.mock.ExpectExpireNX(userKey, ttl).SetVal(true)
	fixture.mock.ExpectExpireGT(userKey, ttl).SetVal(false)

	err := fixture.storage.StoreRefreshToken(fixture.ctx, token, session, ttl)
	assert.NoError(t, err)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

func TestDeleteUserRefreshTokensAfterFormerIndexBoundary(t *testing.T) {
	fixture := newRedisTokenStorageFixture()
	token := "survives-old-index-boundary"
	userID := "user-revocation"
	userKey := fixture.prefix + "oidc:user_refresh_tokens:" + userID
	ttl := 45 * 24 * time.Hour
	session := &OIDCSession{
		ClientID: "test-client",
		UserID:   userID,
	}
	data, _ := json.Marshal(session)

	fixture.mock.ExpectSet(fixture.prefix+"oidc:refresh_token:"+token, string(data), ttl).SetVal("OK")
	fixture.mock.ExpectSAdd(userKey, token).SetVal(1)
	fixture.mock.ExpectExpireNX(userKey, ttl).SetVal(true)
	fixture.mock.ExpectExpireGT(userKey, ttl).SetVal(false)
	fixture.mock.ExpectSMembers(userKey).SetVal([]string{token})
	fixture.mock.ExpectDel(fixture.prefix + "oidc:refresh_token:" + token).SetVal(1)
	fixture.mock.ExpectDel(userKey).SetVal(1)

	err := fixture.storage.StoreRefreshToken(fixture.ctx, token, session, ttl)
	assert.NoError(t, err)

	err = fixture.storage.DeleteUserRefreshTokens(fixture.ctx, userID)
	assert.NoError(t, err)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

type redisReadDeadlineProvider interface {
	redisReadContext(context.Context) (context.Context, context.CancelFunc)
}

// newRedisReadDeadlineTestConfig creates a config with only RedisRead populated.
func newRedisReadDeadlineTestConfig(timeout time.Duration) *config.FileSettings {
	return &config.FileSettings{
		Server: &config.ServerSection{
			Timeouts: config.Timeouts{
				RedisRead: timeout,
			},
		},
	}
}

// assertConfiguredRedisReadDeadline verifies that a storage type applies the configured Redis read timeout.
func assertConfiguredRedisReadDeadline(t *testing.T, provider redisReadDeadlineProvider, timeout time.Duration) {
	t.Helper()

	readCtx, cancel := provider.redisReadContext(context.Background())
	defer cancel()

	deadline, ok := readCtx.Deadline()

	assert.True(t, ok, "expected Redis read context to carry a deadline")
	assert.WithinDuration(t, time.Now().Add(timeout), deadline, 10*time.Millisecond)
}

// assertDeleteUserTokens verifies deletion of all tracked tokens for one user.
func assertDeleteUserTokens(
	t *testing.T,
	mock redismock.ClientMock,
	prefix string,
	tokenKind string,
	userSetKind string,
	tokens []string,
	deleteUserTokens func(context.Context, string) error,
) {
	t.Helper()

	userID := "user123"
	userKey := prefix + "oidc:" + userSetKind + ":" + userID

	mock.ExpectSMembers(userKey).SetVal(tokens)

	for _, token := range tokens {
		mock.ExpectDel(prefix + "oidc:" + tokenKind + ":" + token).SetVal(1)
	}

	mock.ExpectDel(userKey).SetVal(1)

	err := deleteUserTokens(context.Background(), userID)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
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
