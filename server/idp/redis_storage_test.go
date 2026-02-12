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
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

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
}
