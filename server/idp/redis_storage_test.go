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
		key := prefix + "nauthilus:oidc:code:" + code

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
		key := prefix + "nauthilus:oidc:code:" + code

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
		key := prefix + "nauthilus:oidc:code:" + code

		mock.ExpectDel(key).SetVal(1)

		err := storage.DeleteSession(ctx, code)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
