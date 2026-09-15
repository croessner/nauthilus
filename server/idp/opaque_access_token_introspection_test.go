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

package idp

import (
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

func TestOpaqueAccessTokenIntrospectionExpiry(t *testing.T) {
	expires := time.Now().Add(time.Hour).Truncate(time.Second)
	token := &OpaqueAccessToken{}
	claims := token.ClaimsFromSession(&OIDCSession{AccessTokenExpiresAt: expires})
	assert.Equal(t, expires.Unix(), claims["exp"])
}

func TestOpaqueServiceTokenPersistsIntrospectionExpiry(t *testing.T) {
	db, mock := redismock.NewClientMock()
	client := rediscli.NewTestClient(db)
	session := &OIDCSession{ClientID: "caller", UserID: "caller", ServiceToken: true, AccessTokenIssuer: "https://issuer.example"}
	storage := NewRedisTokenStorage(client, "test:")
	token := NewOpaqueAccessToken(session, storage, NewDefaultTokenGenerator(), time.Hour)

	mock.Regexp().ExpectSet("test:oidc:access_token:.*", ".*", time.Hour).SetVal("OK")
	mock.Regexp().ExpectSAdd("test:oidc:user_access_tokens:caller", ".*").SetVal(1)
	mock.ExpectExpireNX("test:oidc:user_access_tokens:caller", time.Hour).SetVal(true)
	mock.ExpectExpireGT("test:oidc:user_access_tokens:caller", time.Hour).SetVal(false)

	value, _, err := token.Issue(t.Context())
	assert.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(time.Hour), session.AccessTokenExpiresAt, time.Second)
	encoded, err := json.Marshal(session)
	assert.NoError(t, err)
	encrypted, err := client.GetSecurityManager().Encrypt(string(encoded))
	assert.NoError(t, err)
	mock.ExpectGet("test:oidc:access_token:" + value).SetVal(encrypted)

	claims, err := token.Validate(t.Context(), value)
	assert.NoError(t, err)
	assert.Equal(t, session.AccessTokenExpiresAt.Unix(), claims["exp"])
	assert.Equal(t, session.AccessTokenIssuer, claims["iss"])
	assert.Equal(t, session.ClientID, claims["client_id"])
	assert.NoError(t, mock.ExpectationsWereMet())
}
