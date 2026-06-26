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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/idp/signing"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/go-redis/redismock/v9"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

const testKID = "test-kid"

func TestAccessToken_OOP(t *testing.T) {
	ctx := t.Context()
	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	storage := NewRedisTokenStorage(redisClient, "test:")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	session := &OIDCSession{
		ClientID:          "client1",
		UserID:            "user1",
		Scopes:            []string{"openid", "profile"},
		AuthTime:          time.Now(),
		AccessTokenClaims: map[string]any{"name": "Test User"},
		IDTokenClaims:     map[string]any{"preferred_username": "testuser", "email": "test@example.com"},
	}

	issuer := "https://issuer.local"
	signer := signing.NewRS256Signer(key, testKID)

	t.Run("JWT Access Token", func(t *testing.T) {
		token := NewJWTAccessToken(issuer, signer, session, time.Hour)
		tokenString, lifetime, err := token.Issue(ctx)
		assert.NoError(t, err)
		assert.NotEmpty(t, tokenString)
		assert.Equal(t, time.Hour, lifetime)

		// Validation is currently in NauthilusIDP, but we can verify it's a JWT
		assert.Contains(t, tokenString, ".")
	})

	t.Run("Opaque Access Token", func(t *testing.T) {
		mock.Regexp().ExpectSet("test:oidc:access_token:.*", ".*", time.Hour).SetVal("OK")
		mock.Regexp().ExpectSAdd("test:oidc:user_access_tokens:user1", ".*").SetVal(1)
		mock.ExpectExpireNX("test:oidc:user_access_tokens:user1", time.Hour).SetVal(true)
		mock.ExpectExpireGT("test:oidc:user_access_tokens:user1", time.Hour).SetVal(false)

		tokenGen := NewDefaultTokenGenerator()
		token := NewOpaqueAccessToken(session, storage, tokenGen, time.Hour)
		tokenString, lifetime, err := token.Issue(ctx)
		assert.NoError(t, err)
		assert.NotEmpty(t, tokenString)
		assert.Contains(t, tokenString, definitions.OIDCTokenPrefixAccessToken)
		assert.Equal(t, time.Hour, lifetime)

		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestAccessTokenReservedClaimsRemainCanonical(t *testing.T) {
	session := &OIDCSession{
		ClientID: "client1",
		UserID:   "user1",
		Scopes:   []string{"openid", "profile"},
		AccessTokenClaims: map[string]any{
			"active":        false,
			"aud":           "evil-client",
			"custom_access": "allowed",
			"exp":           int64(1),
			"iat":           int64(1),
			"iss":           "https://evil.example.test",
			"scope":         "admin",
			"sub":           "attacker",
		},
	}
	signer := &captureAccessTokenSigner{}

	token := NewJWTAccessToken("https://issuer.local", signer, session, time.Hour)
	_, _, err := token.Issue(t.Context())

	assert.NoError(t, err)
	assert.Equal(t, "https://issuer.local", signer.claims["iss"])
	assert.Equal(t, "user1", signer.claims["sub"])
	assert.Equal(t, "client1", signer.claims["aud"])
	assert.Equal(t, "openid profile", signer.claims["scope"])
	assert.Nil(t, signer.claims["active"])
	assert.NotEqual(t, int64(1), signer.claims["exp"])
	assert.NotEqual(t, int64(1), signer.claims["iat"])
	assert.Equal(t, "allowed", signer.claims["custom_access"])

	opaque := NewOpaqueAccessToken(session, nil, nil, time.Hour)
	claims := opaque.ClaimsFromSession(session)

	assert.Equal(t, "user1", claims["sub"])
	assert.Equal(t, "client1", claims["aud"])
	assert.Equal(t, "openid profile", claims["scope"])
	assert.Nil(t, claims["active"])
	assert.Nil(t, claims["iss"])
	assert.Nil(t, claims["exp"])
	assert.Nil(t, claims["iat"])
	assert.Equal(t, "allowed", claims["custom_access"])
}

type captureAccessTokenSigner struct {
	claims jwt.MapClaims
}

func (s *captureAccessTokenSigner) Sign(claims jwt.MapClaims) (string, error) {
	s.claims = make(jwt.MapClaims, len(claims))

	for key, value := range claims {
		s.claims[key] = value
	}

	return "signed-token", nil
}

func (s *captureAccessTokenSigner) Algorithm() string {
	return signing.AlgorithmRS256
}

func (s *captureAccessTokenSigner) KeyID() string {
	return "capture"
}

func (s *captureAccessTokenSigner) PublicKey() crypto.PublicKey {
	return nil
}

func TestOpaqueAccessToken_Validate(t *testing.T) {
	ctx := t.Context()
	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	storage := NewRedisTokenStorage(redisClient, "test:")

	session := &OIDCSession{
		ClientID:          "client1",
		UserID:            "user1",
		Scopes:            []string{"openid", "profile"},
		AuthTime:          time.Now(),
		AccessTokenClaims: map[string]any{"name": "Test User"},
		IDTokenClaims:     map[string]any{"preferred_username": "testuser", "email": "test@example.com"},
	}

	tokenGen := NewDefaultTokenGenerator()
	tokenKey := "test:oidc:access_token:na_at_testtoken"
	sessionData, _ := json.Marshal(session)

	t.Run("Validate returns AccessTokenClaims", func(t *testing.T) {
		mock.ExpectGet(tokenKey).SetVal(string(sessionData))

		token := NewOpaqueAccessToken(session, storage, tokenGen, time.Hour)
		claims, err := token.Validate(ctx, "na_at_testtoken")

		assert.NoError(t, err)
		assert.Equal(t, "user1", claims["sub"])
		assert.Equal(t, "client1", claims["aud"])
		assert.Equal(t, "openid profile", claims["scope"])
		assert.Equal(t, "Test User", claims["name"])
		// Must NOT contain IDTokenClaims
		assert.Nil(t, claims["preferred_username"])
		assert.Nil(t, claims["email"])
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("ValidateForUserInfo returns IDTokenClaims", func(t *testing.T) {
		mock.ExpectGet(tokenKey).SetVal(string(sessionData))

		token := NewOpaqueAccessToken(session, storage, tokenGen, time.Hour)
		claims, err := token.ValidateForUserInfo(ctx, "na_at_testtoken")

		assert.NoError(t, err)
		assert.Equal(t, "user1", claims["sub"])
		assert.Equal(t, "testuser", claims["preferred_username"])
		assert.Equal(t, "test@example.com", claims["email"])
		// Must NOT contain AccessTokenClaims or introspection fields
		assert.Nil(t, claims["aud"])
		assert.Nil(t, claims["scope"])
		assert.Nil(t, claims["name"])
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
