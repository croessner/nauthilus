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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

func generateTestKey() string {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	return string(pemData)
}

type mockIdpConfig struct {
	*config.FileSettings
	oidc config.OIDCConfig
}

type mockTokenGenerator struct {
	token string
}

func (m *mockTokenGenerator) GenerateToken(prefix string) string {
	return prefix + m.token
}

func (m *mockIdpConfig) GetIdP() *config.IdPSection {
	return &config.IdPSection{
		OIDC: m.oidc,
	}
}

func (m *mockIdpConfig) GetServer() *config.ServerSection {
	return m.FileSettings.GetServer()
}

func TestNauthilusIdP_Tokens(t *testing.T) {
	signingKey := generateTestKey()
	oidcCfg := config.OIDCConfig{
		Issuer: "https://issuer.example.com",
		SigningKeys: []config.OIDCKey{
			{ID: "default", Key: signingKey, Active: true},
		},
		Clients: []config.OIDCClient{
			{
				ClientID:             "client1",
				RedirectURIs:         []string{"http://localhost/cb"},
				DelayedResponse:      true,
				AccessTokenLifetime:  2 * time.Hour,
				RefreshTokenLifetime: 7 * 24 * time.Hour,
			},
		},
	}
	cfg := &mockIdpConfig{
		FileSettings: &config.FileSettings{
			Server: &config.ServerSection{
				Redis: config.Redis{
					Prefix: "test:",
				},
			},
		},
		oidc: oidcCfg,
	}
	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	d := &deps.Deps{Cfg: cfg, Redis: redisClient}
	idp := NewNauthilusIdP(d)
	idp.tokenGen = &mockTokenGenerator{token: "fixed-token"}
	ctx := context.Background()

	fixedTime := time.Date(2026, 1, 26, 8, 0, 0, 0, time.UTC)

	t.Run("FindClient", func(t *testing.T) {
		client, found := idp.FindClient("client1")
		assert.True(t, found)
		assert.Equal(t, "client1", client.ClientID)

		_, found = idp.FindClient("nonexistent")
		assert.False(t, found)
	})

	t.Run("IsDelayedResponse", func(t *testing.T) {
		assert.True(t, idp.IsDelayedResponse("client1", ""))
		assert.False(t, idp.IsDelayedResponse("nonexistent", ""))
	})

	t.Run("IssueAndValidateToken", func(t *testing.T) {
		session := &OIDCSession{
			ClientID: "client1",
			UserID:   "user123",
			Scopes:   []string{"openid", "profile"},
			AuthTime: fixedTime,
			Nonce:    "test-nonce",
		}

		idToken, accessToken, refreshToken, expiresIn, err := idp.IssueTokens(ctx, session)
		assert.NoError(t, err)
		assert.NotEmpty(t, idToken)
		assert.NotEmpty(t, accessToken)
		assert.Empty(t, refreshToken)
		assert.Equal(t, 2*time.Hour, expiresIn)

		claims, err := idp.ValidateToken(ctx, idToken)
		assert.NoError(t, err)
		assert.Equal(t, "user123", claims["sub"])
		assert.Equal(t, "https://issuer.example.com", claims["iss"])
		assert.Equal(t, "test-nonce", claims["nonce"])
	})

	t.Run("IssueWithOfflineAccess", func(t *testing.T) {
		session := &OIDCSession{
			ClientID: "client1",
			UserID:   "user123",
			Scopes:   []string{"openid", "offline_access"},
			AuthTime: fixedTime,
		}

		sessionData, _ := json.Marshal(session)
		mock.ExpectSet("test:oidc:refresh_token:na_rt_fixed-token", string(sessionData), 7*24*time.Hour).SetVal("OK")
		mock.ExpectSAdd("test:oidc:user_refresh_tokens:user123", "na_rt_fixed-token").SetVal(1)
		mock.ExpectExpire("test:oidc:user_refresh_tokens:user123", 30*24*time.Hour).SetVal(true)

		idToken, accessToken, refreshToken, _, err := idp.IssueTokens(ctx, session)
		assert.NoError(t, err)
		assert.NotEmpty(t, idToken)
		assert.NotEmpty(t, accessToken)
		assert.Equal(t, "na_rt_fixed-token", refreshToken)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("ExchangeRefreshToken", func(t *testing.T) {
		session := &OIDCSession{
			ClientID: "client1",
			UserID:   "user123",
			Scopes:   []string{"openid", "offline_access"},
			AuthTime: fixedTime,
		}
		refreshToken := "old-rt"
		sessionData, _ := json.Marshal(session)

		// Get old RT
		mock.ExpectGet("test:oidc:refresh_token:" + refreshToken).SetVal(string(sessionData))
		// Delete old RT
		mock.ExpectGet("test:oidc:refresh_token:" + refreshToken).SetVal(string(sessionData))
		mock.ExpectSRem("test:oidc:user_refresh_tokens:user123", refreshToken).SetVal(1)
		mock.ExpectDel("test:oidc:refresh_token:" + refreshToken).SetVal(1)
		// Store new RT (fixed-token due to mock)
		mock.ExpectSet("test:oidc:refresh_token:na_rt_fixed-token", string(sessionData), 7*24*time.Hour).SetVal("OK")
		mock.ExpectSAdd("test:oidc:user_refresh_tokens:user123", "na_rt_fixed-token").SetVal(1)
		mock.ExpectExpire("test:oidc:user_refresh_tokens:user123", 30*24*time.Hour).SetVal(true)

		idToken, accessToken, newRefreshToken, _, err := idp.ExchangeRefreshToken(ctx, refreshToken, "client1")
		assert.NoError(t, err)
		assert.NotEmpty(t, idToken)
		assert.NotEmpty(t, accessToken)
		assert.Equal(t, "na_rt_fixed-token", newRefreshToken)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("GetClaimsWithScopes", func(t *testing.T) {
		user := &backend.User{
			Id:          "user123",
			Name:        "jdoe",
			DisplayName: "John Doe",
			Attributes: bktype.AttributeMapping{
				"mail":     {"jdoe@example.com"},
				"memberOf": {"group1"},
			},
		}
		client := &config.OIDCClient{
			ClientID: "client1",
			Claims: config.IdTokenClaims{
				Email:  "mail",
				Groups: "memberOf",
			},
		}

		ctx, _ := gin.CreateTestContext(nil)

		// Only openid requested -> no extra claims except defaults (sub, name, preferred_username)
		claims, err := idp.GetClaims(ctx, user, client, []string{"openid"})
		assert.NoError(t, err)
		assert.Equal(t, "user123", claims["sub"])
		assert.Equal(t, "John Doe", claims["name"])
		assert.Nil(t, claims["email"])
		assert.Nil(t, claims["groups"])

		// email requested
		claims, err = idp.GetClaims(ctx, user, client, []string{"openid", "email"})
		assert.NoError(t, err)
		assert.Equal(t, "jdoe@example.com", claims["email"])
		assert.Nil(t, claims["groups"])

		// groups requested
		claims, err = idp.GetClaims(ctx, user, client, []string{"openid", "groups"})
		assert.NoError(t, err)
		assert.Nil(t, claims["email"])
		assert.Equal(t, []string{"group1"}, claims["groups"])
	})

	t.Run("FilterScopes", func(t *testing.T) {
		client := &config.OIDCClient{
			ClientID: "client1",
			Scopes:   []string{"openid", "profile"},
		}

		// Requested allowed scopes
		requested := []string{"openid", "profile"}
		filtered := idp.FilterScopes(client, requested)
		assert.Equal(t, []string{"openid", "profile"}, filtered)

		// Requested mixed scopes
		requested = []string{"openid", "profile", "email", "invalid"}
		filtered = idp.FilterScopes(client, requested)
		assert.Equal(t, []string{"openid", "profile"}, filtered)

		// Default scopes when none configured
		clientNoScopes := &config.OIDCClient{ClientID: "client2"}
		requested = []string{"openid", "profile", "email", "groups", "offline_access", "invalid"}
		filtered = idp.FilterScopes(clientNoScopes, requested)
		assert.Equal(t, []string{"openid", "profile", "email", "groups", "offline_access"}, filtered)
	})

	t.Run("ValidateToken_Heuristic", func(t *testing.T) {
		// JWT-like token (with dots) should NOT hit Redis
		jwtToken := "header.payload.signature"
		_, err := idp.ValidateToken(ctx, jwtToken)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet(), "Redis should not have been hit for JWT-like token")

		// Opaque token (without dots) SHOULD hit Redis
		opaqueToken := "na_at_someopaquevalue"
		mock.ExpectGet("test:oidc:access_token:" + opaqueToken).RedisNil()
		_, err = idp.ValidateToken(ctx, opaqueToken)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet(), "Redis should have been hit for opaque token")
	})
}
