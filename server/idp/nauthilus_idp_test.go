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
		Issuer:     "https://issuer.example.com",
		SigningKey: signingKey,
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
	ctx := context.Background()

	// Mock token generator for predictable tests
	oldGen := tokenGenerator
	tokenGenerator = func() string { return "fixed-token" }
	defer func() { tokenGenerator = oldGen }()

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
		mock.ExpectSet("test:nauthilus:oidc:refresh_token:fixed-token", string(sessionData), 7*24*time.Hour).SetVal("OK")

		idToken, accessToken, refreshToken, _, err := idp.IssueTokens(ctx, session)
		assert.NoError(t, err)
		assert.NotEmpty(t, idToken)
		assert.NotEmpty(t, accessToken)
		assert.Equal(t, "fixed-token", refreshToken)
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
		mock.ExpectGet("test:nauthilus:oidc:refresh_token:" + refreshToken).SetVal(string(sessionData))
		// Delete old RT
		mock.ExpectDel("test:nauthilus:oidc:refresh_token:" + refreshToken).SetVal(1)
		// Store new RT (fixed-token due to mock)
		mock.ExpectSet("test:nauthilus:oidc:refresh_token:fixed-token", string(sessionData), 7*24*time.Hour).SetVal("OK")

		idToken, accessToken, newRefreshToken, _, err := idp.ExchangeRefreshToken(ctx, refreshToken, "client1")
		assert.NoError(t, err)
		assert.NotEmpty(t, idToken)
		assert.NotEmpty(t, accessToken)
		assert.Equal(t, "fixed-token", newRefreshToken)
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

		// Only openid requested -> no extra claims except defaults (sub, name, preferred_username)
		claims, err := idp.GetClaims(user, client, []string{"openid"})
		assert.NoError(t, err)
		assert.Equal(t, "user123", claims["sub"])
		assert.Equal(t, "John Doe", claims["name"])
		assert.Nil(t, claims["email"])
		assert.Nil(t, claims["groups"])

		// email requested
		claims, err = idp.GetClaims(user, client, []string{"openid", "email"})
		assert.NoError(t, err)
		assert.Equal(t, "jdoe@example.com", claims["email"])
		assert.Nil(t, claims["groups"])

		// groups requested
		claims, err = idp.GetClaims(user, client, []string{"openid", "groups"})
		assert.NoError(t, err)
		assert.Nil(t, claims["email"])
		assert.Equal(t, []string{"group1"}, claims["groups"])
	})
}
