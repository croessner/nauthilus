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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
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
		CustomScopes: []config.Oauth2CustomScope{
			{
				Name:        "resource",
				Description: "Resource scope for access claims",
				Claims: []config.OIDCCustomClaim{
					{Name: "resource.role", Type: definitions.ClaimTypeStringArray},
				},
			},
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
	ctx := t.Context()

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

	t.Run("IssueWithoutOpenIDScope", func(t *testing.T) {
		// Per OIDC Core 1.0 §3.1.2.1: without "openid" scope, no id_token should be issued.
		session := &OIDCSession{
			ClientID: "client1",
			UserID:   "user123",
			Scopes:   []string{"profile"},
			AuthTime: fixedTime,
			Nonce:    "test-nonce",
		}

		idToken, accessToken, refreshToken, expiresIn, err := idp.IssueTokens(ctx, session)
		assert.NoError(t, err)
		assert.Empty(t, idToken, "id_token must be empty when openid scope is not requested")
		assert.NotEmpty(t, accessToken)
		assert.Empty(t, refreshToken)
		assert.Equal(t, 2*time.Hour, expiresIn)
	})

	t.Run("IssueWithOfflineAccess", func(t *testing.T) {
		session := &OIDCSession{
			ClientID: "client1",
			UserID:   "user123",
			Scopes:   []string{"openid", "offline_access"},
			AuthTime: fixedTime,
		}

		// The stored session will contain the access token (JWT), so we use
		// regexp matching for the refresh token SET value.
		mock.Regexp().ExpectSet("test:oidc:refresh_token:na_rt_fixed-token", ".*", 7*24*time.Hour).SetVal("OK")
		mock.ExpectSAdd("test:oidc:user_refresh_tokens:user123", "na_rt_fixed-token").SetVal(1)
		mock.ExpectExpire("test:oidc:user_refresh_tokens:user123", 30*24*time.Hour).SetVal(true)

		idToken, accessToken, refreshToken, _, err := idp.IssueTokens(ctx, session)
		assert.NoError(t, err)
		assert.NotEmpty(t, idToken)
		assert.NotEmpty(t, accessToken)
		assert.Equal(t, "na_rt_fixed-token", refreshToken)
		assert.Equal(t, accessToken, session.AccessToken, "session must track access token")
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("ExchangeRefreshToken_WithJWTAccessToken", func(t *testing.T) {
		oldAccessToken := "header.payload.signature"
		session := &OIDCSession{
			ClientID:    "client1",
			UserID:      "user123",
			Scopes:      []string{"openid", "offline_access"},
			AuthTime:    fixedTime,
			AccessToken: oldAccessToken,
		}

		refreshToken := "old-rt"
		sessionData, _ := json.Marshal(session)

		// Get old RT
		mock.ExpectGet("test:oidc:refresh_token:" + refreshToken).SetVal(string(sessionData))
		// Deny old JWT access token
		mock.ExpectSet("test:oidc:denied_access_token:"+oldAccessToken, "1", 2*time.Hour).SetVal("OK")
		// Delete old RT
		mock.ExpectGet("test:oidc:refresh_token:" + refreshToken).SetVal(string(sessionData))
		mock.ExpectSRem("test:oidc:user_refresh_tokens:user123", refreshToken).SetVal(1)
		mock.ExpectDel("test:oidc:refresh_token:" + refreshToken).SetVal(1)
		// Store new RT (fixed-token due to mock) — value contains JWT, so use regexp
		mock.Regexp().ExpectSet("test:oidc:refresh_token:na_rt_fixed-token", ".*", 7*24*time.Hour).SetVal("OK")
		mock.ExpectSAdd("test:oidc:user_refresh_tokens:user123", "na_rt_fixed-token").SetVal(1)
		mock.ExpectExpire("test:oidc:user_refresh_tokens:user123", 30*24*time.Hour).SetVal(true)

		idToken, accessToken, newRefreshToken, _, err := idp.ExchangeRefreshToken(ctx, refreshToken, "client1")
		assert.NoError(t, err)
		assert.NotEmpty(t, idToken)
		assert.NotEmpty(t, accessToken)
		assert.Equal(t, "na_rt_fixed-token", newRefreshToken)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("ExchangeRefreshToken_WithOpaqueAccessToken", func(t *testing.T) {
		oldAccessToken := "na_at_old-opaque-token"
		session := &OIDCSession{
			ClientID:    "client1",
			UserID:      "user123",
			Scopes:      []string{"openid", "offline_access"},
			AuthTime:    fixedTime,
			AccessToken: oldAccessToken,
		}

		refreshToken := "old-rt-opaque"
		sessionData, _ := json.Marshal(session)

		// Get old RT
		mock.ExpectGet("test:oidc:refresh_token:" + refreshToken).SetVal(string(sessionData))
		// Delete old opaque access token
		mock.ExpectGet("test:oidc:access_token:" + oldAccessToken).SetVal(string(sessionData))
		mock.ExpectSRem("test:oidc:user_access_tokens:user123", oldAccessToken).SetVal(1)
		mock.ExpectDel("test:oidc:access_token:" + oldAccessToken).SetVal(1)
		// Delete old RT
		mock.ExpectGet("test:oidc:refresh_token:" + refreshToken).SetVal(string(sessionData))
		mock.ExpectSRem("test:oidc:user_refresh_tokens:user123", refreshToken).SetVal(1)
		mock.ExpectDel("test:oidc:refresh_token:" + refreshToken).SetVal(1)
		// Store new RT — value contains JWT, so use regexp
		mock.Regexp().ExpectSet("test:oidc:refresh_token:na_rt_fixed-token", ".*", 7*24*time.Hour).SetVal("OK")
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
			IdTokenClaims: config.IdTokenClaims{
				Mappings: []config.OIDCClaimMapping{
					{Claim: definitions.ClaimEmail, Attribute: "mail", Type: definitions.ClaimTypeString},
					{Claim: definitions.ClaimGroups, Attribute: "memberOf", Type: definitions.ClaimTypeStringArray},
				},
			},
			AccessTokenClaims: config.AccessTokenClaims{
				Mappings: []config.OIDCClaimMapping{
					{Claim: "resource.role", Attribute: "memberOf", Type: definitions.ClaimTypeStringArray},
				},
			},
		}

		ctx, _ := gin.CreateTestContext(nil)

		// Only openid requested -> no extra claims except defaults (sub, name, preferred_username)
		idClaims, accessClaims, err := idp.GetClaims(ctx, user, client, []string{"openid"})
		assert.NoError(t, err)
		assert.Equal(t, "user123", idClaims["sub"])
		assert.Equal(t, "John Doe", idClaims["name"])
		assert.Nil(t, idClaims["email"])
		assert.Nil(t, idClaims["groups"])
		assert.Nil(t, accessClaims["resource.role"])

		// email requested
		idClaims, accessClaims, err = idp.GetClaims(ctx, user, client, []string{"openid", "email"})
		assert.NoError(t, err)
		assert.Equal(t, "jdoe@example.com", idClaims["email"])
		assert.Nil(t, idClaims["groups"])
		assert.Nil(t, accessClaims["resource.role"])

		// groups requested
		idClaims, accessClaims, err = idp.GetClaims(ctx, user, client, []string{"openid", "groups", "resource"})
		assert.NoError(t, err)
		assert.Nil(t, idClaims["email"])
		assert.Equal(t, []string{"group1"}, idClaims["groups"])
		assert.Equal(t, []string{"group1"}, accessClaims["resource.role"])
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

func TestNauthilusIdP_ClientCredentials(t *testing.T) {
	signingKey := generateTestKey()
	oidcCfg := config.OIDCConfig{
		Issuer: "https://issuer.example.com",
		SigningKeys: []config.OIDCKey{
			{ID: "default", Key: signingKey, Active: true},
		},
		Clients: []config.OIDCClient{
			{
				ClientID:            "cc-client",
				ClientSecret:        "cc-secret",
				GrantTypes:          []string{"client_credentials"},
				Scopes:              []string{"api.read", "api.write"},
				AccessTokenLifetime: time.Hour,
			},
			{
				ClientID:     "authcode-only",
				ClientSecret: "secret",
				RedirectURIs: []string{"http://localhost/cb"},
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

	db, _ := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	d := &deps.Deps{Cfg: cfg, Redis: redisClient}
	idpInst := NewNauthilusIdP(d)
	ctx := t.Context()

	t.Run("IssueClientCredentialsToken_Success", func(t *testing.T) {
		accessToken, expiresIn, err := idpInst.IssueClientCredentialsToken(ctx, "cc-client", []string{"api.read"})
		assert.NoError(t, err)
		assert.NotEmpty(t, accessToken)
		assert.Equal(t, time.Hour, expiresIn)

		// Access token should be a JWT (contains dots)
		assert.Contains(t, accessToken, ".")

		// Validate the token
		claims, err := idpInst.ValidateToken(ctx, accessToken)
		assert.NoError(t, err)
		assert.Equal(t, "cc-client", claims["sub"])
		assert.Equal(t, "cc-client", claims["aud"])
		assert.Equal(t, "https://issuer.example.com", claims["iss"])
	})

	t.Run("IssueClientCredentialsToken_UnsupportedGrant", func(t *testing.T) {
		_, _, err := idpInst.IssueClientCredentialsToken(ctx, "authcode-only", []string{"openid"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "does not support client_credentials")
	})

	t.Run("IssueClientCredentialsToken_UnknownClient", func(t *testing.T) {
		_, _, err := idpInst.IssueClientCredentialsToken(ctx, "nonexistent", nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "client not found")
	})

	t.Run("SupportsGrantType", func(t *testing.T) {
		ccClient, ok := idpInst.FindClient("cc-client")
		assert.True(t, ok)
		assert.True(t, ccClient.SupportsGrantType("client_credentials"))
		assert.False(t, ccClient.SupportsGrantType("authorization_code"))

		acClient, ok := idpInst.FindClient("authcode-only")
		assert.True(t, ok)
		assert.True(t, acClient.SupportsGrantType("authorization_code"))
		assert.False(t, acClient.SupportsGrantType("client_credentials"))
	})
}
