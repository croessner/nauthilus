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
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/idp/oidckeys"
	"github.com/croessner/nauthilus/v3/server/idp/signing"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

const (
	testRedisPrefix = "test:"
	testIssuer      = "https://issuer.example.com"
	testClientID    = "client1"
	testUserID      = "user123"
	testScopeClaim  = "openid profile"

	claimIssuer   = "iss"
	claimSubject  = "sub"
	claimAudience = "aud"
	claimIssuedAt = "iat"
	claimExpires  = "exp"
	claimScope    = "scope"
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
	saml config.SAML2Config
}

type mockTokenGenerator struct {
	token string
}

func (m *mockTokenGenerator) GenerateToken(prefix string) string {
	return prefix + m.token
}

func (m *mockIdpConfig) GetIdP() *config.IdPSection {
	return &config.IdPSection{
		OIDC:  m.oidc,
		SAML2: m.saml,
	}
}

func (m *mockIdpConfig) GetServer() *config.ServerSection {
	return m.FileSettings.GetServer()
}

func testAccessTokenKey(token string) string {
	return testRedisPrefix + "oidc:access_token:" + token
}

func testDeniedAccessTokenKey(token string) string {
	return testRedisPrefix + "oidc:denied_access_token:" + token
}

func testRefreshTokenKey(token string) string {
	return testRedisPrefix + "oidc:refresh_token:" + token
}

func testUserAccessTokensKey(userID string) string {
	return testRedisPrefix + "oidc:user_access_tokens:" + userID
}

func testUserRefreshTokensKey(userID string) string {
	return testRedisPrefix + "oidc:user_refresh_tokens:" + userID
}

func testOIDCKeysHashKey() string {
	return testRedisPrefix + oidckeys.RedisKeyOIDCKeys
}

type idpTraceSpanCollector struct {
	mu    sync.Mutex
	spans []sdktrace.ReadOnlySpan
}

func (c *idpTraceSpanCollector) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.spans = append(c.spans, spans...)

	return nil
}

func (c *idpTraceSpanCollector) Shutdown(context.Context) error {
	return nil
}

func (c *idpTraceSpanCollector) findSpan(name string) (sdktrace.ReadOnlySpan, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, span := range c.spans {
		if span.Name() == name {
			return span, true
		}
	}

	return nil, false
}

func installIDPTraceTestProvider(tp *sdktrace.TracerProvider) func() {
	previousProvider := otel.GetTracerProvider()

	otel.SetTracerProvider(tp)

	return func() {
		otel.SetTracerProvider(previousProvider)

		_ = tp.Shutdown(context.Background())
	}
}

func assertIDPSpanRecorded(t *testing.T, collector *idpTraceSpanCollector, name string) sdktrace.ReadOnlySpan {
	t.Helper()

	span, found := collector.findSpan(name)
	if !found {
		t.Fatalf("span %q was not recorded", name)
	}

	return span
}

func newTestIDPWithMock(t *testing.T, oidcCfg config.OIDCConfig) (*NauthilusIdP, redismock.ClientMock, rediscli.Client) {
	t.Helper()

	cfg := &mockIdpConfig{
		FileSettings: &config.FileSettings{
			Server: &config.ServerSection{
				Redis: config.Redis{
					Prefix: testRedisPrefix,
				},
			},
		},
		oidc: oidcCfg,
	}
	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)

	return NewNauthilusIdP(&deps.Deps{Cfg: cfg, Redis: redisClient}), mock, redisClient
}

func signedTestAccessToken(t *testing.T, kid string, pemData string) string {
	t.Helper()

	signer, err := signing.NewRS256SignerFromPEM(pemData, kid)
	assert.NoError(t, err)

	tokenString, err := signer.Sign(jwt.MapClaims{
		claimIssuer:   testIssuer,
		claimSubject:  testUserID,
		claimAudience: testClientID,
		claimIssuedAt: time.Now().Add(-time.Minute).Unix(),
		claimExpires:  time.Now().Add(time.Hour).Unix(),
		claimScope:    testScopeClaim,
	})
	assert.NoError(t, err)

	return tokenString
}

func redisKeyMetadataJSON(t *testing.T, kid string, pemData string) string {
	t.Helper()

	raw, err := json.Marshal(oidckeys.KeyMetadata{
		ID:        kid,
		PEM:       pemData,
		Algorithm: signing.AlgorithmRS256,
		CreatedAt: time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	assert.NoError(t, err)

	return string(raw)
}

func TestNauthilusIdP_Tokens(t *testing.T) {
	signingKey := secret.New(generateTestKey())
	oidcCfg := config.OIDCConfig{
		Issuer: testIssuer,
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
			{
				Name:        "roles",
				Description: "Role scope for compatibility mappings",
				Claims: []config.OIDCCustomClaim{
					{Name: "roles", Type: definitions.ClaimTypeStringArray},
				},
			},
		},
		Clients: []config.OIDCClient{
			{
				ClientID:             testClientID,
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
					Prefix: testRedisPrefix,
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
		client, found := idp.FindClient(testClientID)
		assert.True(t, found)
		assert.Equal(t, testClientID, client.ClientID)

		_, found = idp.FindClient("nonexistent")
		assert.False(t, found)
	})

	t.Run("IsDelayedResponse", func(t *testing.T) {
		assert.True(t, idp.IsDelayedResponse(testClientID, ""))
		assert.False(t, idp.IsDelayedResponse("nonexistent", ""))
	})

	t.Run("IssueAndValidateToken", func(t *testing.T) {
		session := &OIDCSession{
			ClientID: testClientID,
			UserID:   testUserID,
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
		assert.Equal(t, testUserID, claims[claimSubject])
		assert.Equal(t, testIssuer, claims[claimIssuer])
		assert.Equal(t, "test-nonce", claims["nonce"])
	})

	t.Run("IssueWithoutOpenIDScope", func(t *testing.T) {
		// Per OIDC Core 1.0 §3.1.2.1: without "openid" scope, no id_token should be issued.
		session := &OIDCSession{
			ClientID: testClientID,
			UserID:   testUserID,
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
			ClientID: testClientID,
			UserID:   testUserID,
			Scopes:   []string{"openid", "offline_access"},
			AuthTime: fixedTime,
		}

		// The stored session will contain the access token (JWT), so we use
		// regexp matching for the refresh token SET value.
		mock.Regexp().ExpectSet(testRefreshTokenKey("na_rt_fixed-token"), ".*", 7*24*time.Hour).SetVal("OK")
		mock.ExpectSAdd(testUserRefreshTokensKey(testUserID), "na_rt_fixed-token").SetVal(1)
		mock.ExpectExpire(testUserRefreshTokensKey(testUserID), 30*24*time.Hour).SetVal(true)

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
			ClientID:    testClientID,
			UserID:      testUserID,
			Scopes:      []string{"openid", "offline_access"},
			AuthTime:    fixedTime,
			AccessToken: oldAccessToken,
		}

		refreshToken := "old-rt"
		sessionData, _ := json.Marshal(session)

		// Get old RT
		mock.ExpectGet(testRefreshTokenKey(refreshToken)).SetVal(string(sessionData))
		// Deny old JWT access token
		mock.ExpectSet(testDeniedAccessTokenKey(oldAccessToken), "1", 2*time.Hour).SetVal("OK")
		// Delete old RT
		mock.ExpectGet(testRefreshTokenKey(refreshToken)).SetVal(string(sessionData))
		mock.ExpectSRem(testUserRefreshTokensKey(testUserID), refreshToken).SetVal(1)
		mock.ExpectDel(testRefreshTokenKey(refreshToken)).SetVal(1)
		// Store new RT (fixed-token due to mock) — value contains JWT, so use regexp
		mock.Regexp().ExpectSet(testRefreshTokenKey("na_rt_fixed-token"), ".*", 7*24*time.Hour).SetVal("OK")
		mock.ExpectSAdd(testUserRefreshTokensKey(testUserID), "na_rt_fixed-token").SetVal(1)
		mock.ExpectExpire(testUserRefreshTokensKey(testUserID), 30*24*time.Hour).SetVal(true)

		exchangedSession, idToken, accessToken, newRefreshToken, _, err := idp.ExchangeRefreshToken(ctx, refreshToken, testClientID)
		assert.NoError(t, err)
		assert.Equal(t, session.UserID, exchangedSession.UserID)
		assert.NotEmpty(t, idToken)
		assert.NotEmpty(t, accessToken)
		assert.Equal(t, "na_rt_fixed-token", newRefreshToken)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("ExchangeRefreshToken_WithOpaqueAccessToken", func(t *testing.T) {
		oldAccessToken := "na_at_old-opaque-token"
		session := &OIDCSession{
			ClientID:    testClientID,
			UserID:      testUserID,
			Scopes:      []string{"openid", "offline_access"},
			AuthTime:    fixedTime,
			AccessToken: oldAccessToken,
		}

		refreshToken := "old-rt-opaque"
		sessionData, _ := json.Marshal(session)

		// Get old RT
		mock.ExpectGet(testRefreshTokenKey(refreshToken)).SetVal(string(sessionData))
		// Delete old opaque access token
		mock.ExpectGet(testAccessTokenKey(oldAccessToken)).SetVal(string(sessionData))
		mock.ExpectSRem(testUserAccessTokensKey(testUserID), oldAccessToken).SetVal(1)
		mock.ExpectDel(testAccessTokenKey(oldAccessToken)).SetVal(1)
		// Delete old RT
		mock.ExpectGet(testRefreshTokenKey(refreshToken)).SetVal(string(sessionData))
		mock.ExpectSRem(testUserRefreshTokensKey(testUserID), refreshToken).SetVal(1)
		mock.ExpectDel(testRefreshTokenKey(refreshToken)).SetVal(1)
		// Store new RT — value contains JWT, so use regexp
		mock.Regexp().ExpectSet(testRefreshTokenKey("na_rt_fixed-token"), ".*", 7*24*time.Hour).SetVal("OK")
		mock.ExpectSAdd(testUserRefreshTokensKey(testUserID), "na_rt_fixed-token").SetVal(1)
		mock.ExpectExpire(testUserRefreshTokensKey(testUserID), 30*24*time.Hour).SetVal(true)

		exchangedSession, idToken, accessToken, newRefreshToken, _, err := idp.ExchangeRefreshToken(ctx, refreshToken, testClientID)
		assert.NoError(t, err)
		assert.Equal(t, session.UserID, exchangedSession.UserID)
		assert.NotEmpty(t, idToken)
		assert.NotEmpty(t, accessToken)
		assert.Equal(t, "na_rt_fixed-token", newRefreshToken)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("ExchangeRefreshToken_WithoutRotation_ReusesRefreshToken", func(t *testing.T) {
		oldAccessToken := "header.payload.signature"
		session := &OIDCSession{
			ClientID:    testClientID,
			UserID:      testUserID,
			Scopes:      []string{"openid", "offline_access"},
			AuthTime:    fixedTime,
			AccessToken: oldAccessToken,
		}

		refreshToken := "stable-rt"
		sessionData, _ := json.Marshal(session)
		originalClient := cfg.oidc.Clients[0]
		disabled := false
		cfg.oidc.Clients[0].RevokeRefreshToken = &disabled
		defer func() {
			cfg.oidc.Clients[0] = originalClient
		}()

		mock.ExpectGet(testRefreshTokenKey(refreshToken)).SetVal(string(sessionData))
		mock.ExpectSet(testDeniedAccessTokenKey(oldAccessToken), "1", 2*time.Hour).SetVal("OK")
		mock.Regexp().ExpectSet(testRefreshTokenKey(refreshToken), ".*", 7*24*time.Hour).SetVal("OK")
		mock.ExpectSAdd(testUserRefreshTokensKey(testUserID), refreshToken).SetVal(0)
		mock.ExpectExpire(testUserRefreshTokensKey(testUserID), 30*24*time.Hour).SetVal(true)

		exchangedSession, idToken, accessToken, newRefreshToken, _, err := idp.ExchangeRefreshToken(ctx, refreshToken, testClientID)
		assert.NoError(t, err)
		assert.Equal(t, session.UserID, exchangedSession.UserID)
		assert.NotEmpty(t, idToken)
		assert.NotEmpty(t, accessToken)
		assert.Empty(t, newRefreshToken)

		updatedSession := *session
		updatedSession.AccessToken = accessToken
		updatedSessionData, _ := json.Marshal(&updatedSession)

		mock.ExpectGet(testRefreshTokenKey(refreshToken)).SetVal(string(updatedSessionData))
		mock.ExpectSet(testDeniedAccessTokenKey(accessToken), "1", 2*time.Hour).SetVal("OK")
		mock.Regexp().ExpectSet(testRefreshTokenKey(refreshToken), ".*", 7*24*time.Hour).SetVal("OK")
		mock.ExpectSAdd(testUserRefreshTokensKey(testUserID), refreshToken).SetVal(0)
		mock.ExpectExpire(testUserRefreshTokensKey(testUserID), 30*24*time.Hour).SetVal(true)

		_, _, secondAccessToken, secondRefreshToken, _, err := idp.ExchangeRefreshToken(ctx, refreshToken, testClientID)
		assert.NoError(t, err)
		assert.NotEmpty(t, secondAccessToken)
		assert.Empty(t, secondRefreshToken)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("GetClaimsWithScopes", func(t *testing.T) {
		user := &backend.User{
			Id:          testUserID,
			Name:        "jdoe",
			DisplayName: "John Doe",
			Attributes: bktype.AttributeMapping{
				"mail":     {"jdoe@example.com"},
				"memberOf": {"group1"},
			},
		}
		client := &config.OIDCClient{
			ClientID: testClientID,
			IdTokenClaims: config.IdTokenClaims{
				Mappings: []config.OIDCClaimMapping{
					{Claim: definitions.ClaimEmail, Attribute: "mail", Type: definitions.ClaimTypeString},
					{Claim: definitions.ClaimGroups, Attribute: "memberOf", Type: definitions.ClaimTypeStringArray},
					{Claim: "roles", Attribute: "memberOf", Type: definitions.ClaimTypeStringArray},
				},
			},
			AccessTokenClaims: config.AccessTokenClaims{
				Mappings: []config.OIDCClaimMapping{
					{Claim: "resource.role", Attribute: "memberOf", Type: definitions.ClaimTypeStringArray},
					{Claim: "roles", Attribute: "memberOf", Type: definitions.ClaimTypeStringArray},
				},
			},
		}

		ctx, _ := gin.CreateTestContext(nil)

		// Only openid requested -> no extra claims except defaults (sub, name, preferred_username)
		idClaims, accessClaims, err := idp.GetClaims(ctx, user, client, []string{"openid"})
		assert.NoError(t, err)
		assert.Equal(t, testUserID, idClaims[claimSubject])
		assert.Equal(t, "John Doe", idClaims["name"])
		assert.Nil(t, idClaims["email"])
		assert.Nil(t, idClaims["groups"])
		assert.Nil(t, idClaims["roles"])
		assert.Nil(t, accessClaims["roles"])
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
		assert.Nil(t, idClaims["roles"])
		assert.Equal(t, []string{"group1"}, accessClaims["resource.role"])
		assert.Nil(t, accessClaims["roles"])

		// roles implied for compatibility -> roles claim is now included
		clientWithImpliedRoles := &config.OIDCClient{
			ClientID:          testClientID,
			Scopes:            []string{"openid", "roles"},
			ImpliedScopes:     []string{"roles"},
			IdTokenClaims:     client.IdTokenClaims,
			AccessTokenClaims: client.AccessTokenClaims,
		}
		filteredScopes := idp.FilterScopes(clientWithImpliedRoles, []string{"openid"})
		assert.Equal(t, []string{"openid", "roles"}, filteredScopes)

		idClaims, accessClaims, err = idp.GetClaims(ctx, user, clientWithImpliedRoles, filteredScopes)
		assert.NoError(t, err)
		assert.Equal(t, []string{"group1"}, idClaims["roles"])
		assert.Equal(t, []string{"group1"}, accessClaims["roles"])
	})

	t.Run("FilterScopes", func(t *testing.T) {
		client := &config.OIDCClient{
			ClientID: testClientID,
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

		t.Run("adds implied scopes when allowed", func(t *testing.T) {
			clientWithImplied := &config.OIDCClient{
				ClientID:      "client3",
				Scopes:        []string{"openid", "profile", "offline_access", "roles"},
				ImpliedScopes: []string{"offline_access", "roles"},
			}

			filtered := idp.FilterScopes(clientWithImplied, []string{"openid", "profile"})
			assert.Equal(t, []string{"openid", "profile", "offline_access", "roles"}, filtered)
		})

		t.Run("keeps stable order and deduplicates implied scopes", func(t *testing.T) {
			clientWithImplied := &config.OIDCClient{
				ClientID:      "client4",
				Scopes:        []string{"openid", "profile", "offline_access"},
				ImpliedScopes: []string{"offline_access", "offline_access"},
			}

			filtered := idp.FilterScopes(clientWithImplied, []string{"openid", "offline_access"})
			assert.Equal(t, []string{"openid", "offline_access"}, filtered)
		})

		t.Run("ignores implied scopes that are not allowed", func(t *testing.T) {
			clientWithImplied := &config.OIDCClient{
				ClientID:      "client5",
				Scopes:        []string{"openid", "profile"},
				ImpliedScopes: []string{"offline_access"},
			}

			filtered := idp.FilterScopes(clientWithImplied, []string{"openid"})
			assert.Equal(t, []string{"openid"}, filtered)
		})
	})

	t.Run("IssueWithImpliedOfflineAccess", func(t *testing.T) {
		client := &config.OIDCClient{
			ClientID:             testClientID,
			Scopes:               []string{"openid", "profile", "offline_access"},
			ImpliedScopes:        []string{"offline_access"},
			RefreshTokenLifetime: 7 * 24 * time.Hour,
		}

		filteredScopes := idp.FilterScopes(client, []string{"openid", "profile"})
		assert.Equal(t, []string{"openid", "profile", "offline_access"}, filteredScopes)

		session := &OIDCSession{
			ClientID: testClientID,
			UserID:   testUserID,
			Scopes:   filteredScopes,
			AuthTime: fixedTime,
		}

		mock.Regexp().ExpectSet(testRefreshTokenKey("na_rt_fixed-token"), ".*", 7*24*time.Hour).SetVal("OK")
		mock.ExpectSAdd(testUserRefreshTokensKey(testUserID), "na_rt_fixed-token").SetVal(1)
		mock.ExpectExpire(testUserRefreshTokensKey(testUserID), 30*24*time.Hour).SetVal(true)

		_, _, refreshToken, _, err := idp.IssueTokens(ctx, session)
		assert.NoError(t, err)
		assert.Equal(t, "na_rt_fixed-token", refreshToken)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("ValidateToken_Heuristic", func(t *testing.T) {
		// JWT-like token (with dots) should NOT hit Redis
		jwtToken := "header.payload.signature"
		_, err := idp.ValidateToken(ctx, jwtToken)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet(), "Redis should not have been hit for JWT-like token")

		// Opaque token (without dots) SHOULD hit Redis
		opaqueToken := "na_at_someopaquevalue"
		mock.ExpectGet(testAccessTokenKey(opaqueToken)).RedisNil()
		_, err = idp.ValidateToken(ctx, opaqueToken)
		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet(), "Redis should have been hit for opaque token")
	})
}

func TestValidateTokenOpaqueUsesSingleRedisLookup(t *testing.T) {
	idp, mock, _ := newTestIDPWithMock(t, config.OIDCConfig{
		Issuer: testIssuer,
	})

	tokenString := "na_at_single-read"
	session := &OIDCSession{
		ClientID:          testClientID,
		UserID:            testUserID,
		Scopes:            []string{"openid", "profile"},
		AccessTokenClaims: map[string]any{"role": "reader"},
	}

	sessionData, err := json.Marshal(session)
	assert.NoError(t, err)

	mock.ExpectGet(testAccessTokenKey(tokenString)).SetVal(string(sessionData))

	claims, err := idp.ValidateToken(t.Context(), tokenString)
	assert.NoError(t, err)
	assert.Equal(t, testUserID, claims[claimSubject])
	assert.Equal(t, testClientID, claims[claimAudience])
	assert.Equal(t, testScopeClaim, claims[claimScope])
	assert.Equal(t, "reader", claims["role"])
	assert.NoError(t, mock.ExpectationsWereMet(), "opaque token validation must use the session loaded by the first Redis lookup")
}

func TestValidateTokenJWTResolvesRedisKeyByKID(t *testing.T) {
	idp, mock, _ := newTestIDPWithMock(t, config.OIDCConfig{
		Issuer: testIssuer,
	})
	mock.MatchExpectationsInOrder(false)

	kid := "redis-key-1"
	pemData := generateTestKey()
	tokenString := signedTestAccessToken(t, kid, pemData)

	mock.ExpectHGet(testOIDCKeysHashKey(), kid).SetVal(redisKeyMetadataJSON(t, kid, pemData))
	mock.ExpectGet(testDeniedAccessTokenKey(tokenString)).RedisNil()

	claims, err := idp.ValidateToken(t.Context(), tokenString)
	assert.NoError(t, err)
	assert.Equal(t, testUserID, claims[claimSubject])
	assert.NoError(t, mock.ExpectationsWereMet(), "JWT validation should resolve the public key by kid and still check the denylist")
}

func TestValidateTokenJWTRejectsDeniedTokenAfterSignatureValidation(t *testing.T) {
	idp, mock, _ := newTestIDPWithMock(t, config.OIDCConfig{
		Issuer: testIssuer,
	})
	mock.MatchExpectationsInOrder(false)

	kid := "denied-key-1"
	pemData := generateTestKey()
	tokenString := signedTestAccessToken(t, kid, pemData)

	mock.ExpectHGet(testOIDCKeysHashKey(), kid).SetVal(redisKeyMetadataJSON(t, kid, pemData))
	mock.ExpectGet(testDeniedAccessTokenKey(tokenString)).SetVal("1")

	claims, err := idp.ValidateToken(t.Context(), tokenString)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "revoked")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestValidateTokenEmitsDiagnosticChildSpans(t *testing.T) {
	collector := &idpTraceSpanCollector{}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(collector)),
	)

	restore := installIDPTraceTestProvider(tp)
	defer restore()

	idp, mock, _ := newTestIDPWithMock(t, config.OIDCConfig{
		Issuer: testIssuer,
	})
	mock.MatchExpectationsInOrder(false)

	kid := "trace-key-1"
	pemData := generateTestKey()
	tokenString := signedTestAccessToken(t, kid, pemData)

	mock.ExpectHGet(testOIDCKeysHashKey(), kid).SetVal(redisKeyMetadataJSON(t, kid, pemData))
	mock.ExpectGet(testDeniedAccessTokenKey(tokenString)).RedisNil()

	_, err := idp.ValidateToken(t.Context(), tokenString)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())

	assertIDPSpanRecorded(t, collector, "idp.validate_token")
	assertIDPSpanRecorded(t, collector, "idp.validate_token.jwt.verify")
	assertIDPSpanRecorded(t, collector, "idp.validate_token.jwt.key_resolve")
	assertIDPSpanRecorded(t, collector, "idp.validate_token.jwt.denylist")
}

func TestNauthilusIdP_FindSAMLServiceProvider_ReturnsSliceElement(t *testing.T) {
	cfg := &mockIdpConfig{
		FileSettings: &config.FileSettings{
			Server: &config.ServerSection{
				Redis: config.Redis{
					Prefix: testRedisPrefix,
				},
			},
		},
		saml: config.SAML2Config{
			ServiceProviders: []config.SAML2ServiceProvider{
				{
					Name:     "test-client",
					EntityID: "https://localhost:9095/saml/metadata",
					ACSURL:   "https://localhost:9095/saml/acs",
					SLOURL:   "https://localhost:9095/saml/slo",
				},
			},
		},
	}

	idp := NewNauthilusIdP(&deps.Deps{Cfg: cfg})

	sp, found := idp.FindSAMLServiceProvider("https://localhost:9095/saml/metadata")
	assert.True(t, found)
	if !assert.NotNil(t, sp) {
		return
	}

	sp.Name = "updated-client"

	assert.Equal(t, "updated-client", cfg.saml.ServiceProviders[0].Name)
}

func TestNauthilusIdP_ClientCredentials(t *testing.T) {
	signingKey := secret.New(generateTestKey())
	oidcCfg := config.OIDCConfig{
		Issuer: testIssuer,
		SigningKeys: []config.OIDCKey{
			{ID: "default", Key: signingKey, Active: true},
		},
		Clients: []config.OIDCClient{
			{
				ClientID:            "cc-client",
				ClientSecret:        secret.New("cc-secret"),
				GrantTypes:          []string{"client_credentials"},
				Scopes:              []string{"api.read", "api.write"},
				AccessTokenLifetime: time.Hour,
			},
			{
				ClientID:     "authcode-only",
				ClientSecret: secret.New("secret"),
				RedirectURIs: []string{"http://localhost/cb"},
			},
		},
	}

	cfg := &mockIdpConfig{
		FileSettings: &config.FileSettings{
			Server: &config.ServerSection{
				Redis: config.Redis{
					Prefix: testRedisPrefix,
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
		assert.Equal(t, "cc-client", claims[claimSubject])
		assert.Equal(t, "cc-client", claims[claimAudience])
		assert.Equal(t, testIssuer, claims[claimIssuer])
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
