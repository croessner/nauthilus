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
	"context"
	"encoding/json"
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	nauthilusErrors "github.com/croessner/nauthilus/v4/server/errors"
	"github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/idp/dcr"
	"github.com/croessner/nauthilus/v4/server/idp/oidckeys"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
)

const classificationDynamicClientID = dcr.ClientIDPrefix + "classification-client"

// tokenValidationClassificationCase describes one token-state outcome and its expected classification.
type tokenValidationClassificationCase struct {
	expect      func(t *testing.T, mock redismock.ClientMock, token string)
	cause       error
	name        string
	unavailable bool
}

// redisConnectionError is a transport failure that go-redis reports for an unreachable server.
func redisConnectionError() error {
	return &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
}

// classificationOIDCConfig enables dynamic clients so both static and dynamic token paths are reachable.
func classificationOIDCConfig() config.OIDCConfig {
	return config.OIDCConfig{
		Issuer: testIssuer,
		DynamicClientRegistration: config.OIDCDynamicClientRegistrationConfig{
			Enabled:        true,
			RequiredScopes: []string{definitions.ScopeOpenID},
		},
	}
}

// opaqueSessionData serializes the stored state of an opaque access token.
func opaqueSessionData(t *testing.T, clientID string) string {
	t.Helper()

	data, err := json.Marshal(&OIDCSession{
		ClientID:         clientID,
		UserID:           testUserID,
		Scopes:           []string{definitions.ScopeOpenID},
		DynamicUserEpoch: testSubjectEpochFloor,
	})
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}

	return string(data)
}

// runTokenValidationClassification asserts that ValidateToken separates verdicts from technical failures.
func runTokenValidationClassification(
	t *testing.T,
	tests []tokenValidationClassificationCase,
	token func(t *testing.T) string,
) {
	t.Helper()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			idp, mock, _ := newTestIDPWithMock(t, classificationOIDCConfig())
			mock.MatchExpectationsInOrder(false)

			tokenString := token(t)
			test.expect(t, mock, tokenString)

			claims, err := idp.ValidateToken(t.Context(), tokenString)
			if err == nil || claims != nil {
				t.Fatalf("ValidateToken() = (%v, %v), want rejection or technical failure", claims, err)
			}

			if got := nauthilusErrors.IsTokenValidationUnavailable(err); got != test.unavailable {
				t.Fatalf("IsTokenValidationUnavailable(%v) = %t, want %t", err, got, test.unavailable)
			}

			if test.cause != nil && !errors.Is(err, test.cause) {
				t.Fatalf("ValidateToken() error = %v, want cause %v", err, test.cause)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("Redis expectations: %v", err)
			}
		})
	}
}

// TestValidateTokenOpaqueClassifiesTokenStateFailures pins which opaque-token outcomes reject the token and
// which only report that validation could not decide.
//
//nolint:funlen // One table keeps every opaque-token outcome visible next to its classification.
func TestValidateTokenOpaqueClassifiesTokenStateFailures(t *testing.T) {
	tests := []tokenValidationClassificationCase{
		{
			name: "unknown token",
			expect: func(_ *testing.T, mock redismock.ClientMock, token string) {
				expectMissingAccessToken(mock, token)
			},
		},
		{
			name: "undecodable token state",
			expect: func(_ *testing.T, mock redismock.ClientMock, token string) {
				expectAccessTokenState(mock, testUserID, token).SetVal([]any{"not-a-session", nil})
			},
		},
		{
			name: "user epoch revoked",
			expect: func(t *testing.T, mock redismock.ClientMock, token string) {
				expectAccessTokenState(mock, testUserID, token).SetVal([]any{opaqueSessionData(t, testClientID), "1"})
			},
		},
		{
			name: "dynamic client no longer registered",
			expect: func(t *testing.T, mock redismock.ClientMock, token string) {
				expectAccessTokenLookup(mock, testUserID, token, opaqueSessionData(t, classificationDynamicClientID))
				mock.ExpectGet(testDynamicClientKey(classificationDynamicClientID)).RedisNil()
			},
		},
		{
			name: "token store unreachable",
			expect: func(_ *testing.T, mock redismock.ClientMock, token string) {
				expectAccessTokenLocatorError(mock, token, redisConnectionError())
			},
			unavailable: true,
		},
		{
			name: "request context canceled",
			expect: func(_ *testing.T, mock redismock.ClientMock, token string) {
				expectAccessTokenLocatorError(mock, token, context.Canceled)
			},
			cause:       context.Canceled,
			unavailable: true,
		},
		{
			name: "request deadline exceeded",
			expect: func(_ *testing.T, mock redismock.ClientMock, token string) {
				expectAccessTokenLocatorError(mock, token, context.DeadlineExceeded)
			},
			cause:       context.DeadlineExceeded,
			unavailable: true,
		},
		{
			name: "token state and epoch unreachable",
			expect: func(_ *testing.T, mock redismock.ClientMock, token string) {
				expectAccessTokenState(mock, testUserID, token).SetErr(redisConnectionError())
			},
			unavailable: true,
		},
		{
			name: "dynamic client registry unreachable",
			expect: func(t *testing.T, mock redismock.ClientMock, token string) {
				expectAccessTokenLookup(mock, testUserID, token, opaqueSessionData(t, classificationDynamicClientID))
				mock.ExpectGet(testDynamicClientKey(classificationDynamicClientID)).SetErr(redisConnectionError())
			},
			cause:       dcr.ErrUnavailable,
			unavailable: true,
		},
	}

	runTokenValidationClassification(t, tests, func(*testing.T) string {
		return "na_at_classification"
	})
}

// TestValidateTokenJWTClassifiesTokenStateFailures pins the same separation for JWT access tokens, including
// verification-key resolution.
//
//nolint:funlen // One table keeps every JWT outcome visible next to its classification.
func TestValidateTokenJWTClassifiesTokenStateFailures(t *testing.T) {
	const kid = "classification-key"

	pemData := generateTestKey()
	metadata := func(t *testing.T) string {
		t.Helper()

		return redisKeyMetadataJSON(t, kid, pemData)
	}

	tests := []tokenValidationClassificationCase{
		{
			name: "denylisted token",
			expect: func(t *testing.T, mock redismock.ClientMock, token string) {
				mock.ExpectHGet(testOIDCKeysHashKey(), kid).SetVal(metadata(t))
				expectUserTokenEpoch(mock, testUserID)
				expectDeniedAccessTokenLookup(mock, token, true)
			},
		},
		{
			name: "unknown signing key",
			expect: func(_ *testing.T, mock redismock.ClientMock, _ string) {
				mock.ExpectHGet(testOIDCKeysHashKey(), kid).RedisNil()
			},
		},
		{
			name: "denylist unreachable",
			expect: func(t *testing.T, mock redismock.ClientMock, token string) {
				mock.ExpectHGet(testOIDCKeysHashKey(), kid).SetVal(metadata(t))
				expectUserTokenEpoch(mock, testUserID)
				expectDeniedAccessTokenLookupError(mock, token, redisConnectionError())
			},
			unavailable: true,
		},
		{
			name: "user epoch unreachable",
			expect: func(t *testing.T, mock redismock.ClientMock, _ string) {
				mock.ExpectHGet(testOIDCKeysHashKey(), kid).SetVal(metadata(t))
				mock.ExpectGet(testUserTokenEpochKey(testUserID)).SetErr(redisConnectionError())
			},
			unavailable: true,
		},
		{
			name: "signing key store unreachable",
			expect: func(_ *testing.T, mock redismock.ClientMock, _ string) {
				mock.ExpectHGet(testOIDCKeysHashKey(), kid).SetErr(redisConnectionError())
			},
			unavailable: true,
		},
	}

	runTokenValidationClassification(t, tests, func(t *testing.T) string {
		return signedTestAccessToken(t, kid, pemData)
	})
}

// TestValidateTokenJWTRejectsForgedTokensWithoutTechnicalClassification pins that attacker-controlled input
// never reaches the technical classification, which would turn a rejection into a 503 without delay.
func TestValidateTokenJWTRejectsForgedTokensWithoutTechnicalClassification(t *testing.T) {
	const kid = "forged-key"

	signingKey := generateTestKey()
	otherKey := generateTestKey()

	tests := []tokenValidationClassificationCase{
		{
			name:   "malformed token",
			expect: func(*testing.T, redismock.ClientMock, string) {},
		},
		{
			name: "signature from a different key",
			expect: func(t *testing.T, mock redismock.ClientMock, _ string) {
				mock.ExpectHGet(testOIDCKeysHashKey(), kid).SetVal(redisKeyMetadataJSON(t, kid, otherKey))
			},
		},
	}

	runTokenValidationClassification(t, tests[:1], func(*testing.T) string {
		return "not.a.jwt"
	})
	runTokenValidationClassification(t, tests[1:], func(t *testing.T) string {
		return signedTestAccessToken(t, kid, signingKey)
	})
}

// TestValidateTokenKidlessJWTClassifiesKeyStoreFailures pins the verification-only fallback for tokens
// without kid: an unreadable key store is technical, an absent active key rejects the token, and neither
// path generates keys even when automatic rotation is enabled.
func TestValidateTokenKidlessJWTClassifiesKeyStoreFailures(t *testing.T) {
	pemData := generateTestKey()
	activeKey := testRedisPrefix + oidckeys.RedisKeyOIDCActive

	tests := []struct {
		expect      func(t *testing.T, mock redismock.ClientMock)
		name        string
		unavailable bool
	}{
		{
			name: "active key id unreadable",
			expect: func(_ *testing.T, mock redismock.ClientMock) {
				mock.ExpectGet(activeKey).SetErr(redisConnectionError())
			},
			unavailable: true,
		},
		{
			name: "active key material unreadable",
			expect: func(_ *testing.T, mock redismock.ClientMock) {
				mock.ExpectGet(activeKey).SetVal("active-key")
				mock.ExpectHGet(testOIDCKeysHashKey(), "active-key").SetErr(redisConnectionError())
			},
			unavailable: true,
		},
		{
			name: "no active key",
			expect: func(_ *testing.T, mock redismock.ClientMock) {
				mock.ExpectGet(activeKey).RedisNil()
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			oidcConfig := classificationOIDCConfig()
			oidcConfig.AutoKeyRotation = true

			idp, mock, _ := newTestIDPWithMock(t, oidcConfig)
			test.expect(t, mock)

			_, err := idp.ValidateToken(t.Context(), signedTestAccessToken(t, "", pemData))
			if err == nil {
				t.Fatal("ValidateToken() error = nil, want failure")
			}

			if got := nauthilusErrors.IsTokenValidationUnavailable(err); got != test.unavailable {
				t.Fatalf("IsTokenValidationUnavailable(%v) = %t, want %t", err, got, test.unavailable)
			}

			// Any key generation would issue unexpected Redis writes and leave the mock unsatisfied or failing.
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("Redis expectations: %v", err)
			}
		})
	}
}

// TestValidateTokenKidlessJWTNeverGeneratesKeys pins that validating a token without kid leaves the key store
// untouched, even with automatic key rotation enabled and no active key present.
func TestValidateTokenKidlessJWTNeverGeneratesKeys(t *testing.T) {
	server := miniredis.RunT(t)
	handle := redis.NewClient(&redis.Options{Addr: server.Addr()})

	t.Cleanup(func() {
		_ = handle.Close()
	})

	oidcConfig := classificationOIDCConfig()
	oidcConfig.AutoKeyRotation = true

	cfg := &mockIdpConfig{
		FileSettings: &config.FileSettings{Server: &config.ServerSection{Redis: config.Redis{Prefix: testRedisPrefix}}},
		oidc:         oidcConfig,
	}
	idp := NewNauthilusIDP(&deps.Deps{Cfg: cfg, Redis: rediscli.NewTestClient(handle)})

	if _, err := idp.ValidateToken(t.Context(), signedTestAccessToken(t, "", generateTestKey())); err == nil {
		t.Fatal("ValidateToken() error = nil, want rejection without an active key")
	}

	if keys := server.Keys(); len(keys) != 0 {
		t.Fatalf("token validation wrote Redis keys %v", keys)
	}
}
