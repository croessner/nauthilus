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

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// userTokenClaims returns the claims of a current JWT user access token for the fixture client.
func userTokenClaims(now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		oidcClaimIssuer:                  testIssuer,
		oidcClaimSubject:                 testUserID,
		oidcClaimAudience:                []any{testClientID, resourceTestMCP},
		oidcClaimExpiresAt:               float64(now.Add(time.Minute).Unix()),
		oidcClaimIssuedAt:                float64(now.Add(-time.Minute).Unix()),
		oidcClaimScope:                   definitions.ScopeHistoryRead + " openid",
		definitions.ClaimTokenType:       definitions.TokenTypeAccessToken,
		definitions.ClaimAuthorizedParty: testClientID,
	}
}

// TestNewUserAccessToken pins which verified tokens count as user access tokens of this issuer, for JWT and opaque
// formats alike.
func TestNewUserAccessToken(t *testing.T) {
	now := time.Now()

	for name, tc := range map[string]struct {
		mutate func(jwt.MapClaims)
		opaque bool
		ok     bool
	}{
		"jwt user token":           {func(jwt.MapClaims) {}, false, true},
		"opaque without iss":       {func(c jwt.MapClaims) { delete(c, oidcClaimIssuer) }, true, true},
		"opaque without iat":       {func(c jwt.MapClaims) { delete(c, oidcClaimIssuer); delete(c, oidcClaimIssuedAt) }, true, true},
		"jwt without iss":          {func(c jwt.MapClaims) { delete(c, oidcClaimIssuer) }, false, false},
		"jwt without iat":          {func(c jwt.MapClaims) { delete(c, oidcClaimIssuedAt) }, false, false},
		"foreign issuer":           {func(c jwt.MapClaims) { c[oidcClaimIssuer] = "https://evil.example.org" }, false, false},
		"opaque with foreign iss":  {func(c jwt.MapClaims) { c[oidcClaimIssuer] = "https://evil.example.org" }, true, false},
		"id token":                 {func(c jwt.MapClaims) { delete(c, definitions.ClaimTokenType) }, false, false},
		"service token":            {func(c jwt.MapClaims) { c[definitions.ClaimClientID] = testClientID }, false, false},
		"missing azp":              {func(c jwt.MapClaims) { delete(c, definitions.ClaimAuthorizedParty) }, false, false},
		"missing subject":          {func(c jwt.MapClaims) { delete(c, oidcClaimSubject) }, false, false},
		"missing expiry":           {func(c jwt.MapClaims) { delete(c, oidcClaimExpiresAt) }, true, false},
		"expired":                  {func(c jwt.MapClaims) { c[oidcClaimExpiresAt] = float64(now.Add(-time.Second).Unix()) }, false, false},
		"issued after expiry":      {func(c jwt.MapClaims) { c[oidcClaimIssuedAt] = float64(now.Add(time.Hour).Unix()) }, false, false},
		"malformed audience value": {func(c jwt.MapClaims) { c[oidcClaimAudience] = []any{testClientID, " padded"} }, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			claims := userTokenClaims(now)
			tc.mutate(claims)

			token, err := newUserAccessToken(claims, testIssuer, tc.opaque, now)
			if !tc.ok {
				assert.ErrorIs(t, err, ErrNotUserAccessToken)

				return
			}

			if !assert.NoError(t, err) {
				return
			}

			assert.Equal(t, testIssuer, token.Issuer)
			assert.Equal(t, testClientID, token.ClientID)
			assert.Equal(t, testUserID, token.Subject)
			assert.ElementsMatch(t, []string{testClientID, resourceTestMCP}, token.Audiences)
			assert.True(t, token.HasScope(definitions.ScopeHistoryRead))
			assert.False(t, token.HasScope("nauthilus:history"))
			assert.False(t, token.ExpiresAt.IsZero())
		})
	}

	if _, err := newUserAccessToken(userTokenClaims(now), "", false, now); err == nil {
		t.Fatal("an unset issuer must never accept a token")
	}
}

// TestOpaqueClaimsSatisfyUserAccessToken pins that opaque access-token claims carry the lifetime metadata a hosted
// resource server requires, so both token formats pass the same acceptance rules.
func TestOpaqueClaimsSatisfyUserAccessToken(t *testing.T) {
	now := time.Now()
	session := testOIDCSession([]string{definitions.ScopeHistoryRead}, now.Add(-time.Minute))
	session.AccessTokenResources = []string{resourceTestMCP}
	session.AccessTokenIssuedAt = now.Add(-time.Minute).UTC()
	session.AccessTokenExpiresAt = now.Add(time.Minute).UTC()

	claims := NewOpaqueAccessToken(session, nil, nil, 0).ClaimsFromSession(session)

	token, err := newUserAccessToken(claims, testIssuer, true, now)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, session.AccessTokenIssuedAt.Unix(), token.IssuedAt.Unix())
	assert.ElementsMatch(t, []string{testClientID, resourceTestMCP}, token.Audiences)

	session.AccessTokenExpiresAt = time.Time{}

	_, err = newUserAccessToken(NewOpaqueAccessToken(session, nil, nil, 0).ClaimsFromSession(session), testIssuer, true, now)
	assert.ErrorIs(t, err, ErrNotUserAccessToken, "an opaque token without expiry fails closed")
}

// TestValidateUserAccessTokenWithIssuedTokens drives tokens issued by the IdP itself through the typed entry point:
// the access token of a hosted-resource grant is accepted with its exact audience, the ID token of the same grant is
// refused.
func TestValidateUserAccessTokenWithIssuedTokens(t *testing.T) {
	fixture := newIDPTokenTestFixture(t)
	registerHostedTestResource(fixture)

	session := testOIDCSession([]string{"openid", definitions.ScopeHistoryRead}, time.Now().Add(-time.Minute))
	session.AccessTokenResources = []string{resourceTestMCP}

	expectUserTokenEpoch(fixture.mock, session.UserID)

	idToken, accessToken, _, _, err := fixture.idp.IssueTokens(fixture.ctx, session)
	if !assert.NoError(t, err) {
		return
	}

	expectAbsentSubjectEpochAndDenylist(fixture.mock, testUserID, accessToken)

	token, err := fixture.idp.ValidateUserAccessToken(fixture.ctx, accessToken)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, testIssuer, token.Issuer)
	assert.Equal(t, testClientID, token.ClientID)
	assert.Equal(t, testUserID, token.Subject)
	assert.ElementsMatch(t, []string{testClientID, resourceTestMCP}, token.Audiences)
	assert.True(t, token.HasScope(definitions.ScopeHistoryRead))
	assert.LessOrEqual(t, token.ExpiresAt.Sub(token.IssuedAt), 15*time.Minute)

	_, err = fixture.idp.ValidateUserAccessToken(fixture.ctx, idToken)
	assert.ErrorIs(t, err, ErrNotUserAccessToken)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}
