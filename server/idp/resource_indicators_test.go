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
	"encoding/json"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

const (
	resourceTestMail    = "https://mail.example.org/jmap"
	resourceTestCalDAV  = "https://dav.example.org"
	resourceTestUnknown = "https://unknown.example.org"
)

func TestAccessTokenIssuingClient(t *testing.T) {
	cases := []struct {
		name   string
		claims jwt.MapClaims
		want   string
		wantOK bool
	}{
		{name: "authorized party wins", claims: jwt.MapClaims{"azp": "webmail", "aud": []string{"webmail", resourceTestMail}}, want: "webmail", wantOK: true},
		{name: "legacy string audience", claims: jwt.MapClaims{"aud": "webmail"}, want: "webmail", wantOK: true},
		{name: "legacy single array audience", claims: jwt.MapClaims{"aud": []any{"webmail"}}, want: "webmail", wantOK: true},
		{name: "array audience without authorized party", claims: jwt.MapClaims{"aud": []string{"webmail", resourceTestMail}}},
		{name: "malformed authorized party does not fall back", claims: jwt.MapClaims{"azp": 42, "aud": "webmail"}},
		{name: "empty authorized party does not fall back", claims: jwt.MapClaims{"azp": "", "aud": "webmail"}},
		{name: "missing identity", claims: jwt.MapClaims{}},
		{name: "nil claims"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := AccessTokenIssuingClient(tc.claims)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestAccessTokenResourceAudiences(t *testing.T) {
	resources, ok := AccessTokenResourceAudiences(jwt.MapClaims{"aud": []any{"webmail", resourceTestMail}}, "webmail")
	assert.True(t, ok)
	assert.Equal(t, []string{resourceTestMail}, resources)

	resources, ok = AccessTokenResourceAudiences(jwt.MapClaims{"aud": "webmail"}, "webmail")
	assert.True(t, ok)
	assert.Empty(t, resources)

	_, ok = AccessTokenResourceAudiences(jwt.MapClaims{"aud": 42}, "webmail")
	assert.False(t, ok)
}

func TestNarrowAccessTokenResources(t *testing.T) {
	granted := []string{resourceTestMail, resourceTestCalDAV}

	cases := []struct {
		name      string
		requested []string
		want      []string
		wantErr   bool
	}{
		{name: "no request keeps the grant"},
		{name: "subset", requested: []string{resourceTestCalDAV}, want: []string{resourceTestCalDAV}},
		{name: "duplicates collapse", requested: []string{resourceTestMail, resourceTestMail}, want: []string{resourceTestMail}},
		{name: "outside the grant", requested: []string{resourceTestMail, resourceTestUnknown}, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NarrowAccessTokenResources(granted, tc.requested)
			if tc.wantErr {
				assert.ErrorIs(t, err, ErrInvalidTarget)

				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	_, err := NarrowAccessTokenResources(nil, []string{resourceTestMail})
	assert.ErrorIs(t, err, ErrInvalidTarget)
}

func TestValidateRequestedResources(t *testing.T) {
	clients := registryTestClients()
	registry := NewResourceRegistry(clients)
	webmail := &clients[1]

	cases := []struct {
		name      string
		requested []string
		want      []string
		wantErr   bool
	}{
		{name: "none"},
		{name: "registered and allowed", requested: []string{registryTestMailResource, registryTestOtherResource}, want: []string{registryTestMailResource, registryTestOtherResource}},
		{name: "duplicates collapse", requested: []string{registryTestMailResource, registryTestMailResource}, want: []string{registryTestMailResource}},
		{name: "unregistered", requested: []string{resourceTestUnknown}, wantErr: true},
		{name: "relative", requested: []string{"/jmap"}, wantErr: true},
		{name: "fragment", requested: []string{registryTestMailResource + "#frag"}, wantErr: true},
		{name: "empty", requested: []string{""}, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := registry.ValidateRequestedResources(webmail, tc.requested)
			if tc.wantErr {
				assert.ErrorIs(t, err, ErrInvalidTarget)

				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	_, err := registry.ValidateRequestedResources(&clients[2], []string{registryTestMailResource})
	assert.ErrorIs(t, err, ErrInvalidTarget, "a client outside the owner's allowlist must not obtain the resource")
}

// unverifiedAudience decodes the audience of an issued JWT without verifying it.
func unverifiedAudience(t *testing.T, token string) any {
	t.Helper()

	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(token, claims)
	assert.NoError(t, err)

	return claims["aud"]
}

// registerTestResourceServer adds a resource server that owns the mail and CalDAV resources and
// allowlists the fixture client.
func registerTestResourceServer(fixture idpTokenTestFixture) *config.OIDCClient {
	fixture.cfg.oidc.Clients = append(fixture.cfg.oidc.Clients, config.OIDCClient{
		ClientID: "mail-rs", ClientSecret: secret.New("test-secret"),
		TokenIntrospection: config.OIDCTokenIntrospection{
			Resources: []string{resourceTestMail, resourceTestCalDAV}, Clients: []string{testClientID},
		},
	})

	return &fixture.cfg.oidc.Clients[len(fixture.cfg.oidc.Clients)-1]
}

func TestIssueTokensWithOptionsNarrowsOnlyTheAccessToken(t *testing.T) {
	fixture := newIDPTokenTestFixture(t)
	registerTestResourceServer(fixture)
	session := testOIDCSession([]string{"openid", "offline_access"}, fixture.fixedTime)
	session.AccessTokenResources = []string{resourceTestMail, resourceTestCalDAV}

	_, _, _, _, err := fixture.idp.IssueTokensWithOptions(fixture.ctx, session, TokenIssueOptions{Resources: []string{resourceTestUnknown}})
	assert.ErrorIs(t, err, ErrInvalidTarget)

	expectUserTokenEpoch(fixture.mock, session.UserID)
	expectFixedRefreshTokenStore(fixture.mock)

	_, accessToken, refreshToken, _, err := fixture.idp.IssueTokensWithOptions(fixture.ctx, session, TokenIssueOptions{Resources: []string{resourceTestCalDAV}})
	assert.NoError(t, err)
	assert.NotEmpty(t, refreshToken)
	assert.Equal(t, []any{testClientID, resourceTestCalDAV}, unverifiedAudience(t, accessToken))
	assert.Equal(t, []string{resourceTestMail, resourceTestCalDAV}, session.AccessTokenResources, "the refresh grant keeps every resource")
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

func TestIssueTokensKeepsFullResourceGrant(t *testing.T) {
	fixture := newIDPTokenTestFixture(t)
	registerTestResourceServer(fixture)
	session := testOIDCSession([]string{"openid"}, fixture.fixedTime)
	session.AccessTokenResources = []string{resourceTestMail}

	expectUserTokenEpoch(fixture.mock, session.UserID)

	_, accessToken, _, _, err := fixture.idp.IssueTokens(fixture.ctx, session)
	assert.NoError(t, err)
	assert.Equal(t, []any{testClientID, resourceTestMail}, unverifiedAudience(t, accessToken))

	claims := jwt.MapClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(accessToken, claims)
	assert.NoError(t, err)
	assert.Equal(t, testClientID, claims[definitions.ClaimAuthorizedParty])
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

func TestExchangeRefreshTokenWithOptionsNeverWidensTheGrant(t *testing.T) {
	fixture := newIDPTokenTestFixture(t)
	registerTestResourceServer(fixture)
	session := testRefreshOIDCSession("header.payload.signature", fixture.fixedTime)
	session.AccessTokenResources = []string{resourceTestMail, resourceTestCalDAV}
	sessionData, err := json.Marshal(session)
	assert.NoError(t, err)

	// A resource outside the stored grant is rejected before the refresh token is consumed.
	expectStaticRefreshTokenLoad(fixture.mock, "narrow-rt", string(sessionData))

	_, _, _, _, _, err = fixture.idp.ExchangeRefreshTokenWithOptions(fixture.ctx, "narrow-rt", testClientID, TokenIssueOptions{Resources: []string{resourceTestUnknown}})
	assert.ErrorIs(t, err, ErrInvalidTarget)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())

	expectJWTRefreshTokenExchange(fixture.mock, "narrow-rt", session.AccessToken, string(sessionData))

	exchanged, _, accessToken, newRefreshToken, _, err := fixture.idp.ExchangeRefreshTokenWithOptions(fixture.ctx, "narrow-rt", testClientID, TokenIssueOptions{Resources: []string{resourceTestMail}})
	if !assert.NoError(t, err) {
		return
	}

	assert.NotEmpty(t, newRefreshToken)
	assert.Equal(t, []any{testClientID, resourceTestMail}, unverifiedAudience(t, accessToken))
	assert.Equal(t, []string{resourceTestMail, resourceTestCalDAV}, exchanged.AccessTokenResources)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

func TestIssueTokensRejectsResourcesNoLongerAllowlisted(t *testing.T) {
	fixture := newIDPTokenTestFixture(t)
	resourceServer := registerTestResourceServer(fixture)
	resourceServer.TokenIntrospection.Clients = []string{"another-client"}

	session := testOIDCSession([]string{"openid"}, fixture.fixedTime)
	session.AccessTokenResources = []string{resourceTestMail}

	_, _, _, _, err := fixture.idp.IssueTokens(fixture.ctx, session)
	assert.ErrorIs(t, err, ErrInvalidTarget)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}
