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
	"time"

	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/stretchr/testify/assert"
)

const resourceTestMCP = "https://login.example.org/mcp"

// hostedTestResource returns a hosted resource that admits the fixture client.
func hostedTestResource() config.OIDCHostedResource {
	return config.OIDCHostedResource{
		Name:          "support-mcp",
		Resource:      resourceTestMCP,
		Scopes:        []string{definitions.ScopeHistoryRead},
		StaticClients: []string{testClientID},
		UserRight:     config.OIDCHostedResourceUserRight{From: config.HostedResourceUserRightFromGroups, AnyOf: []string{"support"}},
	}
}

// registerHostedTestResource adds the hosted test resource to the fixture configuration.
func registerHostedTestResource(fixture idpTokenTestFixture) {
	fixture.cfg.oidc.HostedResources = append(fixture.cfg.oidc.HostedResources, hostedTestResource())
}

// TestHostedResourceAdmission pins that only listed static clients may request a hosted resource, that a dynamic
// client is refused even under a listed id, that a hosted grant never carries another resource, that the device flow
// never grants it, and that delegated introspection never matches it.
func TestHostedResourceAdmission(t *testing.T) {
	fixture := newIDPTokenTestFixture(t)
	registerTestResourceServer(fixture)
	registerHostedTestResource(fixture)

	registry := fixture.idp.ResourceRegistry()
	listed := &config.OIDCClient{ClientID: testClientID}

	for name, tc := range map[string]struct {
		client *config.OIDCClient
		want   bool
	}{
		"listed static client":         {listed, true},
		"unlisted static client":       {&config.OIDCClient{ClientID: "other"}, false},
		"dynamic client under that id": {&config.OIDCClient{ClientID: testClientID, Dynamic: true}, false},
		"missing client":               {nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, registry.MayRequest(tc.client, resourceTestMCP))
		})
	}

	resources, err := registry.ValidateRequestedResources(listed, []string{resourceTestMCP, resourceTestMCP})
	assert.NoError(t, err)
	assert.Equal(t, []string{resourceTestMCP}, resources)

	_, err = registry.ValidateRequestedResources(listed, []string{resourceTestMCP, resourceTestMail})
	assert.ErrorIs(t, err, ErrInvalidTarget, "a hosted resource must not share a grant")

	_, err = registry.ValidateDeviceRequestedResources(listed, []string{resourceTestMCP})
	assert.ErrorIs(t, err, ErrInvalidTarget, "the device flow never grants a hosted resource")

	resources, err = registry.ValidateDeviceRequestedResources(listed, []string{resourceTestMail})
	assert.NoError(t, err)
	assert.Equal(t, []string{resourceTestMail}, resources)

	owner, _ := registry.ResourceOwner(resourceTestMail)
	assert.False(t, registry.MayIntrospect(owner, IntrospectedUserToken{IssuingClient: listed, Resources: []string{resourceTestMCP}}))

	_, owned := registry.ResourceOwner(resourceTestMCP)
	assert.False(t, owned, "a hosted resource has no owner client")
}

// TestHostedResourceUserRightAndAge pins the group source, the login age boundary, and the lifetime ceiling.
func TestHostedResourceUserRightAndAge(t *testing.T) {
	cfg := hostedTestResource()
	hosted, _ := NewHostedResource(&cfg)
	user := backend.NewUser("anna", "Anna", "anna-id")
	user.Groups = []string{"staff", "support"}
	user.GroupDistinguishedNames = []string{"cn=staff,dc=example,dc=org"}

	assert.True(t, hosted.PermitsUser(user))
	assert.False(t, hosted.PermitsUser(nil))

	cfg.UserRight = config.OIDCHostedResourceUserRight{From: config.HostedResourceUserRightFromGroupDistinguishedNames, AnyOf: []string{"support"}}

	assert.False(t, hosted.PermitsUser(user), "group_dns must not match plain group names")

	cfg.UserRight.AnyOf = []string{"cn=staff,dc=example,dc=org"}

	assert.True(t, hosted.PermitsUser(user))

	now := time.Date(2026, 11, 18, 8, 0, 0, 0, time.UTC)
	assert.True(t, hosted.AuthenticationCurrent(now.Add(-12*time.Hour), now))
	assert.False(t, hosted.AuthenticationCurrent(now.Add(-12*time.Hour-time.Second), now))
	assert.False(t, hosted.AuthenticationCurrent(time.Time{}, now))
	assert.False(t, hosted.AuthenticationCurrent(now.Add(time.Minute), now), "a login in the future is never current")

	assert.Equal(t, 15*time.Minute, hosted.capAccessTokenLifetime(2*time.Hour))
	assert.Equal(t, 5*time.Minute, hosted.capAccessTokenLifetime(5*time.Minute))

	request := &core.IdentityAttributeRequest{}
	hosted.requestsGroups(request)
	assert.True(t, request.IncludeGroupDistinguishedNames)
	assert.False(t, request.IncludeGroups)
}

// TestAdmitHostedResourceUser pins the authorization-time decision on a fresh backend lookup.
func TestAdmitHostedResourceUser(t *testing.T) {
	fixture := newIDPTokenTestFixture(t)
	registerHostedTestResource(fixture)

	now := time.Now()
	entitled := backend.NewUser("anna", "Anna", "anna-id")
	entitled.Groups = []string{"support"}
	other := backend.NewUser("bob", "Bob", "bob-id")

	assert.NoError(t, fixture.idp.AdmitHostedResourceUser([]string{resourceTestMCP}, entitled, now.Add(-time.Minute), now))
	assert.ErrorIs(t, fixture.idp.AdmitHostedResourceUser([]string{resourceTestMCP}, other, now.Add(-time.Minute), now), ErrHostedResourceDenied)
	assert.ErrorIs(t, fixture.idp.AdmitHostedResourceUser([]string{resourceTestMCP}, entitled, now.Add(-13*time.Hour), now), ErrHostedAuthenticationExpired)
	assert.NoError(t, fixture.idp.AdmitHostedResourceUser(nil, other, time.Time{}, now), "requests without a hosted resource are not affected")

	assert.True(t, fixture.idp.HostedAuthenticationExpired([]string{resourceTestMCP}, now.Add(-13*time.Hour), now))
	assert.False(t, fixture.idp.HostedAuthenticationExpired([]string{resourceTestMCP}, now.Add(-time.Hour), now))
	assert.False(t, fixture.idp.HostedAuthenticationExpired([]string{resourceTestMail}, time.Time{}, now))
}

// TestIssueTokensForHostedResource pins the exact audience, the lifetime ceiling, and the refusal of a grant whose
// login is older than max_authentication_age.
func TestIssueTokensForHostedResource(t *testing.T) {
	fixture := newIDPTokenTestFixture(t)
	registerHostedTestResource(fixture)

	session := testOIDCSession([]string{"openid", definitions.ScopeHistoryRead}, time.Now().Add(-time.Minute))
	session.AccessTokenResources = []string{resourceTestMCP}

	expectUserTokenEpoch(fixture.mock, session.UserID)

	_, accessToken, _, expiresIn, err := fixture.idp.IssueTokens(fixture.ctx, session)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, 15*time.Minute, expiresIn)
	assert.Equal(t, []any{testClientID, resourceTestMCP}, unverifiedAudience(t, accessToken))

	stale := testOIDCSession([]string{"openid"}, time.Now().Add(-13*time.Hour))
	stale.AccessTokenResources = []string{resourceTestMCP}

	_, _, _, _, err = fixture.idp.IssueTokens(fixture.ctx, stale)
	assert.ErrorIs(t, err, ErrHostedAuthenticationExpired)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

// TestDeviceGrantNeverIssuesHostedResource pins the issuance-time refusal of a device grant that carries a hosted
// resource, for example one whose resource became hosted while the device code was pending.
func TestDeviceGrantNeverIssuesHostedResource(t *testing.T) {
	fixture := newIDPTokenTestFixture(t)
	registerHostedTestResource(fixture)

	session := testOIDCSession([]string{"openid"}, time.Now())
	session.AccessTokenResources = []string{resourceTestMCP}

	_, _, _, _, err := fixture.idp.IssueTokensWithOptions(fixture.ctx, session, TokenIssueOptions{DeviceGrant: true})
	assert.ErrorIs(t, err, ErrInvalidTarget)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}

// TestRefreshForHostedResourceAfterAuthenticationAge pins that a refresh after max_authentication_age is refused
// before the refresh token is consumed.
func TestRefreshForHostedResourceAfterAuthenticationAge(t *testing.T) {
	fixture := newIDPTokenTestFixture(t)
	registerHostedTestResource(fixture)

	session := testRefreshOIDCSession("header.payload.signature", time.Now().Add(-13*time.Hour))
	session.AccessTokenResources = []string{resourceTestMCP}

	sessionData, err := json.Marshal(session)
	assert.NoError(t, err)

	expectStaticRefreshTokenLoad(fixture.mock, "hosted-rt", string(sessionData))

	_, _, _, _, _, err = fixture.idp.ExchangeRefreshTokenWithOptions(fixture.ctx, "hosted-rt", testClientID, TokenIssueOptions{})
	assert.ErrorIs(t, err, ErrHostedAuthenticationExpired)
	assert.NoError(t, fixture.mock.ExpectationsWereMet())
}
