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
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	coreidp "github.com/croessner/nauthilus/v4/server/idp"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

const (
	introspectionTestMailResource  = "https://mail.example.org/jmap"
	introspectionTestOtherResource = "https://other.example.org/api"
	introspectionTestDynamicClient = "dcr_native-client"
	introspectionTestMissingClient = "dcr_unknown-client"
)

// delegatedIntrospectionClients returns a mail resource server, an allowlisted issuer, a foreign issuer,
// and a second resource server.
func delegatedIntrospectionClients() []config.OIDCClient {
	return []config.OIDCClient{
		{
			ClientID: "mail-rs", ClientSecret: secret.New("test-secret"),
			TokenIntrospection: config.OIDCTokenIntrospection{
				Resources: []string{introspectionTestMailResource}, Clients: []string{"webmail"},
				DynamicClientProfiles: []string{"mail-client-v1"},
			},
		},
		{ClientID: "webmail"},
		{ClientID: "foreign-app"},
		{
			ClientID: "other-rs", ClientSecret: secret.New("test-secret"),
			TokenIntrospection: config.OIDCTokenIntrospection{Resources: []string{introspectionTestOtherResource}, Clients: []string{"webmail"}},
		},
	}
}

// delegatedIntrospectionPolicy resolves static clients and one dynamic client of the mail profile.
func delegatedIntrospectionPolicy(clients []config.OIDCClient, dynamicProfile string) accessTokenIntrospectionPolicy {
	resolve := func(_ context.Context, clientID string) (*config.OIDCClient, error) {
		for idx := range clients {
			if clients[idx].ClientID == clientID {
				return &clients[idx], nil
			}
		}

		if clientID == introspectionTestDynamicClient {
			return &config.OIDCClient{ClientID: clientID, Dynamic: true, DynamicProfile: dynamicProfile}, nil
		}

		return nil, errors.New("client not found")
	}

	return accessTokenIntrospectionPolicy{resources: coreidp.NewResourceRegistry(clients), resolveClient: resolve}
}

// userTokenClaims builds validated user access-token claims.
func userTokenClaims(audience any, authorizedParty any) jwt.MapClaims {
	claims := jwt.MapClaims{"aud": audience, definitions.ClaimTokenType: definitions.TokenTypeAccessToken}
	if authorizedParty != nil {
		claims[definitions.ClaimAuthorizedParty] = authorizedParty
	}

	return claims
}

func TestAccessTokenIntrospectionPolicyDelegatedUserTokens(t *testing.T) {
	clients := delegatedIntrospectionClients()
	serviceToken := jwt.MapClaims{
		"aud": definitions.AudienceBackchannelAPI, definitions.ClaimClientID: "webmail",
		definitions.ClaimTokenType: definitions.TokenTypeAccessToken,
	}
	policyToken := jwt.MapClaims{
		"aud": definitions.AudiencePolicyAPI, definitions.ClaimClientID: "webmail",
		definitions.ClaimTokenType: definitions.TokenTypeAccessToken,
	}
	idToken := jwt.MapClaims{"aud": "webmail", definitions.ClaimTokenType: definitions.TokenTypeIDToken}

	cases := []struct {
		name           string
		caller         *config.OIDCClient
		claims         jwt.MapClaims
		dynamicProfile string
		want           bool
	}{
		{name: "allowlisted static issuer", caller: &clients[0], claims: userTokenClaims("webmail", "webmail"), want: true},
		{name: "legacy token without azp", caller: &clients[0], claims: userTokenClaims("webmail", nil), want: true},
		{name: "issuer not allowlisted", caller: &clients[0], claims: userTokenClaims("foreign-app", "foreign-app")},
		{name: "allowlisted dynamic profile", caller: &clients[0], claims: userTokenClaims(introspectionTestDynamicClient, introspectionTestDynamicClient), dynamicProfile: "mail-client-v1", want: true},
		{name: "dynamic client without matching profile", caller: &clients[0], claims: userTokenClaims(introspectionTestDynamicClient, introspectionTestDynamicClient), dynamicProfile: "other-profile"},
		{name: "dynamic client unresolvable", caller: &clients[0], claims: userTokenClaims(introspectionTestMissingClient, introspectionTestMissingClient), dynamicProfile: "mail-client-v1"},
		{name: "own resource from foreign issuer", caller: &clients[0], claims: userTokenClaims([]any{"foreign-app", introspectionTestMailResource}, "foreign-app"), want: true},
		{name: "foreign resource despite allowlisted issuer", caller: &clients[0], claims: userTokenClaims([]any{"webmail", introspectionTestOtherResource}, "webmail")},
		{name: "array audience without azp", caller: &clients[0], claims: userTokenClaims([]any{"webmail", introspectionTestMailResource}, nil)},
		{name: "malformed azp", caller: &clients[0], claims: userTokenClaims("webmail", 42)},
		{name: "backchannel service token", caller: &clients[0], claims: serviceToken},
		{name: "policy service token", caller: &clients[0], claims: policyToken},
		{name: "id token", caller: &clients[0], claims: idToken},
		{name: "caller without token introspection", caller: &clients[2], claims: userTokenClaims("webmail", "webmail")},
		{name: "own token keeps working", caller: &clients[1], claims: userTokenClaims([]any{"webmail", introspectionTestMailResource}, "webmail"), want: true},
		{name: "dynamic caller", caller: &config.OIDCClient{ClientID: "mail-rs", Dynamic: true, TokenIntrospection: clients[0].TokenIntrospection}, claims: userTokenClaims("webmail", "webmail")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := delegatedIntrospectionPolicy(clients, tc.dynamicProfile)
			assert.Equal(t, tc.want, policy.allows(context.Background(), tc.caller, tc.claims))
		})
	}
}

func TestOIDCHandler_ResourceServerIntrospection(t *testing.T) {
	f := newOIDCIntrospectionTest(t)
	cfg := f.handler.deps.Cfg.(*mockOIDCCfg)
	ctx := context.Background()

	// test-client is the resource server; jwt-client issued the user token.
	f.expectAccessTokenValidation("jwt-user", f.privateKeyJWTAccessToken, 1)
	denied := f.postIntrospection(t, url.Values{"token": {f.privateKeyJWTAccessToken}}, "test-client", "test-secret")
	assert.Equal(t, map[string]any{"active": false}, mustDecodeOIDCTestJSON(t, denied))

	cfg.clients[0].TokenIntrospection = config.OIDCTokenIntrospection{
		Resources: []string{introspectionTestMailResource}, Clients: []string{"jwt-client"},
	}
	cfg.clients = append(cfg.clients, config.OIDCClient{
		ClientID: "other-rs", ClientSecret: secret.New("test-secret"),
		TokenIntrospection: config.OIDCTokenIntrospection{Resources: []string{introspectionTestOtherResource}, Clients: []string{"jwt-client"}},
	})

	f.expectAccessTokenValidation("jwt-user", f.privateKeyJWTAccessToken, 1)
	allowed := mustDecodeOIDCTestJSON(t, f.postIntrospection(t, url.Values{"token": {f.privateKeyJWTAccessToken}}, "test-client", "test-secret"))
	assert.Equal(t, true, allowed["active"])
	assert.Equal(t, "jwt-client", allowed["azp"])
	assert.Equal(t, "jwt-client", allowed["aud"])
	assert.Nil(t, allowed[definitions.ClaimClientID])

	ownResourceToken := f.issueResourceToken(t, "mail-user", introspectionTestMailResource)
	f.expectAccessTokenValidation("mail-user", ownResourceToken, 1)
	resource := mustDecodeOIDCTestJSON(t, f.postIntrospection(t, url.Values{"token": {ownResourceToken}}, "test-client", "test-secret"))
	assert.Equal(t, true, resource["active"])
	assert.Equal(t, []any{"jwt-client", introspectionTestMailResource}, resource["aud"])
	assert.Equal(t, "jwt-client", resource["azp"])

	foreignResourceToken := f.issueResourceToken(t, "other-user", introspectionTestOtherResource)
	f.expectAccessTokenValidation("other-user", foreignResourceToken, 1)
	foreign := f.postIntrospection(t, url.Values{"token": {foreignResourceToken}}, "test-client", "test-secret")
	assert.Equal(t, map[string]any{"active": false}, mustDecodeOIDCTestJSON(t, foreign))

	cfg.clients[1].GrantTypes = []string{"client_credentials"}
	cfg.clients[1].ClientSecret = cfg.clients[0].ClientSecret

	f.mock.ExpectGet(testUserTokenEpochKey("jwt-client")).RedisNil()
	serviceToken, _, err := f.handler.idp.IssueClientCredentialsToken(ctx, "jwt-client", []string{definitions.ScopeAuthenticate})
	assert.NoError(t, err)

	f.expectAccessTokenValidation("jwt-client", serviceToken, 1)
	service := f.postIntrospection(t, url.Values{"token": {serviceToken}}, "test-client", "test-secret")
	assert.Equal(t, http.StatusOK, service.Code)
	assert.Equal(t, map[string]any{"active": false}, mustDecodeOIDCTestJSON(t, service))
	assert.NoError(t, f.mock.ExpectationsWereMet())
}

// issueResourceToken issues a JWT user access token of jwt-client bound to one resource.
func (f *oidcIntrospectionTest) issueResourceToken(t *testing.T, userID string, resource string) string {
	t.Helper()

	f.mock.ExpectGet(testUserTokenEpochKey(userID)).RedisNil()

	_, accessToken, _, _, err := f.handler.idp.IssueTokens(context.Background(), &coreidp.OIDCSession{
		ClientID: "jwt-client", UserID: userID, AuthTime: time.Now(), Scopes: []string{"openid"},
		AccessTokenResources: []string{resource},
	})
	assert.NoError(t, err)

	return accessToken
}
