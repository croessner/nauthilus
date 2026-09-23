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
	coreidp "github.com/croessner/nauthilus/v4/server/idp"
	json "github.com/json-iterator/go"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestOIDCHandler_BackchannelIntrospection(t *testing.T) {
	f := newOIDCIntrospectionTest(t)
	cfg := f.handler.deps.Cfg.(*mockOIDCCfg)

	cfg.clients[0].AllowBackchannelIntrospection = true
	cfg.clients[1].GrantTypes = []string{"client_credentials"}
	// The issuing service uses secret authentication for this fixture.
	cfg.clients[1].ClientSecret = cfg.clients[0].ClientSecret

	f.mock.ExpectGet(testUserTokenEpochKey("jwt-client")).RedisNil()
	token, _, err := f.handler.idp.IssueClientCredentialsToken(context.Background(), "jwt-client", []string{definitions.ScopeAuthenticate})
	assert.NoError(t, err)

	cfg.clients[0].AllowBackchannelIntrospection = false

	f.expectAccessTokenValidation("jwt-client", token, 1)
	denied := f.postIntrospection(t, url.Values{"token": {token}}, "test-client", "test-secret")
	assert.Equal(t, map[string]any{"active": false}, mustDecodeOIDCTestJSON(t, denied))

	cfg.clients[0].AllowBackchannelIntrospection = true

	f.expectAccessTokenValidation("jwt-client", token, 1)
	w := f.postIntrospection(t, url.Values{"token": {token}}, "test-client", "test-secret")
	assert.Equal(t, http.StatusOK, w.Code)
	response := mustDecodeOIDCTestJSON(t, w)
	assertBackchannelIntrospectionResponse(t, response, f.issuer, "jwt-client")
	assert.NoError(t, f.mock.ExpectationsWereMet())
}

func TestCanIntrospectAccessToken(t *testing.T) {
	cases := []struct {
		name      string
		audience  any
		clientID  any
		tokenType string
		allowed   bool
		dynamic   bool
		want      bool
	}{
		{name: "default denied", audience: definitions.AudienceBackchannelAPI, clientID: "caller", tokenType: definitions.TokenTypeAccessToken},
		{name: "explicit grant", audience: definitions.AudienceBackchannelAPI, clientID: "caller", tokenType: definitions.TokenTypeAccessToken, allowed: true, want: true},
		{name: "array grant", audience: []any{definitions.AudienceBackchannelAPI}, clientID: "caller", tokenType: definitions.TokenTypeAccessToken, allowed: true, want: true},
		{name: "array denied by default", audience: []any{definitions.AudienceBackchannelAPI}, clientID: "caller", tokenType: definitions.TokenTypeAccessToken},
		{name: "foreign array", audience: []any{"other-client"}, allowed: true},
		{name: "policy denied", audience: definitions.AudiencePolicyAPI, clientID: "caller", tokenType: definitions.TokenTypeAccessToken, allowed: true},
		{name: "mixed resources", audience: []string{definitions.AudienceBackchannelAPI, definitions.AudiencePolicyAPI}, clientID: "caller", tokenType: definitions.TokenTypeAccessToken, allowed: true},
		{name: "missing audience", allowed: true},
		{name: "malformed audience", audience: []any{definitions.AudienceBackchannelAPI, 42}, clientID: "caller", tokenType: definitions.TokenTypeAccessToken, allowed: true},
		{name: "missing service identity", audience: definitions.AudienceBackchannelAPI, tokenType: definitions.TokenTypeAccessToken, allowed: true},
		{name: "id token", audience: definitions.AudienceBackchannelAPI, clientID: "caller", tokenType: definitions.TokenTypeIDToken, allowed: true},
		{name: "dynamic denied", audience: definitions.AudienceBackchannelAPI, clientID: "caller", tokenType: definitions.TokenTypeAccessToken, allowed: true, dynamic: true},
		{name: "own audience unchanged", audience: "inspector", want: true},
		{name: "own audience array", audience: []string{"inspector"}, want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &config.OIDCClient{ClientID: "inspector", ClientSecret: secret.New("test-secret"), AllowBackchannelIntrospection: tc.allowed, Dynamic: tc.dynamic}
			claims := jwt.MapClaims{"aud": tc.audience, definitions.ClaimClientID: tc.clientID, definitions.ClaimTokenType: tc.tokenType}
			assert.Equal(t, tc.want, canIntrospectAccessToken(client, claims))
		})
	}
}

func TestOIDCHandler_OpaqueBackchannelIntrospection(t *testing.T) {
	f := newOIDCIntrospectionTest(t)
	cfg := f.handler.deps.Cfg.(*mockOIDCCfg)

	cfg.clients[0].AllowBackchannelIntrospection = true
	token := definitions.OIDCTokenPrefixAccessToken + "introspection-test"
	session := &coreidp.OIDCSession{
		ClientID: "service-caller", UserID: "service-caller", ServiceToken: true, DynamicUserEpoch: "0",
		Scopes: []string{definitions.ScopeAuthenticate}, AccessTokenAudience: definitions.AudienceBackchannelAPI,
		AccessTokenIssuer: f.issuer, AccessTokenIssuedAt: time.Now(), AccessTokenExpiresAt: time.Now().Add(time.Hour),
	}
	encoded, err := json.Marshal(session)
	assert.NoError(t, err)

	manager := f.handler.deps.Redis.GetSecurityManager()
	encrypted, err := manager.Encrypt(string(encoded))
	assert.NoError(t, err)

	key := f.staticAccessTokenKey(token)
	f.mock.ExpectGet(key).SetVal(encrypted)
	f.mock.ExpectGet(testUserTokenEpochKey(session.UserID)).RedisNil()
	w := f.postIntrospection(t, url.Values{"token": {token}}, "test-client", "test-secret")
	response := mustDecodeOIDCTestJSON(t, w)
	assert.Equal(t, http.StatusOK, w.Code)
	assertBackchannelIntrospectionResponse(t, response, f.issuer, session.ClientID)
	assert.Equal(t, float64(session.AccessTokenExpiresAt.Unix()), response["exp"])
	// Expired or revoked opaque tokens disappear from authoritative Redis storage.
	f.mock.ExpectGet(key).RedisNil()
	inactive := f.postIntrospection(t, url.Values{"token": {token}}, "test-client", "test-secret")
	assert.Equal(t, map[string]any{"active": false}, mustDecodeOIDCTestJSON(t, inactive))
	assert.NoError(t, f.mock.ExpectationsWereMet())
}

// assertBackchannelIntrospectionResponse verifies the shared JWT and opaque service-token response contract.
func assertBackchannelIntrospectionResponse(t *testing.T, response map[string]any, issuer, clientID string) {
	t.Helper()

	assert.Equal(t, true, response["active"])
	assert.Equal(t, issuer, response["iss"])
	assert.Equal(t, definitions.AudienceBackchannelAPI, response["aud"])
	assert.Equal(t, clientID, response["client_id"])
	assert.Equal(t, definitions.ScopeAuthenticate, response["scope"])
	assert.NotEmpty(t, response["exp"])
}

// TestOIDCHandler_IntrospectionReportsUnavailableTokenStore pins that an unreachable token store is not
// presented as an inactive token, which a protected resource would treat like a revocation.
func TestOIDCHandler_IntrospectionReportsUnavailableTokenStore(t *testing.T) {
	f := newOIDCIntrospectionTest(t)
	token := definitions.OIDCTokenPrefixAccessToken + "store-unavailable"

	f.mock.ExpectGet(f.staticAccessTokenKey(token)).SetErr(&net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET})

	w := f.postIntrospection(t, url.Values{"token": {token}}, "test-client", "test-secret")

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, "1", w.Header().Get("Retry-After"))
	assert.Equal(t, map[string]any{definitions.LogKeyError: "temporarily_unavailable"}, mustDecodeOIDCTestJSON(t, w))
	assert.NoError(t, f.mock.ExpectationsWereMet())
}
