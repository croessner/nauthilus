// Copyright (C) 2026 Christian Roessner
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
	"net/http"
	"testing"

	"github.com/croessner/nauthilus/v3/server/openapi/requesttest"
)

const (
	idpClientSmokeAuthorizationEndpoint = "https://idp.example.test/oidc/authorize"
	idpClientSmokeIssuer                = "https://idp.example.test"
	idpClientSmokeJWKSURI               = "https://idp.example.test/oidc/jwks"
	idpClientSmokeTokenEndpoint         = "https://idp.example.test/oidc/token"
)

func TestGeneratedIDPClientUsesDiscoveryContract(t *testing.T) {
	responseBody := OIDCDiscovery{
		AuthorizationEndpoint: idpClientSmokeAuthorizationEndpoint,
		Issuer:                idpClientSmokeIssuer,
		JwksUri:               idpClientSmokeJWKSURI,
		TokenEndpoint:         idpClientSmokeTokenEndpoint,
	}
	doer := requesttest.NewClientSmokeDoer(t, requesttest.ClientSmokeRoute{
		Response: responseBody,
		Method:   http.MethodGet,
		Path:     "/.well-known/openid-configuration",
		Status:   http.StatusOK,
	})

	client, err := NewClientWithResponses("https://nauthilus.example.test", WithHTTPClient(doer))
	if err != nil {
		t.Fatalf("create generated IDP client: %v", err)
	}

	response, err := client.GetOIDCDiscoveryWithResponse(context.Background())
	if err != nil {
		t.Fatalf("call generated IDP client: %v", err)
	}

	assertIDPDiscoveryClientSmokeResponse(t, response)
}

func assertIDPDiscoveryClientSmokeResponse(t testing.TB, response *GetOIDCDiscoveryResponse) {
	t.Helper()

	if response.StatusCode() != http.StatusOK {
		t.Fatalf("status code = %d, want %d", response.StatusCode(), http.StatusOK)
	}

	if response.JSON200 == nil {
		t.Fatal("JSON200 response missing")
	}

	if response.JSON200.Issuer != idpClientSmokeIssuer {
		t.Fatalf("issuer = %q, want %q", response.JSON200.Issuer, idpClientSmokeIssuer)
	}

	if response.JSON200.AuthorizationEndpoint != idpClientSmokeAuthorizationEndpoint {
		t.Fatalf("authorization endpoint = %q, want %q", response.JSON200.AuthorizationEndpoint, idpClientSmokeAuthorizationEndpoint)
	}

	if response.JSON200.TokenEndpoint != idpClientSmokeTokenEndpoint {
		t.Fatalf("token endpoint = %q, want %q", response.JSON200.TokenEndpoint, idpClientSmokeTokenEndpoint)
	}

	if response.JSON200.JwksUri != idpClientSmokeJWKSURI {
		t.Fatalf("jwks uri = %q, want %q", response.JSON200.JwksUri, idpClientSmokeJWKSURI)
	}
}
