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

// Package mcptest provides a hermetic token authority and an SDK client connection for tests of the MCP support
// endpoint. It never imports the endpoint itself, so the endpoint's own tests and end-to-end tests elsewhere share
// the same fakes.
package mcptest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	nautherrors "github.com/croessner/nauthilus/v4/server/errors"
	"github.com/croessner/nauthilus/v4/server/idp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Fixed names of the hosted test resource.
const (
	Resource     = "https://login.example.test/mcp"
	Issuer       = "https://login.example.test"
	Host         = "login.example.test"
	StaticClient = "support-cli"
	HostedName   = "support-mcp"
)

// Authority is a token authority with fixed tokens and clients.
type Authority struct {
	Tokens      map[string]idp.UserAccessToken
	Clients     map[string]*config.OIDCClient
	Hosted      config.OIDCHostedResource
	Unavailable bool
}

// NewAuthority returns an authority for the hosted resource with the static client and the given scopes.
func NewAuthority(scopes ...string) *Authority {
	return &Authority{Tokens: map[string]idp.UserAccessToken{},
		Clients: map[string]*config.OIDCClient{StaticClient: {ClientID: StaticClient}},
		Hosted: config.OIDCHostedResource{Name: HostedName, Resource: Resource, StaticClients: []string{StaticClient},
			Scopes: scopes}}
}

// ValidateUserAccessToken answers the fixed token table.
func (a *Authority) ValidateUserAccessToken(_ context.Context, token string) (idp.UserAccessToken, error) {
	if a.Unavailable {
		return idp.UserAccessToken{}, nautherrors.NewTokenValidationUnavailable(errors.New("redis down"))
	}

	verified, ok := a.Tokens[token]
	if !ok {
		return idp.UserAccessToken{}, idp.ErrNotUserAccessToken
	}

	return verified, nil
}

// ResolveClient answers the fixed client table.
func (a *Authority) ResolveClient(_ context.Context, clientID string) (*config.OIDCClient, error) {
	client, ok := a.Clients[clientID]
	if !ok {
		return nil, errors.New("unknown client")
	}

	return client, nil
}

// HostedResource returns the one configured hosted resource.
func (a *Authority) HostedResource(name string) (idp.HostedResource, bool) {
	if name != a.Hosted.Name {
		return idp.HostedResource{}, false
	}

	return idp.NewHostedResource(&a.Hosted)
}

// Issuer returns the fixed issuer.
func (a *Authority) Issuer() string { return Issuer }

// UserToken returns a verified user token for the client with the given audience and scopes.
func UserToken(clientID string, audience []any, scopes ...string) idp.UserAccessToken {
	return idp.UserAccessToken{Claims: jwt.MapClaims{"aud": audience}, ClientID: clientID, Subject: "anna-id",
		Scopes: scopes, Issuer: Issuer, ExpiresAt: time.Now().Add(10 * time.Minute)}
}

// ResourceToken returns a verified user token of the static client for the hosted resource.
func ResourceToken(scopes ...string) idp.UserAccessToken {
	return UserToken(StaticClient, []any{StaticClient, Resource}, scopes...)
}

// proxyTransport adds the bearer token and the trusted proxy headers to every SDK client request.
type proxyTransport struct {
	token string
}

// RoundTrip forwards the request as a trusted TLS-terminating proxy on the loopback address would.
func (p proxyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Host = Host
	clone.Header.Set("Authorization", "Bearer "+p.token)
	clone.Header.Set("X-Forwarded-Proto", "https")
	clone.Header.Set("X-Forwarded-For", "203.0.113.50")

	return http.DefaultTransport.RoundTrip(clone)
}

// Transport returns a client transport that presents the token through the trusted loopback proxy.
func Transport(token string) http.RoundTripper {
	return proxyTransport{token: token}
}

// Connect serves the endpoint handler and runs an SDK client against it with the token and protocol version; the
// endpoint must trust the loopback proxy.
func Connect(t *testing.T, handler http.Handler, token string, version string) *mcp.ClientSession {
	t.Helper()

	listener := httptest.NewServer(handler)
	t.Cleanup(listener.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "nauthilus-test", Version: "1"}, nil)

	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: listener.URL + "/mcp",
		HTTPClient: &http.Client{Transport: Transport(token)}}, &mcp.ClientSessionOptions{ProtocolVersion: version})
	if err != nil {
		t.Fatalf("Connect(%s) = %v", version, err)
	}

	t.Cleanup(func() { _ = session.Close() })

	return session
}
