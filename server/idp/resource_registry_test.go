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

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/stretchr/testify/assert"
)

const (
	registryTestMailResource  = "https://mail.example.org/jmap"
	registryTestOtherResource = "https://other.example.org/api"
)

// registryTestClients returns a mail resource server, an issuing client, and a second resource server.
func registryTestClients() []config.OIDCClient {
	return []config.OIDCClient{
		{
			ClientID: "mail-rs", ClientSecret: secret.New("test-secret"),
			TokenIntrospection: config.OIDCTokenIntrospection{
				Resources: []string{registryTestMailResource}, Clients: []string{"webmail"},
				DynamicClientProfiles: []string{"mail-client-v1"},
			},
		},
		{ClientID: "webmail"},
		{
			ClientID: "other-rs", ClientSecret: secret.New("test-secret"),
			TokenIntrospection: config.OIDCTokenIntrospection{Resources: []string{registryTestOtherResource}, Clients: []string{"webmail"}},
		},
	}
}

func TestResourceRegistryOwnerAndRequest(t *testing.T) {
	clients := registryTestClients()
	registry := NewResourceRegistry(clients)
	owner, ok := registry.ResourceOwner(registryTestMailResource)

	assert.True(t, ok)
	assert.Equal(t, "mail-rs", owner.ClientID)

	_, ok = registry.ResourceOwner("https://unknown.example.org")
	assert.False(t, ok)

	cases := []struct {
		name     string
		issuing  *config.OIDCClient
		resource string
		want     bool
	}{
		{name: "allowlisted static", issuing: &clients[1], resource: registryTestMailResource, want: true},
		{name: "allowlisted profile", issuing: &config.OIDCClient{ClientID: "dcr_native", Dynamic: true, DynamicProfile: "mail-client-v1"}, resource: registryTestMailResource, want: true},
		{name: "dynamic without profile", issuing: &config.OIDCClient{ClientID: "dcr_native", Dynamic: true}, resource: registryTestMailResource},
		{name: "dynamic id spoofing static", issuing: &config.OIDCClient{ClientID: "webmail", Dynamic: true}, resource: registryTestMailResource},
		{name: "not allowlisted", issuing: &clients[2], resource: registryTestMailResource},
		{name: "owner itself", issuing: &clients[0], resource: registryTestMailResource},
		{name: "unregistered", issuing: &clients[1], resource: "https://unknown.example.org"},
		{name: "nil issuer", resource: registryTestMailResource},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, registry.MayRequest(tc.issuing, tc.resource))
		})
	}
}

func TestResourceRegistryMayIntrospect(t *testing.T) {
	clients := registryTestClients()
	registry := NewResourceRegistry(clients)
	dynamic := &config.OIDCClient{ClientID: "dcr_native", Dynamic: true, DynamicProfile: "mail-client-v1"}

	cases := []struct {
		name   string
		caller *config.OIDCClient
		token  IntrospectedUserToken
		want   bool
	}{
		{name: "plain allowlisted", caller: &clients[0], token: IntrospectedUserToken{IssuingClient: &clients[1]}, want: true},
		{name: "plain profile", caller: &clients[0], token: IntrospectedUserToken{IssuingClient: dynamic}, want: true},
		{name: "plain not allowlisted", caller: &clients[0], token: IntrospectedUserToken{IssuingClient: &clients[2]}},
		{name: "plain unresolved issuer", caller: &clients[0], token: IntrospectedUserToken{}},
		{name: "own resource", caller: &clients[0], token: IntrospectedUserToken{IssuingClient: &clients[2], Resources: []string{registryTestMailResource}}, want: true},
		{name: "foreign resource despite allowlist", caller: &clients[0], token: IntrospectedUserToken{IssuingClient: &clients[1], Resources: []string{registryTestOtherResource}}},
		{name: "unregistered resource", caller: &clients[0], token: IntrospectedUserToken{IssuingClient: &clients[1], Resources: []string{"https://unknown.example.org"}}},
		{name: "caller without authority", caller: &clients[1], token: IntrospectedUserToken{IssuingClient: &clients[1]}},
		{name: "public caller", caller: &config.OIDCClient{ClientID: "mail-rs", TokenIntrospection: clients[0].TokenIntrospection}, token: IntrospectedUserToken{IssuingClient: &clients[1]}},
		{name: "nil caller", token: IntrospectedUserToken{IssuingClient: &clients[1]}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, registry.MayIntrospect(tc.caller, tc.token))
		})
	}
}

func TestResourceRegistryAmbiguousOwner(t *testing.T) {
	clients := registryTestClients()
	clients[2].TokenIntrospection.Resources = []string{registryTestMailResource}

	_, ok := NewResourceRegistry(clients).ResourceOwner(registryTestMailResource)
	assert.False(t, ok)
}
