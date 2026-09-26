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

package config

import (
	"testing"

	"github.com/go-viper/mapstructure/v2"

	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/stretchr/testify/assert"
)

func TestValidateIDPOIDCIntrospectionSettings(t *testing.T) {
	cases := []struct {
		name      string
		client    OIDCClient
		wantError bool
	}{
		{name: "disabled default", client: OIDCClient{}},
		{name: "basic", client: OIDCClient{AllowBackchannelIntrospection: true, ClientSecret: secret.New("test-secret"), TokenEndpointAuthMethod: AuthorityClientSecretBasicAuth}},
		{name: "post", client: OIDCClient{AllowBackchannelIntrospection: true, ClientSecret: secret.New("test-secret"), TokenEndpointAuthMethod: AuthorityClientSecretPostAuth}},
		{name: "implicit secret auth", client: OIDCClient{AllowBackchannelIntrospection: true, ClientSecret: secret.New("test-secret")}},
		{name: "private key JWT", client: OIDCClient{AllowBackchannelIntrospection: true, TokenEndpointAuthMethod: AuthorityPrivateKeyJWTAuth, ClientPublicKeyFile: "/test/public.pem"}},
		{name: "public", client: OIDCClient{AllowBackchannelIntrospection: true}, wantError: true},
		{name: "none with secret", client: OIDCClient{AllowBackchannelIntrospection: true, ClientSecret: secret.New("test-secret"), TokenEndpointAuthMethod: oidcAuthMethodNone}, wantError: true},
		{name: "missing key", client: OIDCClient{AllowBackchannelIntrospection: true, TokenEndpointAuthMethod: AuthorityPrivateKeyJWTAuth}, wantError: true},
		{name: "dynamic", client: OIDCClient{AllowBackchannelIntrospection: true, ClientSecret: secret.New("test-secret"), Dynamic: true}, wantError: true},
		{name: "unknown method", client: OIDCClient{AllowBackchannelIntrospection: true, ClientSecret: secret.New("test-secret"), TokenEndpointAuthMethod: "unknown"}, wantError: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &FileSettings{IDP: &IDPSection{OIDC: OIDCConfig{Clients: []OIDCClient{tc.client}}}}

			err := cfg.validateIDPOIDCIntrospectionSettings()
			if tc.wantError {
				assert.ErrorContains(t, err, "identity.oidc.clients[0].allow_backchannel_introspection")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestBackchannelIntrospectionConfigDumpDefault(t *testing.T) {
	index, err := getConfigSchemaIndex()
	if !assert.NoError(t, err) {
		return
	}

	clientNode := index.root.fieldByConfigName["identity"].fieldByConfigName["oidc"].fieldByConfigName["clients"].element

	var lines []string

	collectDefaultConfigDumpLines(clientNode, "identity.oidc.clients[0]", configDumpDefaultProviders(), &lines)
	assert.Contains(t, lines, "identity.oidc.clients[0].allow_backchannel_introspection = false")

	settings := map[string]any{"identity": map[string]any{"oidc": map[string]any{"clients": []any{map[string]any{"client_id": "inspector", "allow_backchannel_introspection": true}}}}}
	output, err := RenderNonDefaultConfigDump(settings)
	assert.NoError(t, err)
	assert.Contains(t, output, "identity.oidc.clients[0].allow_backchannel_introspection = true")
}

func TestOIDCClientBackchannelIntrospectionParsing(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		var client OIDCClient

		err := mapstructure.Decode(map[string]any{"allow_backchannel_introspection": enabled}, &client)
		assert.NoError(t, err)
		assert.Equal(t, enabled, client.AllowBackchannelIntrospection)
	}

	var omitted OIDCClient

	assert.NoError(t, mapstructure.Decode(map[string]any{"client_id": "inspector"}, &omitted))
	assert.False(t, omitted.AllowBackchannelIntrospection)
}

// tokenIntrospectionTestConfig builds a resource server, an issuing client, and a second resource server.
func tokenIntrospectionTestConfig(introspection OIDCTokenIntrospection, dynamicEnabled bool) *FileSettings {
	resourceServer := OIDCClient{
		ClientID:                "mail-rs",
		ClientSecret:            secret.New("test-secret"),
		TokenEndpointAuthMethod: AuthorityClientSecretBasicAuth,
		TokenIntrospection:      introspection,
	}
	otherResourceServer := OIDCClient{
		ClientID:     "other-rs",
		ClientSecret: secret.New("test-secret"),
		TokenIntrospection: OIDCTokenIntrospection{
			Resources: []string{"https://other.example.org/api"},
			Clients:   []string{"webmail"},
		},
	}

	return &FileSettings{IDP: &IDPSection{OIDC: OIDCConfig{
		Clients:                   []OIDCClient{resourceServer, {ClientID: "webmail"}, otherResourceServer},
		DynamicClientRegistration: OIDCDynamicClientRegistrationConfig{Enabled: dynamicEnabled},
	}}}
}

func TestValidateIDPOIDCTokenIntrospectionSettings(t *testing.T) {
	const basePath = "identity.oidc.clients[0].token_introspection"

	cases := []struct {
		name           string
		introspection  OIDCTokenIntrospection
		mutate         func(*OIDCClient)
		dynamicEnabled bool
		wantPath       string
	}{
		{name: "not configured", introspection: OIDCTokenIntrospection{}, mutate: func(c *OIDCClient) { c.ClientSecret = secret.Value{} }},
		{name: "valid resources and clients", introspection: OIDCTokenIntrospection{Resources: []string{"https://mail.example.org/jmap", "urn:example:mail"}, Clients: []string{"webmail"}}},
		{name: "valid allowlist only", introspection: OIDCTokenIntrospection{Clients: []string{"webmail"}}},
		{name: "valid dynamic profile", introspection: OIDCTokenIntrospection{Resources: []string{"https://mail.example.org/jmap"}, DynamicClientProfiles: []string{"mail-client-v1"}}, dynamicEnabled: true},
		{name: "public client", introspection: OIDCTokenIntrospection{Clients: []string{"webmail"}}, mutate: func(c *OIDCClient) { c.ClientSecret = secret.Value{} }, wantPath: basePath},
		{name: "none auth method", introspection: OIDCTokenIntrospection{Clients: []string{"webmail"}}, mutate: func(c *OIDCClient) { c.TokenEndpointAuthMethod = oidcAuthMethodNone }, wantPath: basePath},
		{name: "private key JWT without key", introspection: OIDCTokenIntrospection{Clients: []string{"webmail"}}, mutate: func(c *OIDCClient) { c.TokenEndpointAuthMethod = AuthorityPrivateKeyJWTAuth }, wantPath: basePath},
		{name: "resources without allowlist", introspection: OIDCTokenIntrospection{Resources: []string{"https://mail.example.org/jmap"}}, wantPath: basePath},
		{name: "relative resource", introspection: OIDCTokenIntrospection{Resources: []string{"/jmap"}, Clients: []string{"webmail"}}, wantPath: basePath + ".resources[0]"},
		{name: "empty resource", introspection: OIDCTokenIntrospection{Resources: []string{""}, Clients: []string{"webmail"}}, wantPath: basePath + ".resources[0]"},
		{name: "fragment resource", introspection: OIDCTokenIntrospection{Resources: []string{"https://mail.example.org/jmap#x"}, Clients: []string{"webmail"}}, wantPath: basePath + ".resources[0]"},
		{name: "surrounding whitespace", introspection: OIDCTokenIntrospection{Resources: []string{" https://mail.example.org/jmap"}, Clients: []string{"webmail"}}, wantPath: basePath + ".resources[0]"},
		{name: "backchannel audience", introspection: OIDCTokenIntrospection{Resources: []string{"nauthilus:backchannel"}, Clients: []string{"webmail"}}, wantPath: basePath + ".resources[0]"},
		{name: "policy audience", introspection: OIDCTokenIntrospection{Resources: []string{"nauthilus:policy"}, Clients: []string{"webmail"}}, wantPath: basePath + ".resources[0]"},
		{name: "reserved scheme", introspection: OIDCTokenIntrospection{Resources: []string{"NAUTHILUS:mail"}, Clients: []string{"webmail"}}, wantPath: basePath + ".resources[0]"},
		{name: "resource equals client id", introspection: OIDCTokenIntrospection{Resources: []string{"https://mail.example.org/jmap"}, Clients: []string{"webmail"}}, mutate: func(c *OIDCClient) { c.ClientID = "https://mail.example.org/jmap" }, wantPath: basePath + ".resources[0]"},
		{name: "duplicate resource within client", introspection: OIDCTokenIntrospection{Resources: []string{"https://mail.example.org/jmap", "https://mail.example.org/jmap"}, Clients: []string{"webmail"}}, wantPath: basePath + ".resources[1]"},
		{name: "resource owned by another client", introspection: OIDCTokenIntrospection{Resources: []string{"https://other.example.org/api"}, Clients: []string{"webmail"}}, wantPath: "identity.oidc.clients[2].token_introspection.resources[0]"},
		{name: "unknown client", introspection: OIDCTokenIntrospection{Clients: []string{"unknown"}}, wantPath: basePath + ".clients[0]"},
		{name: "self in allowlist", introspection: OIDCTokenIntrospection{Clients: []string{"webmail", "mail-rs"}}, wantPath: basePath + ".clients[1]"},
		{name: "profile without registration", introspection: OIDCTokenIntrospection{DynamicClientProfiles: []string{"mail-client-v1"}}, wantPath: basePath + ".dynamic_client_profiles"},
		{name: "unknown profile", introspection: OIDCTokenIntrospection{DynamicClientProfiles: []string{"other-profile"}}, dynamicEnabled: true, wantPath: basePath + ".dynamic_client_profiles[0]"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tokenIntrospectionTestConfig(tc.introspection, tc.dynamicEnabled)
			if tc.mutate != nil {
				tc.mutate(&cfg.IDP.OIDC.Clients[0])
			}

			err := cfg.validateIDPOIDCTokenIntrospectionSettings()
			if tc.wantPath == "" {
				assert.NoError(t, err)

				return
			}

			assert.ErrorContains(t, err, tc.wantPath)
		})
	}
}

func TestOIDCClientTokenIntrospectionParsing(t *testing.T) {
	var client OIDCClient

	err := mapstructure.Decode(map[string]any{"token_introspection": map[string]any{
		"resources":               []string{"https://mail.example.org/jmap"},
		"clients":                 []string{"webmail"},
		"dynamic_client_profiles": []string{"mail-client-v1"},
	}}, &client)
	assert.NoError(t, err)
	assert.Equal(t, OIDCTokenIntrospection{
		Resources:             []string{"https://mail.example.org/jmap"},
		Clients:               []string{"webmail"},
		DynamicClientProfiles: []string{"mail-client-v1"},
	}, client.TokenIntrospection)
}
