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

	"github.com/croessner/nauthilus/v3/server/secret"
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
		{name: "unknown method", client: OIDCClient{AllowBackchannelIntrospection: true, ClientSecret: secret.New("test-secret"), TokenEndpointAuthMethod: "unknown"}, wantError: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &FileSettings{IDP: &IDPSection{OIDC: OIDCConfig{Clients: []OIDCClient{tc.client}}}}

			err := cfg.validateIDPOIDCIntrospectionSettings()
			if tc.wantError {
				assert.ErrorContains(t, err, "idp.oidc.clients[0].allow_backchannel_introspection")
			} else {
				assert.NoError(t, err)
			}
		})
	}
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
