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
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/secret"
)

// hostedResourceTestSettings returns an OIDC configuration with one admitted public CLI client.
func hostedResourceTestSettings() *FileSettings {
	return &FileSettings{IDP: &IDPSection{OIDC: OIDCConfig{
		Enabled: true,
		Issuer:  "https://login.example.org",
		Clients: []OIDCClient{
			{
				ClientID: "support-cli", TokenEndpointAuthMethod: "none",
				RedirectURIs: []string{"http://127.0.0.1/callback", "http://localhost/callback"},
				Scopes:       []string{definitions.ScopeHistoryRead, definitions.ScopeOperationsRead, definitions.ScopeOfflineAccess},
				GrantTypes:   []string{definitions.OIDCFlowAuthorizationCode, definitions.OIDCFlowRefreshToken},
				RequireMFA:   []string{"totp", "webauthn"},
			},
			{
				ClientID: "mail-rs", ClientSecret: secret.New("secret"),
				TokenIntrospection: OIDCTokenIntrospection{Resources: []string{"https://mail.example.org/"}, Clients: []string{"support-cli"}},
			},
		},
		HostedResources: []OIDCHostedResource{{
			Name: "support-mcp", Resource: "https://login.example.org/mcp",
			Scopes:        []string{definitions.ScopeHistoryRead, definitions.ScopeOperationsRead},
			StaticClients: []string{"support-cli"},
			UserRight:     OIDCHostedResourceUserRight{From: HostedResourceUserRightFromGroups, AnyOf: []string{"nauthilus-support"}},
		}},
	}}}
}

// TestValidateIDPOIDCHostedResources pins every rejection of the hosted resource block and the static-client fitness
// rules, plus the defaults of the duration ceilings.
func TestValidateIDPOIDCHostedResources(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*OIDCConfig)
		want   string
	}{
		"valid":                  {func(*OIDCConfig) {}, ""},
		"loopback http resource": {func(o *OIDCConfig) { o.HostedResources[0].Resource = "http://127.0.0.1:8443/mcp" }, ""},
		"oidc disabled":          {func(o *OIDCConfig) { o.Enabled = false }, "identity.oidc.enabled"},
		"bad name":               {func(o *OIDCConfig) { o.HostedResources[0].Name = "Support MCP" }, ".name"},
		"duplicate name":         {func(o *OIDCConfig) { o.HostedResources = append(o.HostedResources, o.HostedResources[0]) }, "[1].name"},
		"plain http resource":    {func(o *OIDCConfig) { o.HostedResources[0].Resource = "http://login.example.org/mcp" }, "must use https"},
		"resource with query":    {func(o *OIDCConfig) { o.HostedResources[0].Resource = "https://login.example.org/mcp?x=1" }, ".resource"},
		"resource with fragment": {func(o *OIDCConfig) { o.HostedResources[0].Resource = "https://login.example.org/mcp#x" }, ".resource"},
		"client-owned resource":  {func(o *OIDCConfig) { o.HostedResources[0].Resource = "https://mail.example.org/" }, "owned by a client"},
		"reserved audience":      {func(o *OIDCConfig) { o.HostedResources[0].Resource = "nauthilus://api" }, ".resource"},
		"no scopes":              {func(o *OIDCConfig) { o.HostedResources[0].Scopes = nil }, ".scopes"},
		"foreign scope":          {func(o *OIDCConfig) { o.HostedResources[0].Scopes = []string{"openid"} }, ".scopes[0]"},
		"duplicate scope": {func(o *OIDCConfig) {
			o.HostedResources[0].Scopes = []string{definitions.ScopeHistoryRead, definitions.ScopeHistoryRead}
		}, "must not repeat"},
		"attribute user right":      {func(o *OIDCConfig) { o.HostedResources[0].UserRight.From = "attribute" }, ".user_right.from"},
		"no entitling group":        {func(o *OIDCConfig) { o.HostedResources[0].UserRight.AnyOf = nil }, ".user_right.any_of"},
		"padded group":              {func(o *OIDCConfig) { o.HostedResources[0].UserRight.AnyOf = []string{" support"} }, ".user_right.any_of[0]"},
		"login age too short":       {func(o *OIDCConfig) { o.HostedResources[0].MaxAuthenticationAge = time.Minute }, "max_authentication_age"},
		"token lifetime too long":   {func(o *OIDCConfig) { o.HostedResources[0].MaxAccessTokenLifetime = 2 * time.Hour }, "max_access_token_lifetime"},
		"no static clients":         {func(o *OIDCConfig) { o.HostedResources[0].StaticClients = nil }, ".static_clients"},
		"unknown static client":     {func(o *OIDCConfig) { o.HostedResources[0].StaticClients = []string{"dcr_abc"} }, "configured static client"},
		"confidential without pkce": {func(o *OIDCConfig) { o.HostedResources[0].StaticClients = []string{"mail-rs"} }, "require_pkce"},
		"device grant": {func(o *OIDCConfig) {
			o.Clients[0].GrantTypes = append(o.Clients[0].GrantTypes, definitions.OIDCFlowDeviceCode)
		}, "grant_types"},
		"client credentials grant": {func(o *OIDCConfig) { o.Clients[0].GrantTypes = []string{"client_credentials"} }, "grant_types"},
		"no mfa":                   {func(o *OIDCConfig) { o.Clients[0].RequireMFA = nil }, "require MFA"},
		"mfa level is enough":      {func(o *OIDCConfig) { o.Clients[0].RequireMFA = nil; o.Clients[0].RequiredMFALevel = 2 }, ""},
		"client lacks scopes":      {func(o *OIDCConfig) { o.Clients[0].Scopes = []string{"openid"} }, "client scopes"},
	} {
		t.Run(name, func(t *testing.T) {
			settings := hostedResourceTestSettings()
			tc.mutate(&settings.IDP.OIDC)

			err := settings.validateIDPOIDCHostedResources()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("validateIDPOIDCHostedResources() = %v, want nil", err)
				}

				return
			}

			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateIDPOIDCHostedResources() = %v, want error containing %q", err, tc.want)
			}
		})
	}

	resource := hostedResourceTestSettings().IDP.OIDC.HostedResources[0]
	if resource.GetMaxAuthenticationAge() != 12*time.Hour || resource.GetMaxAccessTokenLifetime() != 15*time.Minute {
		t.Fatal("unexpected hosted resource defaults")
	}
}

// TestOIDCHostedResourceLookupAndMaterialize pins name and URI lookup and the deep copy of the wire schema.
func TestOIDCHostedResourceLookupAndMaterialize(t *testing.T) {
	oidc := hostedResourceTestSettings().IDP.OIDC

	if found, ok := oidc.FindHostedResource("support-mcp"); !ok || found.Resource != "https://login.example.org/mcp" {
		t.Fatal("FindHostedResource did not return the configured resource")
	}

	if _, ok := oidc.FindHostedResourceByURI("https://login.example.org/other"); ok {
		t.Fatal("FindHostedResourceByURI matched an unknown resource")
	}

	wire := OIDCWireConfig{HostedResources: oidc.HostedResources}
	materialized := wire.Materialize()
	materialized.HostedResources[0].StaticClients[0] = "changed"

	if wire.HostedResources[0].StaticClients[0] != "support-cli" {
		t.Fatal("Materialize must not alias the wire-level hosted resources")
	}
}
