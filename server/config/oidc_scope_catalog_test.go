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
	"slices"
	"testing"
)

// scopeCatalogTestSettings builds an enabled OIDC issuer over the given clients and global custom scopes.
func scopeCatalogTestSettings(customScopes []Oauth2CustomScope, clients ...OIDCClient) *FileSettings {
	return &FileSettings{IDP: &IDPSection{OIDC: OIDCConfig{Enabled: true, CustomScopes: customScopes, Clients: clients}}}
}

// scopeCatalogTestScope declares a custom scope that releases the given string-array claims.
func scopeCatalogTestScope(name string, claims ...string) Oauth2CustomScope {
	scope := Oauth2CustomScope{Name: name, Description: name + " description"}
	for _, claim := range claims {
		scope.Claims = append(scope.Claims, OIDCCustomClaim{Name: claim, Type: "string_array"})
	}

	return scope
}

// scopeCatalogTestMappings maps the given claims from the group memberships.
func scopeCatalogTestMappings(claims ...string) []OIDCClaimMapping {
	mappings := make([]OIDCClaimMapping, 0, len(claims))
	for _, claim := range claims {
		mappings = append(mappings, OIDCClaimMapping{Claim: claim, From: "groups"})
	}

	return mappings
}

// TestCustomScopeClaimsAreOptional verifies that a custom scope may declare a scope without releasing a claim.
func TestCustomScopeClaimsAreOptional(t *testing.T) {
	validate, err := newConfigValidator()
	if err != nil {
		t.Fatalf("newConfigValidator() error = %v", err)
	}

	tests := []struct {
		name      string
		scope     Oauth2CustomScope
		wantError bool
	}{
		{name: "no claims key", scope: Oauth2CustomScope{Name: "mail:diagnose", Description: "Read diagnostics"}},
		{name: "empty claims list", scope: Oauth2CustomScope{Name: "mail:diagnose", Description: "Read diagnostics", Claims: []OIDCCustomClaim{}}},
		{name: "claims", scope: scopeCatalogTestScope("mail:diagnose", "groups")},
		{name: "description stays required", scope: Oauth2CustomScope{Name: "mail:diagnose"}, wantError: true},
		{name: "claim entries stay validated", scope: Oauth2CustomScope{
			Name: "mail:diagnose", Description: "Read diagnostics", Claims: []OIDCCustomClaim{{Name: "groups"}},
		}, wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validate.Struct(&tt.scope); (err != nil) != tt.wantError {
				t.Fatalf("struct validation error = %v, wantError = %t", err, tt.wantError)
			}
		})
	}
}

// scopeCatalogCase is one configuration and the findings the catalog must report for it.
type scopeCatalogCase struct {
	name     string
	settings *FileSettings
	want     []oidcScopeFinding
}

// scopeCatalogCases covers consistent configurations and each of the three reported inconsistencies.
func scopeCatalogCases() []scopeCatalogCase {
	return []scopeCatalogCase{
		{
			name: "claim-less custom scope allowed for a client is consistent",
			settings: scopeCatalogTestSettings(
				[]Oauth2CustomScope{scopeCatalogTestScope("mail:diagnose")},
				OIDCClient{ClientID: "support", Scopes: []string{"openid", "mail:diagnose"}},
			),
		},
		{
			name: "mapped claim released by a custom scope of the client is consistent",
			settings: scopeCatalogTestSettings(nil, OIDCClient{
				ClientID: "support", Scopes: []string{"openid", "mail:diagnose"},
				CustomScopes:      []Oauth2CustomScope{scopeCatalogTestScope("mail:diagnose", "groups")},
				AccessTokenClaims: AccessTokenClaims{Mappings: scopeCatalogTestMappings("groups")},
			}),
		},
		{
			name: "mapped claim no allowed scope releases",
			settings: scopeCatalogTestSettings(
				[]Oauth2CustomScope{scopeCatalogTestScope("mail:diagnose")},
				OIDCClient{
					ClientID: "support", Scopes: []string{"openid", "mail:diagnose"},
					IDTokenClaims:     IDTokenClaims{Mappings: scopeCatalogTestMappings("roles")},
					AccessTokenClaims: AccessTokenClaims{Mappings: scopeCatalogTestMappings("groups", "roles")},
				},
			),
			want: []oidcScopeFinding{
				{Problem: scopeFindingUnreleasableClaim, ClientID: "support", Claim: "roles"},
				{Problem: scopeFindingUnreleasableClaim, ClientID: "support", Claim: "groups"},
			},
		},
		{
			name: "standard claim released by its allowed standard scope is consistent",
			settings: scopeCatalogTestSettings(nil, OIDCClient{
				ClientID: "webmail", Scopes: []string{"openid", "groups"},
				IDTokenClaims: IDTokenClaims{Mappings: scopeCatalogTestMappings("groups")},
			}),
		},
		{
			name: "custom scope no client allows",
			settings: scopeCatalogTestSettings(
				[]Oauth2CustomScope{scopeCatalogTestScope("mail:diagnose")},
				OIDCClient{
					ClientID: "webmail", Scopes: []string{"openid"},
					CustomScopes: []Oauth2CustomScope{scopeCatalogTestScope("webmail:admin")},
				},
			),
			want: []oidcScopeFinding{
				{Problem: scopeFindingUnusedCustomScope, ClientID: "webmail", Scope: "webmail:admin"},
				{Problem: scopeFindingUnusedCustomScope, Scope: "mail:diagnose"},
			},
		},
		{
			name: "client scope nothing declares",
			settings: scopeCatalogTestSettings(nil, OIDCClient{
				ClientID: "support", Scopes: []string{"openid", "mail:diagnoze"}, ImpliedScopes: []string{"mail:diagnoze", "nauthilus:admin"},
			}),
			want: []oidcScopeFinding{{Problem: scopeFindingUndeclaredScope, ClientID: "support", Scope: "mail:diagnoze"}},
		},
	}
}

// TestOIDCScopeCatalogFindings verifies the three inconsistencies the catalog reports and that consistent
// configurations, including a claim-less custom scope, report nothing.
func TestOIDCScopeCatalogFindings(t *testing.T) {
	for _, tt := range scopeCatalogCases() {
		t.Run(tt.name, func(t *testing.T) {
			if got := newOIDCScopeCatalog(tt.settings).findings(); !slices.Equal(got, tt.want) {
				t.Fatalf("findings() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestOIDCScopeCatalogKnowsScopesOfOtherComponents verifies that scopes required by hooks and scopes of
// dynamically registered clients are not reported.
func TestOIDCScopeCatalogKnowsScopesOfOtherComponents(t *testing.T) {
	settings := scopeCatalogTestSettings(
		[]Oauth2CustomScope{scopeCatalogTestScope("mail-client:sync")},
		OIDCClient{ClientID: "postfix-bridge", Scopes: []string{"nauthilus:authenticate", "workshop:postfix", "reputation:admin"}},
	)
	settings.Lua = &LuaSection{Hooks: []LuaHooks{{Location: "postfix/policy", Method: "POST", Scopes: []string{"workshop:postfix"}}}}
	settings.Plugins = &PluginsSection{Modules: []PluginModule{{
		Hooks: []PluginHookAuthorization{{Name: "reputation", RequiredScopes: []string{"reputation:admin"}}},
	}}}
	settings.IDP.OIDC.DynamicClientRegistration.OptionalScopes = []string{"mail-client:sync"}

	if got := newOIDCScopeCatalog(settings).findings(); len(got) != 0 {
		t.Fatalf("findings() = %+v, want none", got)
	}
}

// TestWarnIDPOIDCScopeFindingsNeverFailsTheLoad verifies that findings are warnings and a disabled issuer is skipped.
func TestWarnIDPOIDCScopeFindingsNeverFailsTheLoad(t *testing.T) {
	inconsistent := scopeCatalogTestSettings(nil, OIDCClient{ClientID: "support", Scopes: []string{"mail:diagnoze"}})

	disabled := scopeCatalogTestSettings(nil)
	disabled.IDP.OIDC.Enabled = false

	for name, settings := range map[string]*FileSettings{"inconsistent": inconsistent, "disabled": disabled, "no identity section": {}} {
		t.Run(name, func(t *testing.T) {
			if err := settings.warnIDPOIDCScopeFindings(); err != nil {
				t.Fatalf("warnIDPOIDCScopeFindings() error = %v", err)
			}
		})
	}
}
