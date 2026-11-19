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

	"github.com/croessner/nauthilus/v4/server/definitions"
)

const (
	// scopeFindingUnreleasableClaim reports a claim mapping that can never reach a token of its client.
	scopeFindingUnreleasableClaim = "OIDC claim mapping is never released: no scope allowed for the client releases the claim"

	// scopeFindingUnusedCustomScope reports a declared scope no client may request.
	scopeFindingUnusedCustomScope = "OIDC custom scope is not allowed for any client"

	// scopeFindingUndeclaredScope reports a client scope that nothing in the configuration defines.
	scopeFindingUndeclaredScope = "OIDC client scope is neither built in nor declared in custom_scopes or by a hook"
)

// oidcScopeFinding is one inconsistency between declared scopes, client scopes, and claim mappings.
type oidcScopeFinding struct {
	Problem  string `mapstructure:"-"`
	ClientID string `mapstructure:"-"`
	Scope    string `mapstructure:"-"`
	Claim    string `mapstructure:"-"`
}

// oidcScopeCatalog knows which scopes the deployment declares and which of them release a claim. A custom scope
// declares a scope; listing claims for it is optional and only decides which claims the scope releases.
type oidcScopeCatalog struct {
	oidc     *OIDCConfig         `mapstructure:"-"`
	declared map[string]struct{} `mapstructure:"-"`
}

// newOIDCScopeCatalog collects the scopes defined outside a single client: the built-in scopes, the global
// custom scopes, and the scopes Lua and native hooks require.
func newOIDCScopeCatalog(f *FileSettings) *oidcScopeCatalog {
	catalog := &oidcScopeCatalog{oidc: &f.IDP.OIDC, declared: make(map[string]struct{})}

	catalog.declare(definitions.BuiltinScopes()...)

	for index := range catalog.oidc.CustomScopes {
		catalog.declare(catalog.oidc.CustomScopes[index].Name)
	}

	for _, hook := range f.GetLua().GetHooks() {
		catalog.declare(hook.GetScopes()...)
	}

	if plugins := f.GetPlugins(); plugins != nil {
		for moduleIndex := range plugins.Modules {
			for _, hook := range plugins.Modules[moduleIndex].Hooks {
				catalog.declare(hook.RequiredScopes...)
			}
		}
	}

	return catalog
}

// declare adds scopes to the declared set.
func (c *oidcScopeCatalog) declare(scopes ...string) {
	for _, scope := range scopes {
		c.declared[scope] = struct{}{}
	}
}

// findings lists every inconsistency of the configured clients and custom scopes in a stable order.
func (c *oidcScopeCatalog) findings() []oidcScopeFinding {
	var findings []oidcScopeFinding

	requestable := c.dynamicallyRegisteredScopes()

	for index := range c.oidc.Clients {
		client := &c.oidc.Clients[index]
		effective := c.oidc.GetEffectiveCustomScopes(client)

		findings = append(findings, c.undeclaredScopes(client, effective)...)
		findings = append(findings, unreleasableClaims(client, effective)...)
		findings = append(findings, unusedCustomScopes(client.ClientID, client.CustomScopes, client.GetAllowedScopes())...)

		requestable = append(requestable, client.GetAllowedScopes()...)
	}

	return append(findings, unusedCustomScopes("", c.oidc.CustomScopes, requestable)...)
}

// dynamicallyRegisteredScopes returns the scopes a dynamically registered client may hold.
func (c *oidcScopeCatalog) dynamicallyRegisteredScopes() []string {
	registration := &c.oidc.DynamicClientRegistration

	return slices.Concat(
		registration.RequiredScopes, registration.OptionalScopes, registration.DefaultScopes, registration.ImpliedScopes,
	)
}

// undeclaredScopes reports client scopes nothing defines; such a scope is usually a typing error.
func (c *oidcScopeCatalog) undeclaredScopes(client *OIDCClient, effective []Oauth2CustomScope) []oidcScopeFinding {
	var findings []oidcScopeFinding

	for _, scope := range uniqueScopes(client.Scopes, client.ImpliedScopes) {
		if _, declared := c.declared[scope]; declared || declaresCustomScope(effective, scope) {
			continue
		}

		findings = append(findings, oidcScopeFinding{Problem: scopeFindingUndeclaredScope, ClientID: client.ClientID, Scope: scope})
	}

	return findings
}

// unreleasableClaims reports mapped claims that no scope allowed for the client releases. Such a mapping is
// silently skipped for every request that names a scope, which is what a forgotten claim list of a custom scope
// looks like.
func unreleasableClaims(client *OIDCClient, effective []Oauth2CustomScope) []oidcScopeFinding {
	var findings []oidcScopeFinding

	allowed := client.GetAllowedScopes()
	mappings := slices.Concat(client.IDTokenClaims.GetMappings(), client.AccessTokenClaims.GetMappings())
	seen := make(map[string]struct{}, len(mappings))

	for index := range mappings {
		claim := mappings[index].Claim
		if _, duplicate := seen[claim]; duplicate || claim == "" {
			continue
		}

		seen[claim] = struct{}{}

		if slices.ContainsFunc(claimReleasingScopes(claim, effective), func(scope string) bool {
			return slices.Contains(allowed, scope)
		}) {
			continue
		}

		findings = append(findings, oidcScopeFinding{Problem: scopeFindingUnreleasableClaim, ClientID: client.ClientID, Claim: claim})
	}

	return findings
}

// claimReleasingScopes returns the scopes that release claim: its standard scope and every custom scope listing it.
func claimReleasingScopes(claim string, customScopes []Oauth2CustomScope) []string {
	var scopes []string

	if standardClaim, standard := definitions.StandardClaims()[claim]; standard {
		scopes = append(scopes, standardClaim.Scope)
	}

	for index := range customScopes {
		if slices.ContainsFunc(customScopes[index].Claims, func(customClaim OIDCCustomClaim) bool {
			return customClaim.Name == claim
		}) {
			scopes = append(scopes, customScopes[index].Name)
		}
	}

	return scopes
}

// unusedCustomScopes reports declared custom scopes that none of requestable allows; clientID is empty for the
// global custom scopes.
func unusedCustomScopes(clientID string, customScopes []Oauth2CustomScope, requestable []string) []oidcScopeFinding {
	var findings []oidcScopeFinding

	for index := range customScopes {
		if name := customScopes[index].Name; !slices.Contains(requestable, name) {
			findings = append(findings, oidcScopeFinding{Problem: scopeFindingUnusedCustomScope, ClientID: clientID, Scope: name})
		}
	}

	return findings
}

// declaresCustomScope reports whether customScopes declares scope.
func declaresCustomScope(customScopes []Oauth2CustomScope, scope string) bool {
	return slices.ContainsFunc(customScopes, func(customScope Oauth2CustomScope) bool {
		return customScope.Name == scope
	})
}

// uniqueScopes returns the scopes of all lists once each, in first-seen order.
func uniqueScopes(lists ...[]string) []string {
	var unique []string

	for _, scope := range slices.Concat(lists...) {
		if scope != "" && !slices.Contains(unique, scope) {
			unique = append(unique, scope)
		}
	}

	return unique
}

// warnIDPOIDCScopeFindings logs scope inconsistencies of an enabled OIDC issuer. They never fail the load: a
// scope may be defined by a component the configuration does not describe.
func (f *FileSettings) warnIDPOIDCScopeFindings() error {
	if f == nil || f.IDP == nil || !f.IDP.OIDC.Enabled {
		return nil
	}

	for _, finding := range newOIDCScopeCatalog(f).findings() {
		safeWarn("msg", finding.Problem, "client_id", finding.ClientID, "scope", finding.Scope, "claim", finding.Claim)
	}

	return nil
}
