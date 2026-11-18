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
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
)

const (
	// HostedResourceUserRightFromGroups evaluates the user right against resolved group names.
	HostedResourceUserRightFromGroups = "groups"

	// HostedResourceUserRightFromGroupDistinguishedNames evaluates the user right against resolved group distinguished names.
	HostedResourceUserRightFromGroupDistinguishedNames = "group_dns"

	defaultHostedResourceMaxAuthenticationAge   = 12 * time.Hour
	minHostedResourceMaxAuthenticationAge       = 5 * time.Minute
	maxHostedResourceMaxAuthenticationAge       = 30 * 24 * time.Hour
	defaultHostedResourceMaxAccessTokenLifetime = 15 * time.Minute
	minHostedResourceMaxAccessTokenLifetime     = time.Minute
	maxHostedResourceMaxAccessTokenLifetime     = time.Hour

	oidcHostedResourcesPath = "identity.oidc.hosted_resources"
)

// hostedResourceNamePattern keeps hosted resource names short, lower-case, and usable as a config reference.
var hostedResourceNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// OIDCHostedResource is an RFC 8707 protected resource that Nauthilus serves itself (for example the read-only MCP
// support endpoint). Nauthilus is its authorization server and its resource server. Only the listed static clients
// may obtain tokens for it, only users holding the user right are admitted at authorization time, and a grant for
// it never carries another resource.
type OIDCHostedResource struct {
	Scopes                 []string                    `mapstructure:"scopes"`
	StaticClients          []string                    `mapstructure:"static_clients"`
	UserRight              OIDCHostedResourceUserRight `mapstructure:"user_right"`
	Name                   string                      `mapstructure:"name"`
	Resource               string                      `mapstructure:"resource"`
	MaxAuthenticationAge   time.Duration               `mapstructure:"max_authentication_age"`
	MaxAccessTokenLifetime time.Duration               `mapstructure:"max_access_token_lifetime"`
}

// OIDCHostedResourceUserRight names the directory groups that entitle a user. The issuer evaluates them against the
// groups of a fresh backend lookup when it issues an authorization code; a token claim never decides it.
type OIDCHostedResourceUserRight struct {
	AnyOf []string `mapstructure:"any_of"`
	From  string   `mapstructure:"from"`
}

// GetMaxAuthenticationAge returns how long after the interactive login a grant for the resource may still be
// issued or refreshed.
func (r *OIDCHostedResource) GetMaxAuthenticationAge() time.Duration {
	if r == nil || r.MaxAuthenticationAge <= 0 {
		return defaultHostedResourceMaxAuthenticationAge
	}

	return r.MaxAuthenticationAge
}

// GetMaxAccessTokenLifetime returns the access-token lifetime ceiling for the resource.
func (r *OIDCHostedResource) GetMaxAccessTokenLifetime() time.Duration {
	if r == nil || r.MaxAccessTokenLifetime <= 0 {
		return defaultHostedResourceMaxAccessTokenLifetime
	}

	return r.MaxAccessTokenLifetime
}

// AdmitsClientID reports whether the static client id is listed for the resource.
func (r *OIDCHostedResource) AdmitsClientID(clientID string) bool {
	return r != nil && clientID != "" && slices.Contains(r.StaticClients, clientID)
}

// cloneHostedResources deep-copies hosted resources so materialized config never aliases wire-level slices.
func cloneHostedResources(resources []OIDCHostedResource) []OIDCHostedResource {
	if len(resources) == 0 {
		return nil
	}

	cloned := make([]OIDCHostedResource, len(resources))

	for idx, resource := range resources {
		resource.Scopes = slices.Clone(resource.Scopes)
		resource.StaticClients = slices.Clone(resource.StaticClients)
		resource.UserRight.AnyOf = slices.Clone(resource.UserRight.AnyOf)
		cloned[idx] = resource
	}

	return cloned
}

// GetHostedResources returns the configured hosted resources.
func (o *OIDCConfig) GetHostedResources() []OIDCHostedResource {
	if o == nil {
		return nil
	}

	return o.HostedResources
}

// FindHostedResource returns the hosted resource with the given name.
func (o *OIDCConfig) FindHostedResource(name string) (*OIDCHostedResource, bool) {
	return o.findHostedResource(func(resource *OIDCHostedResource) bool { return resource.Name == name })
}

// FindHostedResourceByURI returns the hosted resource with the given resource indicator.
func (o *OIDCConfig) FindHostedResourceByURI(resource string) (*OIDCHostedResource, bool) {
	return o.findHostedResource(func(candidate *OIDCHostedResource) bool { return candidate.Resource == resource })
}

// findHostedResource returns the first hosted resource that matches; it never matches an empty key.
func (o *OIDCConfig) findHostedResource(match func(*OIDCHostedResource) bool) (*OIDCHostedResource, bool) {
	if o == nil {
		return nil, false
	}

	for idx := range o.HostedResources {
		if match(&o.HostedResources[idx]) {
			return &o.HostedResources[idx], true
		}
	}

	return nil, false
}

// validateIDPOIDCHostedResources validates every hosted resource against the whole OIDC configuration.
func (f *FileSettings) validateIDPOIDCHostedResources() error {
	if f == nil || f.IDP == nil || len(f.IDP.OIDC.HostedResources) == 0 {
		return nil
	}

	oidc := &f.IDP.OIDC
	if !oidc.Enabled {
		return NewValidationProblem("identity.oidc.enabled", "must be enabled when hosted_resources are configured")
	}

	validator := newHostedResourceValidator(oidc)

	for idx := range oidc.HostedResources {
		if err := validator.validate(fmt.Sprintf("%s[%d]", oidcHostedResourcesPath, idx), &oidc.HostedResources[idx]); err != nil {
			return err
		}
	}

	return nil
}

// hostedResourceValidator checks hosted resources for uniqueness and against the configured clients.
type hostedResourceValidator struct {
	clients         map[string]*OIDCClient `mapstructure:"-"`
	clientResources map[string]struct{}    `mapstructure:"-"`
	names           map[string]struct{}    `mapstructure:"-"`
	resources       map[string]struct{}    `mapstructure:"-"`
}

// newHostedResourceValidator indexes clients and client-owned resources once.
func newHostedResourceValidator(oidc *OIDCConfig) *hostedResourceValidator {
	validator := &hostedResourceValidator{
		clients:         make(map[string]*OIDCClient, len(oidc.Clients)),
		clientResources: make(map[string]struct{}),
		names:           make(map[string]struct{}, len(oidc.HostedResources)),
		resources:       make(map[string]struct{}, len(oidc.HostedResources)),
	}

	for idx := range oidc.Clients {
		client := &oidc.Clients[idx]
		validator.clients[client.ClientID] = client

		for _, resource := range client.TokenIntrospection.Resources {
			validator.clientResources[resource] = struct{}{}
		}
	}

	return validator
}

// validate checks one hosted resource.
func (v *hostedResourceValidator) validate(path string, resource *OIDCHostedResource) error {
	checks := []func(string, *OIDCHostedResource) error{
		v.validateName,
		v.validateResource,
		validateHostedResourceScopes,
		validateHostedResourceUserRight,
		validateHostedResourceDurations,
		v.validateStaticClients,
	}

	for _, check := range checks {
		if err := check(path, resource); err != nil {
			return err
		}
	}

	return nil
}

// validateName requires a unique reference name.
func (v *hostedResourceValidator) validateName(path string, resource *OIDCHostedResource) error {
	if !hostedResourceNamePattern.MatchString(resource.Name) {
		return NewValidationProblem(path+".name", "must be 1-63 lower-case letters, digits, or dashes")
	}

	if _, taken := v.names[resource.Name]; taken {
		return NewValidationProblem(path+".name", "must be unique")
	}

	v.names[resource.Name] = struct{}{}

	return nil
}

// validateResource requires a unique HTTPS resource indicator (plain HTTP only on loopback) that no client owns.
func (v *hostedResourceValidator) validateResource(path string, resource *OIDCHostedResource) error {
	field := path + ".resource"

	if reason := hostedResourceURLDefect(resource.Resource); reason != "" {
		return NewValidationProblem(field, reason)
	}

	if reason := v.resourceCollision(resource.Resource); reason != "" {
		return NewValidationProblem(field, reason)
	}

	v.resources[resource.Resource] = struct{}{}

	return nil
}

// hostedResourceURLDefect returns why a hosted resource indicator is not an acceptable URL, or "".
func hostedResourceURLDefect(resource string) string {
	if err := ValidateOIDCResourceIndicator(resource); err != nil {
		return err.Error()
	}

	parsed, err := url.Parse(resource)
	if err != nil || parsed.Host == "" || parsed.RawQuery != "" || parsed.User != nil {
		return "must be an absolute URL with a host and without query or user info"
	}

	secure := strings.EqualFold(parsed.Scheme, uriSchemeHTTPS)
	loopbackHTTP := strings.EqualFold(parsed.Scheme, uriSchemeHTTP) && isLoopbackHost(parsed.Hostname())

	if !secure && !loopbackHTTP {
		return "must use https; plain http is allowed only for loopback hosts"
	}

	if isReservedOIDCResource(resource) {
		return "must not use a reserved nauthilus audience"
	}

	return ""
}

// resourceCollision returns why a hosted resource indicator collides with a client, a client resource, or another
// hosted resource, or "".
func (v *hostedResourceValidator) resourceCollision(resource string) string {
	if _, owned := v.clientResources[resource]; owned {
		return "must not equal a resource owned by a client token_introspection block"
	}

	if _, collides := v.clients[resource]; collides {
		return "must not equal a configured client_id"
	}

	if _, taken := v.resources[resource]; taken {
		return "must be unique"
	}

	return ""
}

// isLoopbackHost reports whether host is localhost or a loopback IP literal.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}

	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}

// validateHostedResourceScopes requires a non-empty, duplicate-free subset of the hosted support scopes.
func validateHostedResourceScopes(path string, resource *OIDCHostedResource) error {
	field := path + ".scopes"

	if len(resource.Scopes) == 0 {
		return NewValidationProblem(field, "must list at least one scope")
	}

	return validateUniqueMembers(field, resource.Scopes, func(scope string) bool {
		return slices.Contains(definitions.HostedResourceScopes, scope)
	}, "must be one of "+strings.Join(definitions.HostedResourceScopes, ", "))
}

// validateHostedResourceUserRight requires a group source and at least one entitling group.
func validateHostedResourceUserRight(path string, resource *OIDCHostedResource) error {
	field := path + ".user_right"
	right := resource.UserRight

	if right.From != HostedResourceUserRightFromGroups && right.From != HostedResourceUserRightFromGroupDistinguishedNames {
		return NewValidationProblem(field+".from", "must be groups or group_dns")
	}

	if len(right.AnyOf) == 0 {
		return NewValidationProblem(field+".any_of", "must list at least one group")
	}

	return validateUniqueMembers(field+".any_of", right.AnyOf, func(group string) bool {
		return group != "" && strings.TrimSpace(group) == group
	}, "must not be empty or padded")
}

// validateUniqueMembers checks every entry with accept and rejects duplicates.
func validateUniqueMembers(path string, values []string, accept func(string) bool, rejection string) error {
	seen := make(map[string]struct{}, len(values))

	for idx, value := range values {
		elementPath := fmt.Sprintf("%s[%d]", path, idx)

		if !accept(value) {
			return NewValidationProblem(elementPath, rejection)
		}

		if _, duplicate := seen[value]; duplicate {
			return NewValidationProblem(elementPath, "must not repeat a value")
		}

		seen[value] = struct{}{}
	}

	return nil
}

// validateHostedResourceDurations bounds the authentication age and the access-token lifetime ceiling.
func validateHostedResourceDurations(path string, resource *OIDCHostedResource) error {
	if age := resource.GetMaxAuthenticationAge(); age < minHostedResourceMaxAuthenticationAge || age > maxHostedResourceMaxAuthenticationAge {
		return NewValidationProblem(path+".max_authentication_age", "must be between 5m and 720h")
	}

	if lifetime := resource.GetMaxAccessTokenLifetime(); lifetime < minHostedResourceMaxAccessTokenLifetime ||
		lifetime > maxHostedResourceMaxAccessTokenLifetime {
		return NewValidationProblem(path+".max_access_token_lifetime", "must be between 1m and 1h")
	}

	return nil
}

// validateStaticClients requires every listed client to exist and to be fit for interactive support access.
func (v *hostedResourceValidator) validateStaticClients(path string, resource *OIDCHostedResource) error {
	field := path + ".static_clients"

	if len(resource.StaticClients) == 0 {
		return NewValidationProblem(field, "must list at least one static client")
	}

	if err := validateUniqueMembers(field, resource.StaticClients, func(clientID string) bool {
		_, ok := v.clients[clientID]

		return ok
	}, "must name a configured static client"); err != nil {
		return err
	}

	for idx, clientID := range resource.StaticClients {
		if reason := hostedResourceClientDefect(v.clients[clientID], resource); reason != "" {
			return NewValidationProblem(fmt.Sprintf("%s[%d]", field, idx), reason)
		}
	}

	return nil
}

// hostedResourceClientDefect returns why a static client may not be admitted, or "" when it may.
func hostedResourceClientDefect(client *OIDCClient, resource *OIDCHostedResource) string {
	switch {
	case !client.RequiresPKCE():
		return "client must be public or set require_pkce"
	case !hostedResourceGrantTypesAllowed(client.GetGrantTypes()):
		return "client grant_types must be authorization_code, optionally with refresh_token"
	case len(client.RequireMFA) == 0 && client.RequiredMFALevel <= 0:
		return "client must require MFA (require_mfa or required_mfa_level)"
	case !slices.ContainsFunc(resource.Scopes, func(scope string) bool { return slices.Contains(client.Scopes, scope) }):
		return "client scopes must contain at least one scope of the hosted resource"
	default:
		return ""
	}
}

// hostedResourceGrantTypesAllowed accepts authorization_code with an optional refresh_token grant only.
func hostedResourceGrantTypesAllowed(grantTypes []string) bool {
	if !slices.Contains(grantTypes, definitions.OIDCFlowAuthorizationCode) {
		return false
	}

	for _, grantType := range grantTypes {
		if grantType != definitions.OIDCFlowAuthorizationCode && grantType != definitions.OIDCFlowRefreshToken {
			return false
		}
	}

	return true
}
