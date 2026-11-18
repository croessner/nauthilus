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
	"errors"
	"slices"
	"time"

	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
)

var (
	// ErrHostedResourceDenied reports an authenticated user without the user right of a requested hosted resource.
	// Authorization answers access_denied.
	ErrHostedResourceDenied = errors.New("hosted resource access denied")

	// ErrHostedAuthenticationExpired reports a grant whose interactive login is older than the hosted resource
	// allows. Authorization forces a new login; the token endpoint answers invalid_grant.
	ErrHostedAuthenticationExpired = errors.New("hosted resource authentication too old")
)

// HostedResource is the admission view of one hosted resource. The resource registry, the authorization and token
// endpoints, and the resource server of the hosted resource all decide through this one object, built from the
// current configuration on every use.
type HostedResource struct {
	cfg *config.OIDCHostedResource
}

// NewHostedResource wraps one configured hosted resource.
func NewHostedResource(cfg *config.OIDCHostedResource) (HostedResource, bool) {
	return HostedResource{cfg: cfg}, cfg != nil
}

// HostedResource returns the hosted resource with the given configured name.
func (n *NauthilusIDP) HostedResource(name string) (HostedResource, bool) {
	cfg, ok := n.deps.Cfg.GetIDP().OIDC.FindHostedResource(name)
	if !ok {
		return HostedResource{}, false
	}

	return NewHostedResource(cfg)
}

// Name returns the configured reference name.
func (h HostedResource) Name() string {
	if h.cfg == nil {
		return ""
	}

	return h.cfg.Name
}

// Resource returns the RFC 8707 resource indicator, which is also the audience of its access tokens.
func (h HostedResource) Resource() string {
	if h.cfg == nil {
		return ""
	}

	return h.cfg.Resource
}

// Scopes returns the scopes the resource gates.
func (h HostedResource) Scopes() []string {
	if h.cfg == nil {
		return nil
	}

	return slices.Clone(h.cfg.Scopes)
}

// Admits reports whether the client may obtain tokens for the resource. Only listed static clients are admitted;
// a dynamically registered client never is, whatever it declared at registration.
func (h HostedResource) Admits(client *config.OIDCClient) bool {
	return h.cfg != nil && client != nil && !client.Dynamic && h.cfg.AdmitsClientID(client.ClientID)
}

// PermitsUser reports whether the groups of a fresh backend lookup contain one of the entitling groups.
func (h HostedResource) PermitsUser(user *backend.User) bool {
	if h.cfg == nil || user == nil {
		return false
	}

	groups := user.Groups
	if h.cfg.UserRight.From == config.HostedResourceUserRightFromGroupDistinguishedNames {
		groups = user.GroupDistinguishedNames
	}

	return slices.ContainsFunc(h.cfg.UserRight.AnyOf, func(group string) bool {
		return group != "" && slices.Contains(groups, group)
	})
}

// AuthenticationCurrent reports whether an interactive login at authTime is still young enough at now. A missing
// login time is never current.
func (h HostedResource) AuthenticationCurrent(authTime time.Time, now time.Time) bool {
	if h.cfg == nil || authTime.IsZero() || authTime.After(now) {
		return false
	}

	return now.Sub(authTime) <= h.cfg.GetMaxAuthenticationAge()
}

// capAccessTokenLifetime returns the lifetime bounded by the resource's ceiling.
func (h HostedResource) capAccessTokenLifetime(lifetime time.Duration) time.Duration {
	if h.cfg == nil {
		return lifetime
	}

	return min(lifetime, h.cfg.GetMaxAccessTokenLifetime())
}

// requestsGroups adds the group source of the user right to a backend attribute request.
func (h HostedResource) requestsGroups(request *core.IdentityAttributeRequest) {
	if h.cfg == nil || request == nil {
		return
	}

	if h.cfg.UserRight.From == config.HostedResourceUserRightFromGroupDistinguishedNames {
		request.IncludeGroupDistinguishedNames = true

		return
	}

	request.IncludeGroups = true
}

// hostedResourcesOf returns the hosted resources among resources.
func (r *ResourceRegistry) hostedResourcesOf(resources []string) []HostedResource {
	if r == nil {
		return nil
	}

	var hosted []HostedResource

	for _, resource := range resources {
		if candidate, ok := r.Hosted(resource); ok {
			hosted = append(hosted, candidate)
		}
	}

	return hosted
}

// AdmitHostedResourceUser checks, at authorization time, that the user of a fresh backend lookup holds the user
// right of every requested hosted resource and that the login is young enough. It returns
// ErrHostedResourceDenied or ErrHostedAuthenticationExpired.
func (n *NauthilusIDP) AdmitHostedResourceUser(resources []string, user *backend.User, authTime time.Time, now time.Time) error {
	for _, hosted := range n.ResourceRegistry().hostedResourcesOf(resources) {
		if !hosted.PermitsUser(user) {
			return ErrHostedResourceDenied
		}

		if !hosted.AuthenticationCurrent(authTime, now) {
			return ErrHostedAuthenticationExpired
		}
	}

	return nil
}

// HostedAuthenticationExpired reports whether an authorization request for resources needs a fresh login because
// the current login is older than a requested hosted resource allows.
func (n *NauthilusIDP) HostedAuthenticationExpired(resources []string, authTime time.Time, now time.Time) bool {
	return slices.ContainsFunc(n.ResourceRegistry().hostedResourcesOf(resources), func(hosted HostedResource) bool {
		return !hosted.AuthenticationCurrent(authTime, now)
	})
}

// checkHostedGrant refuses token issuance and refresh for a hosted resource once the grant's login is too old.
func (n *NauthilusIDP) checkHostedGrant(session *OIDCSession, resources []string, now time.Time) error {
	for _, hosted := range n.ResourceRegistry().hostedResourcesOf(resources) {
		if session == nil || !hosted.AuthenticationCurrent(session.AuthTime, now) {
			return ErrHostedAuthenticationExpired
		}
	}

	return nil
}

// capHostedAccessTokenLifetime bounds an access-token lifetime by every hosted resource the token carries.
func (n *NauthilusIDP) capHostedAccessTokenLifetime(lifetime time.Duration, resources []string) time.Duration {
	for _, hosted := range n.ResourceRegistry().hostedResourcesOf(resources) {
		lifetime = hosted.capAccessTokenLifetime(lifetime)
	}

	return lifetime
}

// requestHostedResourceGroups makes a claims lookup for an admitted client also resolve the groups its hosted
// resources evaluate, so the user right is decided on directory data rather than on scope-gated claims.
func (n *NauthilusIDP) requestHostedResourceGroups(request *core.IdentityAttributeRequest, client *config.OIDCClient) {
	resources := n.deps.Cfg.GetIDP().OIDC.GetHostedResources()

	for idx := range resources {
		if hosted, ok := NewHostedResource(&resources[idx]); ok && hosted.Admits(client) {
			hosted.requestsGroups(request)
		}
	}
}

// Issuer returns the configured issuer identifier.
func (n *NauthilusIDP) Issuer() string {
	return n.deps.Cfg.GetIDP().OIDC.Issuer
}
