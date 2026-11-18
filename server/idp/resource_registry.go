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
	"slices"

	"github.com/croessner/nauthilus/v4/server/config"
)

// IntrospectedUserToken describes the parts of a validated user access token that decide
// delegated introspection.
type IntrospectedUserToken struct {
	// IssuingClient is the client the token was issued to; it is only consulted for plain tokens.
	IssuingClient *config.OIDCClient
	// Resources are the token audiences other than the issuing client.
	Resources []string
}

// ResourceRegistry maps RFC 8707 resource indicators to the static client that owns them and to the hosted
// resources Nauthilus serves itself. Hosted resources have no owner client, so delegated introspection never
// matches them.
type ResourceRegistry struct {
	owners map[string]*config.OIDCClient
	hosted map[string]HostedResource
}

// NewResourceRegistry indexes the resources of every client with token introspection authority.
// Configuration validation keeps resources unique; a resource claimed twice anyway has no owner.
func NewResourceRegistry(clients []config.OIDCClient) *ResourceRegistry {
	owners := make(map[string]*config.OIDCClient)

	for idx := range clients {
		client := &clients[idx]
		if !client.AllowsTokenIntrospection() {
			continue
		}

		for _, resource := range client.TokenIntrospection.Resources {
			if current, taken := owners[resource]; taken && current != client {
				owners[resource] = nil

				continue
			}

			owners[resource] = client
		}
	}

	return &ResourceRegistry{owners: owners}
}

// NewResourceRegistryWithHosted indexes client-owned resources and the hosted resources of the configuration.
// Configuration validation keeps hosted resources disjoint from client-owned resources.
func NewResourceRegistryWithHosted(clients []config.OIDCClient, hosted []config.OIDCHostedResource) *ResourceRegistry {
	registry := NewResourceRegistry(clients)
	registry.hosted = make(map[string]HostedResource, len(hosted))

	for idx := range hosted {
		resource := &hosted[idx]
		if _, owned := registry.owners[resource.Resource]; owned {
			continue
		}

		registry.hosted[resource.Resource] = HostedResource{cfg: resource}
	}

	return registry
}

// ResourceRegistry builds the resource registry of the current configuration.
func (n *NauthilusIDP) ResourceRegistry() *ResourceRegistry {
	oidc := n.deps.Cfg.GetIDP().OIDC

	return NewResourceRegistryWithHosted(oidc.Clients, oidc.GetHostedResources())
}

// Hosted returns the hosted resource registered for a resource indicator.
func (r *ResourceRegistry) Hosted(resource string) (HostedResource, bool) {
	if r == nil {
		return HostedResource{}, false
	}

	hosted, ok := r.hosted[resource]

	return hosted, ok
}

// containsHosted reports whether resources name a hosted resource.
func (r *ResourceRegistry) containsHosted(resources []string) bool {
	return len(r.hostedResourcesOf(resources)) > 0
}

// ResourceOwner returns the client that owns a registered resource indicator.
func (r *ResourceRegistry) ResourceOwner(resource string) (*config.OIDCClient, bool) {
	if r == nil {
		return nil, false
	}

	owner := r.owners[resource]

	return owner, owner != nil
}

// MayRequest reports whether the issuing client may obtain tokens for a registered resource. A hosted resource
// admits only its listed static clients.
func (r *ResourceRegistry) MayRequest(issuing *config.OIDCClient, resource string) bool {
	if hosted, ok := r.Hosted(resource); ok {
		return hosted.Admits(issuing)
	}

	owner, ok := r.ResourceOwner(resource)

	return ok && owner.TokenIntrospection.AllowsIssuingClient(issuing)
}

// MayIntrospect decides delegated introspection of a user access token by a resource server.
// A token restricted to resources is only visible to the owner of one of them, regardless of the
// allowlist; a plain token is visible when its issuing client is allowlisted by the caller.
func (r *ResourceRegistry) MayIntrospect(caller *config.OIDCClient, token IntrospectedUserToken) bool {
	if r == nil || !caller.AllowsTokenIntrospection() {
		return false
	}

	if len(token.Resources) > 0 {
		return slices.ContainsFunc(token.Resources, func(resource string) bool {
			owner, ok := r.ResourceOwner(resource)

			return ok && owner.ClientID == caller.ClientID
		})
	}

	return caller.TokenIntrospection.AllowsIssuingClient(token.IssuingClient)
}
