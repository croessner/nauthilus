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
	"context"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/idp"
	"github.com/croessner/nauthilus/v4/server/middleware/oidcbearer"
	"github.com/golang-jwt/jwt/v5"
)

// oidcClientResolver resolves a static or dynamic client by its id.
type oidcClientResolver func(ctx context.Context, clientID string) (*config.OIDCClient, error)

// accessTokenIntrospectionPolicy decides whether an authenticated client may see a validated access token.
type accessTokenIntrospectionPolicy struct {
	resources     *idp.ResourceRegistry
	resolveClient oidcClientResolver
}

// introspectionPolicy binds the introspection decision to the current resource registry and client lookup.
func (h *OIDCHandler) introspectionPolicy() accessTokenIntrospectionPolicy {
	return accessTokenIntrospectionPolicy{resources: h.idp.ResourceRegistry(), resolveClient: h.idp.ResolveClient}
}

// allows binds tokens to their recipient, an explicitly authorized backchannel inspector, or a resource
// server with delegated user-token introspection authority.
func (p accessTokenIntrospectionPolicy) allows(ctx context.Context, caller *config.OIDCClient, claims jwt.MapClaims) bool {
	if caller == nil || caller.Dynamic {
		return false
	}

	if oidcbearer.HasAudience(claims, caller.ClientID) {
		return true
	}

	if caller.AllowsBackchannelIntrospection() && oidcbearer.IsBackchannelAccessToken(claims) {
		return true
	}

	return p.allowsDelegatedUserToken(ctx, caller, claims)
}

// allowsDelegatedUserToken applies token_introspection to user access tokens of other clients. A token
// bound to resources is visible only to the owner of one of them; a plain token only when its issuing
// client is allowlisted. An issuing client that cannot be resolved denies the request.
func (p accessTokenIntrospectionPolicy) allowsDelegatedUserToken(ctx context.Context, caller *config.OIDCClient, claims jwt.MapClaims) bool {
	if !caller.AllowsTokenIntrospection() || !isUserAccessToken(claims) {
		return false
	}

	issuingClientID, ok := idp.AccessTokenIssuingClient(claims)
	if !ok {
		return false
	}

	resources, ok := idp.AccessTokenResourceAudiences(claims, issuingClientID)
	if !ok {
		return false
	}

	token := idp.IntrospectedUserToken{Resources: resources}

	if len(resources) == 0 {
		if p.resolveClient == nil {
			return false
		}

		issuing, err := p.resolveClient(ctx, issuingClientID)
		if err != nil || issuing == nil {
			return false
		}

		token.IssuingClient = issuing
	}

	return p.resources.MayIntrospect(caller, token)
}

// isUserAccessToken accepts access tokens that carry no service-token discriminator and no Nauthilus API audience.
func isUserAccessToken(claims jwt.MapClaims) bool {
	if !oidcbearer.HasTokenType(claims, definitions.TokenTypeAccessToken) {
		return false
	}

	if _, service := claims[definitions.ClaimClientID]; service {
		return false
	}

	return !oidcbearer.HasAudience(claims, definitions.AudienceBackchannelAPI) &&
		!oidcbearer.HasAudience(claims, definitions.AudiencePolicyAPI)
}
