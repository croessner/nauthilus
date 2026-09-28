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
	"fmt"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
)

// passwordProtocolBinding is the OIDC client or SAML service provider of one password attempt.
// It resolves an OIDC client lazily and at most once, so dynamic clients cost one authoritative
// repository read per attempt however many decisions consult the binding.
type passwordProtocolBinding struct {
	ctx            context.Context
	idp            *NauthilusIDP
	client         *config.OIDCClient
	clientErr      error
	oidcClientID   string
	samlEntityID   string
	clientResolved bool
}

// newPasswordProtocolBinding binds one password attempt to its protocol peer without resolving it yet.
func (n *NauthilusIDP) newPasswordProtocolBinding(
	ctx context.Context,
	oidcClientID string,
	samlEntityID string,
) *passwordProtocolBinding {
	return &passwordProtocolBinding{
		ctx:          ctx,
		idp:          n,
		oidcClientID: oidcClientID,
		samlEntityID: samlEntityID,
	}
}

// oidcClient returns the memoized authoritative resolution of the bound OIDC client,
// including a resolution error, so one attempt never mixes two resolution results.
func (b *passwordProtocolBinding) oidcClient() (*config.OIDCClient, error) {
	if !b.clientResolved {
		b.client, b.clientErr = b.idp.ResolveClient(b.ctx, b.oidcClientID)
		b.clientResolved = true
	}

	return b.client, b.clientErr
}

// delayedResponse reports whether the bound peer enables delayed login-failure presentation.
// An unresolvable peer keeps the immediate presentation.
func (b *passwordProtocolBinding) delayedResponse() bool {
	if b.oidcClientID != "" {
		if client, err := b.oidcClient(); err == nil {
			return client.IsDelayedResponse()
		}
	}

	if b.samlEntityID != "" {
		if serviceProvider, ok := b.idp.FindSAMLServiceProvider(b.samlEntityID); ok {
			return serviceProvider.IsDelayedResponse()
		}
	}

	return false
}

// identityAttributes builds the attribute request an identity lookup must satisfy for the bound peer.
func (b *passwordProtocolBinding) identityAttributes(
	protocolContext core.IDPRequestContext,
) (*core.IdentityAttributeRequest, error) {
	if b.oidcClientID != "" {
		client, err := b.oidcClient()
		if err != nil {
			return nil, err
		}

		effectiveScopes := b.idp.deps.Cfg.GetIDP().OIDC.GetEffectiveCustomScopes(client)

		return core.NewOIDCIdentityAttributeRequest(
			client, protocolContext.RequestedScopes, effectiveScopes,
		), nil
	}

	if b.samlEntityID != "" {
		serviceProvider, ok := b.idp.FindSAMLServiceProvider(b.samlEntityID)
		if !ok {
			return nil, fmt.Errorf("delayed password SAML service provider not found")
		}

		return core.NewSAMLIdentityAttributeRequest(serviceProvider), nil
	}

	return nil, fmt.Errorf("delayed password protocol binding is missing")
}
