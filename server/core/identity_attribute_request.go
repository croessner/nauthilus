// Copyright (C) 2026 Christian Roessner
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

package core

import (
	"sort"
	"strings"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
)

// IdentityAttributeRequest describes backend identity data needed by edge-side claim materialization.
type IdentityAttributeRequest struct {
	Names                          []string
	IncludeStandardIdentity        bool
	IncludeGroups                  bool
	IncludeGroupDistinguishedNames bool
	ReportMissing                  bool
}

// Clone returns a detached copy of the request.
func (r *IdentityAttributeRequest) Clone() *IdentityAttributeRequest {
	if r == nil {
		return nil
	}

	return &IdentityAttributeRequest{
		Names:                          append([]string(nil), r.Names...),
		IncludeStandardIdentity:        r.IncludeStandardIdentity,
		IncludeGroups:                  r.IncludeGroups,
		IncludeGroupDistinguishedNames: r.IncludeGroupDistinguishedNames,
		ReportMissing:                  r.ReportMissing,
	}
}

// NewOIDCIdentityAttributeRequest derives backend attributes from OIDC claim mappings and granted scopes.
func NewOIDCIdentityAttributeRequest(
	client *config.OIDCClient,
	requestedScopes []string,
	customScopes []config.Oauth2CustomScope,
) *IdentityAttributeRequest {
	request := newBaseIdentityAttributeRequest()
	if client == nil {
		return request
	}

	collector := newIdentityAttributeCollector(request)
	scopeManager := NewScopeManager(requestedScopes, customScopes)
	collector.collectOIDCMappings(client.IDTokenClaims.GetMappings(), scopeManager)
	collector.collectOIDCMappings(client.AccessTokenClaims.GetMappings(), scopeManager)
	collector.finalize()

	return request
}

// NewSAMLIdentityAttributeRequest derives backend attributes from SAML SP attribute configuration.
func NewSAMLIdentityAttributeRequest(sp *config.SAML2ServiceProvider) *IdentityAttributeRequest {
	request := newBaseIdentityAttributeRequest()
	collector := newIdentityAttributeCollector(request)

	for _, name := range sp.GetAllowedAttributes() {
		collector.addSource(name)
	}

	collector.finalize()

	return request
}

func newBaseIdentityAttributeRequest() *IdentityAttributeRequest {
	return &IdentityAttributeRequest{
		IncludeStandardIdentity: true,
		ReportMissing:           true,
	}
}

type identityAttributeCollector struct {
	request *IdentityAttributeRequest
	names   map[string]struct{}
}

func newIdentityAttributeCollector(request *IdentityAttributeRequest) *identityAttributeCollector {
	return &identityAttributeCollector{
		request: request,
		names:   make(map[string]struct{}),
	}
}

func (c *identityAttributeCollector) collectOIDCMappings(mappings []config.OIDCClaimMapping, scopes *ScopeManager) {
	for _, mapping := range mappings {
		if mapping.Claim == "" || !scopes.AllowsClaim(mapping.Claim) {
			continue
		}

		if mapping.Attribute != "" {
			c.addSource(mapping.Attribute)

			continue
		}

		c.addSource(mapping.From)
	}
}

func (c *identityAttributeCollector) addSource(name string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}

	switch name {
	case definitions.ClaimGroups:
		c.request.IncludeGroups = true
	case definitions.LuaBackendResultGroupDistinguishedNames:
		c.request.IncludeGroupDistinguishedNames = true
	default:
		c.names[name] = struct{}{}
	}
}

func (c *identityAttributeCollector) finalize() {
	if len(c.names) == 0 {
		return
	}

	c.request.Names = make([]string, 0, len(c.names))
	for name := range c.names {
		c.request.Names = append(c.request.Names, name)
	}

	sort.Strings(c.request.Names)
}
