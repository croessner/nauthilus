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
	"strings"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/idp/dcr"
	"github.com/golang-jwt/jwt/v5"
)

// ErrInvalidTarget reports a resource indicator that is malformed, unregistered, not requestable by the
// client, or outside the granted resources (RFC 8707 invalid_target).
var ErrInvalidTarget = errors.New("invalid target")

// TokenIssueOptions adjusts one token response without changing the persisted grant.
type TokenIssueOptions struct {
	// Resources narrows the access-token audience to a subset of the granted resources.
	// An empty list keeps the full grant.
	Resources []string
}

// uniqueResources removes repeated resource indicators and keeps the first-seen order.
func uniqueResources(resources []string) []string {
	if len(resources) == 0 {
		return nil
	}

	result := make([]string, 0, len(resources))

	for _, resource := range resources {
		if !slices.Contains(result, resource) {
			result = append(result, resource)
		}
	}

	return result
}

// ValidateRequestedResources checks the RFC 8707 resource parameters of an issuing client and returns
// them deduplicated. Every value must be an absolute URI without fragment, registered by a resource
// server, and requestable by the issuing client.
func (r *ResourceRegistry) ValidateRequestedResources(issuing *config.OIDCClient, requested []string) ([]string, error) {
	resources := uniqueResources(requested)

	for _, resource := range resources {
		if config.ValidateOIDCResourceIndicator(resource) != nil || !r.MayRequest(issuing, resource) {
			return nil, ErrInvalidTarget
		}
	}

	return resources, nil
}

// NarrowAccessTokenResources returns the requested subset of the granted resources. Without a request
// the result is nil, which keeps the full grant; a resource outside the grant is an invalid target.
func NarrowAccessTokenResources(granted []string, requested []string) ([]string, error) {
	narrowed := uniqueResources(requested)

	for _, resource := range narrowed {
		if !slices.Contains(granted, resource) {
			return nil, ErrInvalidTarget
		}
	}

	return narrowed, nil
}

// CheckAccessTokenResources reports whether a token request may issue an access token for the requested
// resources of a grant, without issuing anything. It returns ErrInvalidTarget otherwise.
func (n *NauthilusIDP) CheckAccessTokenResources(client *config.OIDCClient, granted []string, requested []string) error {
	_, err := n.accessTokenResources(client, granted, requested)

	return err
}

// accessTokenResources resolves the resources of one access token: the requested subset of the grant
// (nil keeps the whole grant). Every resource the token will carry must still be requestable by the
// client under the current configuration, so a revoked allowlist entry stops refresh as well.
func (n *NauthilusIDP) accessTokenResources(client *config.OIDCClient, granted []string, requested []string) ([]string, error) {
	narrowed, err := NarrowAccessTokenResources(granted, requested)
	if err != nil {
		return nil, err
	}

	effective := narrowed
	if len(effective) == 0 {
		effective = granted
	}

	registry := n.ResourceRegistry()

	for _, resource := range effective {
		if !registry.MayRequest(client, resource) {
			return nil, ErrInvalidTarget
		}
	}

	return narrowed, nil
}

// withAccessTokenResources returns the session an access token is issued from. A narrowed resource set
// applies to a shallow copy so the persisted grant keeps every granted resource.
func (s *OIDCSession) withAccessTokenResources(resources []string) *OIDCSession {
	if len(resources) == 0 {
		return s
	}

	narrowed := *s
	narrowed.AccessTokenResources = slices.Clone(resources)

	return &narrowed
}

// AccessTokenIssuingClient returns the client a user access token was issued to: the issuer-owned azp
// claim, or for tokens issued before azp existed a single audience. A malformed azp never falls back.
func AccessTokenIssuingClient(claims jwt.MapClaims) (string, bool) {
	if claims == nil {
		return "", false
	}

	if raw, present := claims[definitions.ClaimAuthorizedParty]; present {
		azp, ok := raw.(string)

		return azp, ok && azp != ""
	}

	audiences, err := claims.GetAudience()
	if err != nil || len(audiences) != 1 || audiences[0] == "" {
		return "", false
	}

	return audiences[0], true
}

// AccessTokenResourceAudiences returns the audiences of a user access token other than its issuing client.
// A missing or malformed audience is reported as not ok.
func AccessTokenResourceAudiences(claims jwt.MapClaims, issuingClient string) ([]string, bool) {
	audiences, err := claims.GetAudience()
	if err != nil || len(audiences) == 0 {
		return nil, false
	}

	return slices.DeleteFunc(slices.Clone(audiences), func(audience string) bool {
		return audience == issuingClient
	}), true
}

// accessTokenMayBelongToDynamicClient reports whether claims without a resolvable issuing client could
// still belong to a dynamic client, so that dynamic-client checks fail closed.
func accessTokenMayBelongToDynamicClient(claims jwt.MapClaims) bool {
	if _, present := claims[definitions.ClaimAuthorizedParty]; present {
		return true
	}

	audiences, err := claims.GetAudience()
	if err != nil {
		return true
	}

	return slices.ContainsFunc(audiences, func(audience string) bool {
		return strings.HasPrefix(audience, dcr.ClientIDPrefix)
	})
}
