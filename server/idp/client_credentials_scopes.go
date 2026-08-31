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
	"strings"

	"github.com/croessner/nauthilus/v4/server/definitions"
)

// ErrClientCredentialsOpenIDScope reports an identity scope on a service-token grant.
var ErrClientCredentialsOpenIDScope = errors.New("openid scope is not allowed for client_credentials")

// ErrClientCredentialsMixedResourceScopes reports a grant spanning protected resources.
var ErrClientCredentialsMixedResourceScopes = errors.New("policy and backchannel scopes require separate client_credentials tokens")

// ErrClientCredentialsResourceScopeMismatch reports a filtered grant that changed protected resources.
var ErrClientCredentialsResourceScopeMismatch = errors.New("requested client_credentials resource scope family is not authorized")

type clientCredentialsResource uint8

const (
	clientCredentialsResourceUnknown clientCredentialsResource = iota
	clientCredentialsResourceBackchannel
	clientCredentialsResourcePolicy
)

// audience returns the exact protected-resource audience for the classification.
func (r clientCredentialsResource) audience() string {
	switch r {
	case clientCredentialsResourceBackchannel:
		return definitions.AudienceBackchannelAPI
	case clientCredentialsResourcePolicy:
		return definitions.AudiencePolicyAPI
	default:
		return ""
	}
}

// ValidateClientCredentialsScopes validates identity and resource-family separation.
func ValidateClientCredentialsScopes(scopes []string) error {
	_, err := classifyClientCredentialsScopes(scopes)

	return err
}

// ValidateClientCredentialsScopeTransition rejects filtering that changes an explicitly requested resource family.
func ValidateClientCredentialsScopeTransition(requestedScopes []string, effectiveScopes []string) error {
	requestedResource, err := classifyClientCredentialsScopes(requestedScopes)
	if err != nil {
		return err
	}

	effectiveResource, err := classifyClientCredentialsScopes(effectiveScopes)
	if err != nil {
		return err
	}

	if hasClientCredentialsScope(requestedScopes) && requestedResource != effectiveResource {
		return ErrClientCredentialsResourceScopeMismatch
	}

	return nil
}

// hasClientCredentialsScope reports whether a caller explicitly requested any non-empty scope.
func hasClientCredentialsScope(scopes []string) bool {
	for _, scope := range scopes {
		if strings.TrimSpace(scope) != "" {
			return true
		}
	}

	return false
}

// classifyClientCredentialsScopes selects one exact protected resource for a grant.
func classifyClientCredentialsScopes(scopes []string) (clientCredentialsResource, error) {
	var (
		hasBackchannelScope bool
		hasPolicyScope      bool
	)

	for _, rawScope := range scopes {
		scope := strings.TrimSpace(rawScope)

		switch scope {
		case "":
			continue
		case definitions.ScopeOpenID:
			return clientCredentialsResourceUnknown, ErrClientCredentialsOpenIDScope
		case definitions.ScopePolicyEvaluate, definitions.ScopePolicyDiagnostics:
			hasPolicyScope = true
		default:
			hasBackchannelScope = true
		}

		if hasPolicyScope && hasBackchannelScope {
			return clientCredentialsResourceUnknown, ErrClientCredentialsMixedResourceScopes
		}
	}

	if hasPolicyScope {
		return clientCredentialsResourcePolicy, nil
	}

	return clientCredentialsResourceBackchannel, nil
}
