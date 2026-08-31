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

package dcr

import (
	"slices"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
)

// RuntimePolicy revalidates stored registrations against current operator policy.
type RuntimePolicy struct {
	registration config.OIDCDynamicClientRegistrationConfig
}

// NewRuntimePolicy creates a current-policy dynamic-client resolver.
func NewRuntimePolicy(registration config.OIDCDynamicClientRegistrationConfig) RuntimePolicy {
	return RuntimePolicy{registration: registration}
}

// Resolve rejects retired records and only materializes privileges still allowed today.
func (p RuntimePolicy) Resolve(record *DynamicClientRecord) (*config.OIDCClient, error) { //nolint:gocyclo
	if record == nil || record.Profile != ProfileMailClientV1 || record.ProfileVersion != p.registration.GetProfileVersion() {
		return nil, ErrCorrupt
	}

	if !p.registration.Enabled || !validStoredMetadata(record) {
		return nil, ErrNotFound
	}

	allowedScopes := append(append([]string(nil), p.registration.RequiredScopes...), p.registration.OptionalScopes...)
	currentScopes := slices.DeleteFunc(splitScope(record.Scope), func(scope string) bool {
		return !slices.Contains(allowedScopes, scope)
	})

	for _, requiredScope := range p.registration.RequiredScopes {
		if !slices.Contains(currentScopes, requiredScope) {
			return nil, ErrNotFound
		}
	}

	grantTypes := append([]string(nil), record.GrantTypes...)
	if !p.registration.AllowRefreshTokens {
		grantTypes = slices.DeleteFunc(grantTypes, func(grantType string) bool { return grantType == GrantRefreshToken })
		currentScopes = slices.DeleteFunc(currentScopes, func(scope string) bool { return scope == definitions.ScopeOfflineAccess })
	}

	hasRefresh := slices.Contains(grantTypes, GrantRefreshToken)
	hasOfflineAccess := slices.Contains(currentScopes, definitions.ScopeOfflineAccess)

	if hasRefresh != hasOfflineAccess {
		return nil, ErrNotFound
	}

	client := record.OIDCClient()
	client.Scopes = currentScopes
	client.OptionalScopes = append([]string(nil), currentScopes...)
	client.GrantTypes = grantTypes
	client.RequiredMFALevel = max(record.RequiredMFALevel, p.registration.RequiredMFALevel)
	client.AccessTokenLifetime = minimumPositiveDuration(record.AccessTokenTTL, p.registration.GetAccessTokenLifetime())
	client.RefreshTokenLifetime = minimumPositiveDuration(record.RefreshTokenTTL, p.registration.GetRefreshTokenLifetime())

	return client, nil
}

// validStoredMetadata verifies immutable effective-profile invariants.
func validStoredMetadata(record *DynamicClientRecord) bool {
	if !strings.HasPrefix(record.ClientID, ClientIDPrefix) || !slices.Equal(record.ResponseTypes, []string{ResponseTypeCode}) ||
		!validSet(record.GrantTypes, []string{GrantAuthorizationCode, GrantRefreshToken}) ||
		!slices.Contains(record.GrantTypes, GrantAuthorizationCode) || !uniqueStrings(splitScope(record.Scope)) ||
		record.TokenEndpointAuthMethod != TokenEndpointAuthMethodNone || record.ApplicationType != ApplicationTypeNative ||
		record.SubjectType != SubjectTypePublic || record.IDTokenSignedResponseAlg != IDTokenSigningAlgorithm {
		return false
	}

	_, redirectErr := validateRedirectURIs(record.RedirectURIs, len(record.RedirectURIs), 8_192)

	return redirectErr == nil
}

// minimumPositiveDuration returns the narrower positive duration.
func minimumPositiveDuration(stored time.Duration, current time.Duration) time.Duration {
	if stored <= 0 || current < stored {
		return current
	}

	return stored
}
