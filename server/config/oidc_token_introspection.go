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
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/croessner/nauthilus/v4/server/definitions"
)

const (
	oidcReservedResourceScheme = "nauthilus"
	oidcTokenIntrospectionPath = "identity.oidc.clients[%d].token_introspection"
)

var (
	errOIDCResourceEmpty      = errors.New("must not be empty")
	errOIDCResourceWhitespace = errors.New("must not contain whitespace")
	errOIDCResourceNotAbsURI  = errors.New("must be an absolute URI")
	errOIDCResourceFragment   = errors.New("must not contain a fragment")
)

// OIDCTokenIntrospection lets a confidential static client act as a protected resource that
// introspects user access tokens issued to other clients.
//
// Resources lists the RFC 8707 resource indicators this client owns. Clients and
// DynamicClientProfiles name the issuing clients whose plain user tokens the owner may introspect;
// the same allowlist decides which clients may request the owner's resources.
type OIDCTokenIntrospection struct {
	Resources             []string `mapstructure:"resources"`
	Clients               []string `mapstructure:"clients"`
	DynamicClientProfiles []string `mapstructure:"dynamic_client_profiles"`
}

// IsConfigured reports whether any token introspection authority is configured.
func (t OIDCTokenIntrospection) IsConfigured() bool {
	return len(t.Resources) > 0 || len(t.Clients) > 0 || len(t.DynamicClientProfiles) > 0
}

// AllowsIssuingClient reports whether user tokens of the issuing client fall under this allowlist.
// Dynamic clients match by their registration profile, static clients by their client id.
func (t OIDCTokenIntrospection) AllowsIssuingClient(issuing *OIDCClient) bool {
	if issuing == nil {
		return false
	}

	if issuing.Dynamic {
		return issuing.DynamicProfile != "" && slices.Contains(t.DynamicClientProfiles, issuing.DynamicProfile)
	}

	return issuing.ClientID != "" && slices.Contains(t.Clients, issuing.ClientID)
}

// AllowsTokenIntrospection reports whether a static confidential client holds token introspection authority.
func (c *OIDCClient) AllowsTokenIntrospection() bool {
	return c != nil && c.TokenIntrospection.IsConfigured() && c.hasConfidentialStaticAuth()
}

// ValidateOIDCResourceIndicator checks the RFC 8707 syntax of one resource indicator: an absolute URI
// without fragment. Whitespace is rejected so resource lists can be stored space-separated.
func ValidateOIDCResourceIndicator(resource string) error {
	if resource == "" {
		return errOIDCResourceEmpty
	}

	if strings.ContainsFunc(resource, unicode.IsSpace) {
		return errOIDCResourceWhitespace
	}

	if strings.Contains(resource, "#") {
		return errOIDCResourceFragment
	}

	parsed, err := url.Parse(resource)
	if err != nil || parsed.Scheme == "" || !parsed.IsAbs() {
		return errOIDCResourceNotAbsURI
	}

	return nil
}

// isReservedOIDCResource reports whether a resource collides with an audience Nauthilus owns itself.
func isReservedOIDCResource(resource string) bool {
	if resource == definitions.AudienceBackchannelAPI || resource == definitions.AudiencePolicyAPI {
		return true
	}

	parsed, err := url.Parse(resource)

	return err == nil && strings.EqualFold(parsed.Scheme, oidcReservedResourceScheme)
}

// oidcTokenIntrospectionValidator validates token_introspection blocks against the whole client set.
type oidcTokenIntrospectionValidator struct {
	clientIDs      map[string]struct{} `mapstructure:"-"`
	resourceOwners map[string]int      `mapstructure:"-"`
	dynamicProfile string              `mapstructure:"-"`
	dynamicEnabled bool                `mapstructure:"-"`
}

// newOIDCTokenIntrospectionValidator captures the client ids and the dynamic registration profile.
func newOIDCTokenIntrospectionValidator(oidc *OIDCConfig) *oidcTokenIntrospectionValidator {
	validator := &oidcTokenIntrospectionValidator{
		clientIDs:      make(map[string]struct{}, len(oidc.Clients)),
		resourceOwners: make(map[string]int),
		dynamicProfile: oidc.DynamicClientRegistration.GetProfile(),
		dynamicEnabled: oidc.DynamicClientRegistration.Enabled,
	}

	for idx := range oidc.Clients {
		validator.clientIDs[oidc.Clients[idx].ClientID] = struct{}{}
	}

	return validator
}

// validateIDPOIDCTokenIntrospectionSettings validates delegated user-token introspection and resource ownership.
func (f *FileSettings) validateIDPOIDCTokenIntrospectionSettings() error {
	if f == nil || f.IDP == nil {
		return nil
	}

	oidc := &f.IDP.OIDC
	validator := newOIDCTokenIntrospectionValidator(oidc)

	for idx := range oidc.Clients {
		if err := validator.validateClient(idx, &oidc.Clients[idx]); err != nil {
			return err
		}
	}

	return nil
}

// validateClient validates one client's token_introspection block.
func (v *oidcTokenIntrospectionValidator) validateClient(idx int, client *OIDCClient) error {
	settings := client.TokenIntrospection
	if !settings.IsConfigured() {
		return nil
	}

	path := fmt.Sprintf(oidcTokenIntrospectionPath, idx)

	if !client.hasConfidentialStaticAuth() {
		return NewValidationProblem(path, "token introspection requires a static client with confidential client authentication")
	}

	if len(settings.Resources) > 0 && len(settings.Clients) == 0 && len(settings.DynamicClientProfiles) == 0 {
		return NewValidationProblem(path, "resources require at least one entry in clients or dynamic_client_profiles")
	}

	if err := v.validateResources(idx, path+".resources", settings.Resources); err != nil {
		return err
	}

	if err := v.validateClients(path+".clients", client.ClientID, settings.Clients); err != nil {
		return err
	}

	return v.validateProfiles(path+".dynamic_client_profiles", settings.DynamicClientProfiles)
}

// validateResources enforces resource syntax, reserved audiences, and a single owner per resource.
func (v *oidcTokenIntrospectionValidator) validateResources(idx int, path string, resources []string) error {
	for position, resource := range resources {
		elementPath := fmt.Sprintf("%s[%d]", path, position)

		if err := ValidateOIDCResourceIndicator(resource); err != nil {
			return NewValidationProblem(elementPath, err.Error())
		}

		if isReservedOIDCResource(resource) {
			return NewValidationProblem(elementPath, "must not use a reserved nauthilus audience")
		}

		if _, collides := v.clientIDs[resource]; collides {
			return NewValidationProblem(elementPath, "must not equal a configured client_id")
		}

		if owner, taken := v.resourceOwners[resource]; taken {
			return NewValidationProblem(elementPath, fmt.Sprintf("is already registered by identity.oidc.clients[%d]", owner))
		}

		v.resourceOwners[resource] = idx
	}

	return nil
}

// validateClients requires every allowlisted issuer to be another configured static client.
func (v *oidcTokenIntrospectionValidator) validateClients(path string, ownClientID string, clients []string) error {
	for position, clientID := range clients {
		elementPath := fmt.Sprintf("%s[%d]", path, position)

		if clientID == ownClientID {
			return NewValidationProblem(elementPath, "must not name the client itself")
		}

		if _, known := v.clientIDs[clientID]; !known {
			return NewValidationProblem(elementPath, "must name a configured static client_id")
		}
	}

	return nil
}

// validateProfiles requires every allowlisted profile to be the enabled dynamic registration profile.
func (v *oidcTokenIntrospectionValidator) validateProfiles(path string, profiles []string) error {
	if len(profiles) > 0 && !v.dynamicEnabled {
		return NewValidationProblem(path, "requires identity.oidc.dynamic_client_registration.enabled")
	}

	for position, profile := range profiles {
		if profile != v.dynamicProfile {
			return NewValidationProblem(fmt.Sprintf("%s[%d]", path, position), "must name the configured dynamic client registration profile")
		}
	}

	return nil
}
