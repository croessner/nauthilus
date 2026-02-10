// Copyright (C) 2024 Christian Rößner
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

import "fmt"

type Oauth2CustomScope struct {
	Name        string            `mapstructure:"name" validate:"required,scope_token"`
	Description string            `mapstructure:"description" validate:"required"`
	Claims      []OIDCCustomClaim `mapstructure:"claims" validate:"required,dive"`
	Other       map[string]any    `mapstructure:",remain"`
}

// GetName retrieves the name of the custom scope.
// Returns an empty string if the Oauth2CustomScope is nil.
func (s *Oauth2CustomScope) GetName() string {
	if s == nil {
		return ""
	}

	return s.Name
}

// GetDescription retrieves the description of the custom scope.
// Returns an empty string if the Oauth2CustomScope is nil.
func (s *Oauth2CustomScope) GetDescription() string {
	if s == nil {
		return ""
	}

	return s.Description
}

// GetClaims retrieves the list of custom claims for this scope.
// Returns an empty slice if the Oauth2CustomScope is nil.
func (s *Oauth2CustomScope) GetClaims() []OIDCCustomClaim {
	if s == nil {
		return []OIDCCustomClaim{}
	}

	return s.Claims
}

// GetOther retrieves the map of additional properties for this scope.
// Returns nil if the Oauth2CustomScope is nil.
func (s *Oauth2CustomScope) GetOther() map[string]any {
	if s == nil {
		return nil
	}

	return s.Other
}

type OIDCCustomClaim struct {
	Name string `mapstructure:"name" validate:"required,oidc_claim_name"`
	Type string `mapstructure:"type" validate:"required,oidc_claim_type"`
}

type OIDCClaimMapping struct {
	Claim     string `mapstructure:"claim" validate:"required,oidc_claim_name"`
	Attribute string `mapstructure:"attribute" validate:"required,printascii,excludesall= "`
	Type      string `mapstructure:"type" validate:"omitempty,oidc_claim_type"`
}

// GetName retrieves the name of the custom claim.
// Returns an empty string if the OIDCCustomClaim is nil.
func (c *OIDCCustomClaim) GetName() string {
	if c == nil {
		return ""
	}

	return c.Name
}

// GetType retrieves the type of the custom claim.
// Returns an empty string if the OIDCCustomClaim is nil.
func (c *OIDCCustomClaim) GetType() string {
	if c == nil {
		return ""
	}

	return c.Type
}

type IdTokenClaims struct {
	Mappings []OIDCClaimMapping `mapstructure:"mappings" validate:"omitempty,dive"`
}

func (i *IdTokenClaims) String() string {
	if i == nil {
		return "<nil>"
	}

	return fmt.Sprintf("{IdTokenClaims: %+v}", *i)
}

// GetMappings retrieves the claim mappings from the IdTokenClaims.
// Returns nil if the IdTokenClaims is nil.
func (i *IdTokenClaims) GetMappings() []OIDCClaimMapping {
	if i == nil {
		return nil
	}

	return i.Mappings
}

// AccessTokenClaims defines claim mappings for access tokens.
type AccessTokenClaims struct {
	Mappings []OIDCClaimMapping `mapstructure:"mappings" validate:"omitempty,dive"`
}

func (a *AccessTokenClaims) String() string {
	if a == nil {
		return "<nil>"
	}

	return fmt.Sprintf("{AccessTokenClaims: %+v}", *a)
}

// GetMappings retrieves the claim mappings from the AccessTokenClaims.
// Returns nil if the AccessTokenClaims is nil.
func (a *AccessTokenClaims) GetMappings() []OIDCClaimMapping {
	if a == nil {
		return nil
	}

	return a.Mappings
}
