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
	Name        string            `mapstructure:"name" validate:"required,alphanumunicode,excludesall= "`
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
	Name string
	Type string
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
	// Scope: profile.
	Name              string `mapstructure:"name" validate:"omitempty,printascii,excludesall= "`
	GivenName         string `mapstructure:"given_name" validate:"omitempty,printascii,excludesall= "`
	FamilyName        string `mapstructure:"family_name" validate:"omitempty,printascii,excludesall= "`
	MiddleName        string `mapstructure:"middle_name" validate:"omitempty,printascii,excludesall= "`
	NickName          string `mapstructure:"nickname" validate:"omitempty,printascii,excludesall= "`
	PreferredUserName string `mapstructure:"preferred_username" validate:"omitempty,printascii,excludesall= "`
	Profile           string `mapstructure:"profile" validate:"omitempty,printascii,excludesall= "`
	Website           string `mapstructure:"website" validate:"omitempty,printascii,excludesall= "`
	Picture           string `mapstructure:"picture" validate:"omitempty,printascii,excludesall= "`
	Gender            string `mapstructure:"gender" validate:"omitempty,printascii,excludesall= "`
	Birthdate         string `mapstructure:"birthdate" validate:"omitempty,printascii,excludesall= "`
	ZoneInfo          string `mapstructure:"zoneinfo" validate:"omitempty,printascii,excludesall= "`
	Locale            string `mapstructure:"locale" validate:"omitempty,printascii,excludesall= "`
	UpdatedAt         string `mapstructure:"updated_at" validate:"omitempty,printascii,excludesall= "`

	// Scope: email.
	Email         string `mapstructure:"email" validate:"omitempty,printascii,excludesall= "`
	EmailVerified string `mapstructure:"email_verified" validate:"omitempty,printascii,excludesall= "`

	// Scope: phone.
	PhoneNumber         string `mapstructure:"phone_number" validate:"omitempty,printascii,excludesall= "`
	PhoneNumberVerified string `mapstructure:"phone_number_verified" validate:"omitempty,printascii,excludesall= "`

	// Scope: address.
	Address string `mapstructure:"address" validate:"omitempty,printascii,excludesall= "`

	// Scope: groups.
	Groups string `mapstructure:"groups" validate:"omitempty,printascii,excludesall= "`

	// Scope: user defined.
	CustomClaims map[string]any `mapstructure:",remain"`
}

func (i *IdTokenClaims) String() string {
	if i == nil {
		return "<nil>"
	}

	return fmt.Sprintf("{IdTokenClaims: %+v}", *i)
}

// Profile scope getters

// GetName retrieves the name claim from the IdTokenClaims.
// Returns an empty string if the IdTokenClaims is nil.
func (i *IdTokenClaims) GetName() string {
	if i == nil {
		return ""
	}

	return i.Name
}

// GetGivenName retrieves the given name claim from the IdTokenClaims.
// Returns an empty string if the IdTokenClaims is nil.
func (i *IdTokenClaims) GetGivenName() string {
	if i == nil {
		return ""
	}

	return i.GivenName
}

// GetFamilyName retrieves the family name claim from the IdTokenClaims.
// Returns an empty string if the IdTokenClaims is nil.
func (i *IdTokenClaims) GetFamilyName() string {
	if i == nil {
		return ""
	}

	return i.FamilyName
}

// GetMiddleName retrieves the middle name claim from the IdTokenClaims.
// Returns an empty string if the IdTokenClaims is nil.
func (i *IdTokenClaims) GetMiddleName() string {
	if i == nil {
		return ""
	}

	return i.MiddleName
}

// GetNickName retrieves the nickname claim from the IdTokenClaims.
// Returns an empty string if the IdTokenClaims is nil.
func (i *IdTokenClaims) GetNickName() string {
	if i == nil {
		return ""
	}

	return i.NickName
}

// GetPreferredUserName retrieves the preferred username claim from the IdTokenClaims.
// Returns an empty string if the IdTokenClaims is nil.
func (i *IdTokenClaims) GetPreferredUserName() string {
	if i == nil {
		return ""
	}

	return i.PreferredUserName
}

// GetProfile retrieves the profile claim from the IdTokenClaims.
// Returns an empty string if the IdTokenClaims is nil.
func (i *IdTokenClaims) GetProfile() string {
	if i == nil {
		return ""
	}

	return i.Profile
}

// GetWebsite retrieves the website claim from the IdTokenClaims.
// Returns an empty string if the IdTokenClaims is nil.
func (i *IdTokenClaims) GetWebsite() string {
	if i == nil {
		return ""
	}

	return i.Website
}

// GetPicture retrieves the picture claim from the IdTokenClaims.
// Returns an empty string if the IdTokenClaims is nil.
func (i *IdTokenClaims) GetPicture() string {
	if i == nil {
		return ""
	}

	return i.Picture
}

// GetGender retrieves the gender claim from the IdTokenClaims.
// Returns an empty string if the IdTokenClaims is nil.
func (i *IdTokenClaims) GetGender() string {
	if i == nil {
		return ""
	}

	return i.Gender
}

// GetBirthdate retrieves the birthdate claim from the IdTokenClaims.
// Returns an empty string if the IdTokenClaims is nil.
func (i *IdTokenClaims) GetBirthdate() string {
	if i == nil {
		return ""
	}

	return i.Birthdate
}

// GetZoneInfo retrieves the zoneinfo claim from the IdTokenClaims.
// Returns an empty string if the IdTokenClaims is nil.
func (i *IdTokenClaims) GetZoneInfo() string {
	if i == nil {
		return ""
	}

	return i.ZoneInfo
}

// GetLocale retrieves the locale claim from the IdTokenClaims.
// Returns an empty string if the IdTokenClaims is nil.
func (i *IdTokenClaims) GetLocale() string {
	if i == nil {
		return ""
	}

	return i.Locale
}

// GetUpdatedAt retrieves the updated_at claim from the IdTokenClaims.
// Returns an empty string if the IdTokenClaims is nil.
func (i *IdTokenClaims) GetUpdatedAt() string {
	if i == nil {
		return ""
	}

	return i.UpdatedAt
}

// Email scope getters

// GetEmail retrieves the email claim from the IdTokenClaims.
// Returns an empty string if the IdTokenClaims is nil.
func (i *IdTokenClaims) GetEmail() string {
	if i == nil {
		return ""
	}

	return i.Email
}

// GetEmailVerified retrieves the email_verified claim from the IdTokenClaims.
// Returns an empty string if the IdTokenClaims is nil.
func (i *IdTokenClaims) GetEmailVerified() string {
	if i == nil {
		return ""
	}

	return i.EmailVerified
}

// Phone scope getters

// GetPhoneNumber retrieves the phone_number claim from the IdTokenClaims.
// Returns an empty string if the IdTokenClaims is nil.
func (i *IdTokenClaims) GetPhoneNumber() string {
	if i == nil {
		return ""
	}

	return i.PhoneNumber
}

// GetPhoneNumberVerified retrieves the phone_number_verified claim from the IdTokenClaims.
// Returns an empty string if the IdTokenClaims is nil.
func (i *IdTokenClaims) GetPhoneNumberVerified() string {
	if i == nil {
		return ""
	}

	return i.PhoneNumberVerified
}

// Address scope getter

// GetAddress retrieves the address claim from the IdTokenClaims.
// Returns an empty string if the IdTokenClaims is nil.
func (i *IdTokenClaims) GetAddress() string {
	if i == nil {
		return ""
	}

	return i.Address
}

// Groups scope getter

// GetGroups retrieves the groups claim from the IdTokenClaims.
// Returns an empty string if the IdTokenClaims is nil.
func (i *IdTokenClaims) GetGroups() string {
	if i == nil {
		return ""
	}

	return i.Groups
}

// Custom claims getter

// GetCustomClaims retrieves the custom claims from the IdTokenClaims.
// Returns nil if the IdTokenClaims is nil.
func (i *IdTokenClaims) GetCustomClaims() map[string]any {
	if i == nil {
		return nil
	}

	return i.CustomClaims
}
