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

type Oauth2Section struct {
	CustomScopes []Oauth2CustomScope `mapstructure:"custom_scopes" validate:"omitempty,dive"`
	Clients      []Oauth2Client      `mapstructure:"clients" validate:"omitempty,dive"`
}

func (o *Oauth2Section) String() string {
	if o == nil {
		return "OAuth2Section: <nil>"
	}

	return fmt.Sprintf("OAuth2Section: {Oauth2Client[%+v]}", o.Clients)
}

type Oauth2Client struct {
	SkipConsent bool          `mapstructure:"skip_consent"`
	SkipTOTP    bool          `mapstructure:"skip_totp"`
	ClientName  string        `mapstructure:"name" validate:"required"`
	ClientId    string        `mapstructure:"client_id" validate:"required"`
	Subject     string        `mapstructure:"subject" validate:"required,alphanumunicode,excludesall= "`
	Claims      IdTokenClaims `mapstructure:"claims" validate:"required"`
}

type Oauth2CustomScope struct {
	Name        string            `mapstructure:"name" validate:"required,alphanumunicode,excludesall= "`
	Description string            `mapstructure:"description" validate:"required"`
	Claims      []OIDCCustomClaim `mapstructure:"claims" validate:"required,dive"`
	Other       map[string]any    `mapstructure:",remain"`
}

type OIDCCustomClaim struct {
	Name string
	Type string
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
