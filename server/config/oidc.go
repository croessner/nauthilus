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
	CustomScopes []Oauth2CustomScope `mapstructure:"custom_scopes"`
	Clients      []Oauth2Client
}

func (o *Oauth2Section) String() string {
	return fmt.Sprintf("OAuth2Section: {Oauth2Client[%+v]}", o.Clients)
}

type Oauth2Client struct {
	SkipConsent bool   `mapstructure:"skip_consent"`
	SkipTOTP    bool   `mapstructure:"skip_totp"`
	ClientName  string `mapstructure:"name"`
	ClientId    string `mapstructure:"client_id"`
	Subject     string
	Claims      IdTokenClaims `mapstructure:"claims"`
}

type Oauth2CustomScope struct {
	Name        string
	Description string
	Claims      []OIDCCustomClaim
	Other       map[string]any `mapstructure:",remain"`
}

type OIDCCustomClaim struct {
	Name string
	Type string
}

type IdTokenClaims struct {
	// Scope: profile.
	Name              string
	GivenName         string `mapstructure:"given_name"`
	FamilyName        string `mapstructure:"family_name"`
	MiddleName        string `mapstructure:"middle_name"`
	NickName          string
	PreferredUserName string `mapstructure:"preferred_username"`
	Profile           string
	Website           string
	Picture           string
	Gender            string
	Birthdate         string
	ZoneInfo          string
	Locale            string
	UpdatedAt         string `mapstructure:"updated_at"`

	// Scope: email.
	Email         string
	EmailVerified string `mapstructure:"email_verified"`

	// Scope: phone.
	PhoneNumber         string `mapstructure:"phone_number"`
	PhoneNumberVerified string `mapstructure:"phone_number_verified"`

	// Scope: address.
	Address string

	// Scope: groups.
	Groups string

	// Scope: user defined.
	CustomClaims map[string]any `mapstructure:",remain"`
}

func (i *IdTokenClaims) String() string {
	return fmt.Sprintf("{IdTokenClaims: %+v}", *i)
}
