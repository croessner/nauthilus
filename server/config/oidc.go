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
