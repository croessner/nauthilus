package config

import "fmt"

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
