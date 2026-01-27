// Copyright (C) 2025 Christian Rößner
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
	"fmt"
	"os"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
)

// IdPSection represents the configuration for the internal Identity Provider.
type IdPSection struct {
	OIDC              OIDCConfig  `mapstructure:"oidc"`
	SAML2             SAML2Config `mapstructure:"saml2"`
	WebAuthn          WebAuthn    `mapstructure:"webauthn"`
	TermsOfServiceURL string      `mapstructure:"terms_of_service_url"`
	PrivacyPolicyURL  string      `mapstructure:"privacy_policy_url"`
}

func (i *IdPSection) String() string {
	if i == nil {
		return "IdPSection: <nil>"
	}

	return fmt.Sprintf("IdPSection: {OIDC:%s SAML2:%s WebAuthn:%s TermsOfServiceURL:%s PrivacyPolicyURL:%s}", i.OIDC.String(), i.SAML2.String(), i.WebAuthn.String(), i.TermsOfServiceURL, i.PrivacyPolicyURL)
}

// WebAuthn represents the configuration for WebAuthn.
type WebAuthn struct {
	RPDisplayName string   `mapstructure:"rp_display_name"`
	RPID          string   `mapstructure:"rp_id"`
	RPOrigins     []string `mapstructure:"rp_origins"`
}

func (w *WebAuthn) String() string {
	if w == nil {
		return "WebAuthn: <nil>"
	}

	return fmt.Sprintf("WebAuthn: {RPDisplayName:%s RPID:%s RPOrigins:%v}", w.RPDisplayName, w.RPID, w.RPOrigins)
}

// OIDCConfig represents the configuration for OpenID Connect.
type OIDCConfig struct {
	Enabled        bool                `mapstructure:"enabled"`
	Issuer         string              `mapstructure:"issuer" validate:"required_if=Enabled true"`
	SigningKey     string              `mapstructure:"signing_key" validate:"required_if=Enabled true SigningKeyFile ''"`
	SigningKeyFile string              `mapstructure:"signing_key_file" validate:"required_if=Enabled true SigningKey ''"`
	Clients        []OIDCClient        `mapstructure:"clients"`
	CustomScopes   []Oauth2CustomScope `mapstructure:"custom_scopes" validate:"omitempty,dive"`
}

func (o *OIDCConfig) String() string {
	if o == nil {
		return "OIDCConfig: <nil>"
	}

	return fmt.Sprintf("OIDCConfig: {Enabled:%t Issuer:%s Clients:%+v}", o.Enabled, o.Issuer, o.Clients)
}

// GetSigningKey returns the signing key content.
func (o *OIDCConfig) GetSigningKey() (string, error) {
	return getContent(o.SigningKey, o.SigningKeyFile)
}

// OIDCClient represents an OIDC client configuration.
type OIDCClient struct {
	ClientID                          string        `mapstructure:"client_id" validate:"required"`
	ClientSecret                      string        `mapstructure:"client_secret" validate:"required"`
	RedirectURIs                      []string      `mapstructure:"redirect_uris" validate:"required,gt=0"`
	Scopes                            []string      `mapstructure:"scopes"`
	SkipConsent                       bool          `mapstructure:"skip_consent"`
	DelayedResponse                   bool          `mapstructure:"delayed_response"`
	RememberMeTTL                     time.Duration `mapstructure:"remember_me_ttl"`
	AccessTokenLifetime               time.Duration `mapstructure:"access_token_lifetime"`
	RefreshTokenLifetime              time.Duration `mapstructure:"refresh_token_lifetime"`
	TokenEndpointAuthMethod           string        `mapstructure:"token_endpoint_auth_method"`
	Claims                            IdTokenClaims `mapstructure:"claims"`
	PostLogoutRedirectURIs            []string      `mapstructure:"post_logout_redirect_uris"`
	BackChannelLogoutURI              string        `mapstructure:"backchannel_logout_uri"`
	FrontChannelLogoutURI             string        `mapstructure:"frontchannel_logout_uri"`
	FrontChannelLogoutSessionRequired bool          `mapstructure:"frontchannel_logout_session_required"`
	LogoutRedirectURI                 string        `mapstructure:"logout_redirect_uri"`
}

// GetAllowedScopes returns the allowed scopes for this client. If no scopes are configured, a default set of scopes is returned.
func (c *OIDCClient) GetAllowedScopes() []string {
	if c == nil {
		return nil
	}

	if len(c.Scopes) == 0 {
		return []string{
			definitions.ScopeOpenId,
			definitions.ScopeProfile,
			definitions.ScopeEmail,
			definitions.ScopeGroups,
			definitions.ScopeOfflineAccess,
		}
	}

	return c.Scopes
}

// IsDelayedResponse returns true if delayed response is enabled for this client.
func (c *OIDCClient) IsDelayedResponse() bool {
	if c == nil {
		return false
	}

	return c.DelayedResponse
}

// SAML2Config represents the configuration for SAML 2.0.
type SAML2Config struct {
	Enabled          bool                   `mapstructure:"enabled"`
	EntityID         string                 `mapstructure:"entity_id" validate:"required_if=Enabled true"`
	Cert             string                 `mapstructure:"cert" validate:"required_if=Enabled true CertFile ''"`
	CertFile         string                 `mapstructure:"cert_file" validate:"required_if=Enabled true Cert ''"`
	Key              string                 `mapstructure:"key" validate:"required_if=Enabled true KeyFile ''"`
	KeyFile          string                 `mapstructure:"key_file" validate:"required_if=Enabled true Key ''"`
	ServiceProviders []SAML2ServiceProvider `mapstructure:"service_providers"`
}

func (s *SAML2Config) String() string {
	if s == nil {
		return "SAML2Config: <nil>"
	}

	return fmt.Sprintf("SAML2Config: {Enabled:%t EntityID:%s ServiceProviders:%+v}", s.Enabled, s.EntityID, s.ServiceProviders)
}

// GetCert returns the certificate content.
func (s *SAML2Config) GetCert() (string, error) {
	return getContent(s.Cert, s.CertFile)
}

// GetKey returns the key content.
func (s *SAML2Config) GetKey() (string, error) {
	return getContent(s.Key, s.KeyFile)
}

func getContent(raw, path string) (string, error) {
	if raw != "" {
		return raw, nil
	}

	if path != "" {
		content, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}

		return string(content), nil
	}

	return "", nil
}

// SAML2ServiceProvider represents a SAML 2.0 service provider configuration.
type SAML2ServiceProvider struct {
	EntityID          string        `mapstructure:"entity_id" validate:"required"`
	ACSURL            string        `mapstructure:"acs_url" validate:"required"`
	SLOURL            string        `mapstructure:"slo_url"`
	DelayedResponse   bool          `mapstructure:"delayed_response"`
	RememberMeTTL     time.Duration `mapstructure:"remember_me_ttl"`
	LogoutRedirectURI string        `mapstructure:"logout_redirect_uri"`
}

// IsDelayedResponse returns true if delayed response is enabled for this service provider.
func (s *SAML2ServiceProvider) IsDelayedResponse() bool {
	if s == nil {
		return false
	}

	return s.DelayedResponse
}

// GetIdP retrieves the IdPSection from the FileSettings instance. Returns nil if the FileSettings is nil.
func (f *FileSettings) GetIdP() *IdPSection {
	if f == nil {
		return &IdPSection{}
	}

	if f.IdP == nil {
		return &IdPSection{}
	}

	return f.IdP
}
