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
	"strings"
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

// warnUnsupported returns a list of warnings for unsupported Identity Provider configuration parameters.
func (i *IdPSection) warnUnsupported() []string {
	if i == nil {
		return nil
	}

	var warnings []string
	warnings = append(warnings, i.OIDC.warnUnsupported()...)
	warnings = append(warnings, i.SAML2.warnUnsupported()...)

	return warnings
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
	Enabled                            bool                `mapstructure:"enabled"`
	Issuer                             string              `mapstructure:"issuer" validate:"required_if=Enabled true"`
	SigningKeys                        []OIDCKey           `mapstructure:"signing_keys"`
	AutoKeyRotation                    bool                `mapstructure:"auto_key_rotation"`
	KeyRotationInterval                time.Duration       `mapstructure:"key_rotation_interval"`
	KeyMaxAge                          time.Duration       `mapstructure:"key_max_age"`
	Clients                            []OIDCClient        `mapstructure:"clients"`
	CustomScopes                       []Oauth2CustomScope `mapstructure:"custom_scopes" validate:"omitempty,dive"`
	ScopesSupported                    []string            `mapstructure:"scopes_supported"`
	ResponseTypesSupported             []string            `mapstructure:"response_types_supported"`
	SubjectTypesSupported              []string            `mapstructure:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported   []string            `mapstructure:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported  []string            `mapstructure:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                    []string            `mapstructure:"claims_supported"`
	FrontChannelLogoutSupported        *bool               `mapstructure:"front_channel_logout_supported"`
	FrontChannelLogoutSessionSupported *bool               `mapstructure:"front_channel_logout_session_supported"`
	BackChannelLogoutSupported         *bool               `mapstructure:"back_channel_logout_supported"`
	BackChannelLogoutSessionSupported  *bool               `mapstructure:"back_channel_logout_session_supported"`
	AccessTokenType                    string              `mapstructure:"access_token_type"`
	DefaultAccessTokenLifetime         time.Duration       `mapstructure:"default_access_token_lifetime"`
	DefaultRefreshTokenLifetime        time.Duration       `mapstructure:"default_refresh_token_lifetime"`
}

// OIDCKey represents a single OIDC signing key.
type OIDCKey struct {
	ID      string `mapstructure:"id"`
	Key     string `mapstructure:"key"`
	KeyFile string `mapstructure:"key_file"`
	Active  bool   `mapstructure:"active"`
}

func (o *OIDCConfig) String() string {
	if o == nil {
		return "OIDCConfig: <nil>"
	}

	return fmt.Sprintf("OIDCConfig: {Enabled:%t Issuer:%s Clients:%+v ScopesSupported:%v ResponseTypesSupported:%v SubjectTypesSupported:%v IDTokenSigningAlgValuesSupported:%v TokenEndpointAuthMethodsSupported:%v ClaimsSupported:%v FrontChannelLogoutSupported:%v FrontChannelLogoutSessionSupported:%v BackChannelLogoutSupported:%v BackChannelLogoutSessionSupported:%v DefaultAccessTokenLifetime:%s DefaultRefreshTokenLifetime:%s SigningKeys:%v AutoKeyRotation:%t KeyRotationInterval:%s KeyMaxAge:%s}",
		o.Enabled, o.Issuer, o.Clients, o.ScopesSupported, o.ResponseTypesSupported, o.SubjectTypesSupported, o.IDTokenSigningAlgValuesSupported, o.TokenEndpointAuthMethodsSupported, o.ClaimsSupported, o.FrontChannelLogoutSupported, o.FrontChannelLogoutSessionSupported, o.BackChannelLogoutSupported, o.BackChannelLogoutSessionSupported, o.DefaultAccessTokenLifetime, o.DefaultRefreshTokenLifetime, o.SigningKeys, o.AutoKeyRotation, o.KeyRotationInterval, o.KeyMaxAge)
}

// GetSigningKey returns the signing key content.
func (o *OIDCConfig) GetSigningKey() (string, error) {
	for _, k := range o.SigningKeys {
		if k.Active {
			return GetContent(k.Key, k.KeyFile)
		}
	}

	return "", fmt.Errorf("no signing key configured")
}

// GetScopesSupported returns the supported scopes.
func (o *OIDCConfig) GetScopesSupported() []string {
	if len(o.ScopesSupported) > 0 {
		return o.ScopesSupported
	}

	return []string{
		definitions.ScopeOpenId,
		definitions.ScopeProfile,
		definitions.ScopeEmail,
		definitions.ScopeGroups,
		definitions.ScopeOfflineAccess,
	}
}

// GetResponseTypesSupported returns the supported response types.
func (o *OIDCConfig) GetResponseTypesSupported() []string {
	if len(o.ResponseTypesSupported) > 0 {
		return o.ResponseTypesSupported
	}

	return []string{"code"}
}

// GetSubjectTypesSupported returns the supported subject types.
func (o *OIDCConfig) GetSubjectTypesSupported() []string {
	if len(o.SubjectTypesSupported) > 0 {
		return o.SubjectTypesSupported
	}

	return []string{"public"}
}

// GetIDTokenSigningAlgValuesSupported returns the supported ID token signing algorithms.
func (o *OIDCConfig) GetIDTokenSigningAlgValuesSupported() []string {
	if len(o.IDTokenSigningAlgValuesSupported) > 0 {
		return o.IDTokenSigningAlgValuesSupported
	}

	return []string{"RS256"}
}

// GetTokenEndpointAuthMethodsSupported returns the supported token endpoint auth methods.
func (o *OIDCConfig) GetTokenEndpointAuthMethodsSupported() []string {
	if len(o.TokenEndpointAuthMethodsSupported) > 0 {
		return o.TokenEndpointAuthMethodsSupported
	}

	return []string{"client_secret_post", "client_secret_basic"}
}

// GetClaimsSupported returns the supported claims.
func (o *OIDCConfig) GetClaimsSupported() []string {
	if len(o.ClaimsSupported) > 0 {
		return o.ClaimsSupported
	}

	return []string{"sub", "name", "preferred_username", "email"}
}

// GetFrontChannelLogoutSupported returns true if front-channel logout is supported.
func (o *OIDCConfig) GetFrontChannelLogoutSupported() bool {
	if o.FrontChannelLogoutSupported != nil {
		return *o.FrontChannelLogoutSupported
	}

	return true
}

// GetFrontChannelLogoutSessionSupported returns true if front-channel logout session is supported.
func (o *OIDCConfig) GetFrontChannelLogoutSessionSupported() bool {
	if o.FrontChannelLogoutSessionSupported != nil {
		return *o.FrontChannelLogoutSessionSupported
	}

	return false
}

// GetBackChannelLogoutSupported returns true if back-channel logout is supported.
func (o *OIDCConfig) GetBackChannelLogoutSupported() bool {
	if o.BackChannelLogoutSupported != nil {
		return *o.BackChannelLogoutSupported
	}

	return true
}

// GetBackChannelLogoutSessionSupported returns true if back-channel logout session is supported.
func (o *OIDCConfig) GetBackChannelLogoutSessionSupported() bool {
	if o.BackChannelLogoutSessionSupported != nil {
		return *o.BackChannelLogoutSessionSupported
	}

	return false
}

// GetDefaultAccessTokenLifetime returns the default access token lifetime.
func (o *OIDCConfig) GetDefaultAccessTokenLifetime() time.Duration {
	if o.DefaultAccessTokenLifetime > 0 {
		return o.DefaultAccessTokenLifetime
	}

	return 1 * time.Hour
}

// GetDefaultRefreshTokenLifetime returns the default refresh token lifetime.
func (o *OIDCConfig) GetDefaultRefreshTokenLifetime() time.Duration {
	if o.DefaultRefreshTokenLifetime > 0 {
		return o.DefaultRefreshTokenLifetime
	}

	return 30 * 24 * time.Hour
}

// GetAccessTokenType returns the configured access token type (jwt or opaque).
func (o *OIDCConfig) GetAccessTokenType() string {
	if o.AccessTokenType == "" {
		return "jwt"
	}

	return strings.ToLower(o.AccessTokenType)
}

// GetAutoKeyRotation returns true if auto key rotation is enabled.
func (o *OIDCConfig) GetAutoKeyRotation() bool {
	return o.AutoKeyRotation
}

// GetKeyRotationInterval returns the interval for auto key rotation.
func (o *OIDCConfig) GetKeyRotationInterval() time.Duration {
	if o.KeyRotationInterval > 0 {
		return o.KeyRotationInterval
	}

	return 24 * time.Hour
}

// GetKeyMaxAge returns the maximum age for OIDC keys.
func (o *OIDCConfig) GetKeyMaxAge() time.Duration {
	if o.KeyMaxAge > 0 {
		return o.KeyMaxAge
	}

	return 7 * 24 * time.Hour
}

// GetSigningKeyID returns the signing key ID.
func (o *OIDCConfig) GetSigningKeyID() string {
	for _, k := range o.SigningKeys {
		if k.Active {
			return k.ID
		}
	}

	return "default"
}

// warnUnsupported returns a list of warnings for unsupported OIDC configuration parameters.
func (o *OIDCConfig) warnUnsupported() []string {
	if !o.Enabled {
		return nil
	}

	var warnings []string

	if len(o.ResponseTypesSupported) > 0 {
		for _, rt := range o.ResponseTypesSupported {
			if rt != "code" {
				warnings = append(warnings, fmt.Sprintf("oidc.response_types_supported: '%s' is currently not supported (only 'code' is supported)", rt))
			}
		}
	}

	if len(o.SubjectTypesSupported) > 0 {
		for _, st := range o.SubjectTypesSupported {
			if st != "public" {
				warnings = append(warnings, fmt.Sprintf("oidc.subject_types_supported: '%s' is currently not supported (only 'public' is supported)", st))
			}
		}
	}

	if len(o.IDTokenSigningAlgValuesSupported) > 0 {
		for _, alg := range o.IDTokenSigningAlgValuesSupported {
			if alg != "RS256" {
				warnings = append(warnings, fmt.Sprintf("oidc.id_token_signing_alg_values_supported: '%s' is currently not supported (only 'RS256' is supported)", alg))
			}
		}
	}

	if o.FrontChannelLogoutSessionSupported != nil && *o.FrontChannelLogoutSessionSupported {
		warnings = append(warnings, "oidc.front_channel_logout_session_supported: setting to 'true' is currently not supported (no effect)")
	}

	if o.BackChannelLogoutSessionSupported != nil && *o.BackChannelLogoutSessionSupported {
		warnings = append(warnings, "oidc.back_channel_logout_session_supported: setting to 'true' is currently not supported (no effect)")
	}

	return warnings
}

// OIDCClient represents an OIDC client configuration.
type OIDCClient struct {
	Name                              string            `mapstructure:"name"`
	ClientID                          string            `mapstructure:"client_id" validate:"required"`
	ClientSecret                      string            `mapstructure:"client_secret" validate:"required"`
	RedirectURIs                      []string          `mapstructure:"redirect_uris" validate:"required,gt=0"`
	Scopes                            []string          `mapstructure:"scopes"`
	SkipConsent                       bool              `mapstructure:"skip_consent"`
	DelayedResponse                   bool              `mapstructure:"delayed_response"`
	RememberMeTTL                     time.Duration     `mapstructure:"remember_me_ttl"`
	AccessTokenLifetime               time.Duration     `mapstructure:"access_token_lifetime"`
	AccessTokenType                   string            `mapstructure:"access_token_type"`
	RefreshTokenLifetime              time.Duration     `mapstructure:"refresh_token_lifetime"`
	TokenEndpointAuthMethod           string            `mapstructure:"token_endpoint_auth_method"`
	IdTokenClaims                     IdTokenClaims     `mapstructure:"id_token_claims"`
	AccessTokenClaims                 AccessTokenClaims `mapstructure:"access_token_claims"`
	PostLogoutRedirectURIs            []string          `mapstructure:"post_logout_redirect_uris"`
	BackChannelLogoutURI              string            `mapstructure:"backchannel_logout_uri"`
	FrontChannelLogoutURI             string            `mapstructure:"frontchannel_logout_uri"`
	FrontChannelLogoutSessionRequired bool              `mapstructure:"frontchannel_logout_session_required"`
	LogoutRedirectURI                 string            `mapstructure:"logout_redirect_uri"`
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

// GetAccessTokenType returns the configured access token type for the client (jwt or opaque).
func (c *OIDCClient) GetAccessTokenType(defaultType string) string {
	if c.AccessTokenType == "" {
		return defaultType
	}

	return strings.ToLower(c.AccessTokenType)
}

// SAML2Config represents the configuration for SAML 2.0.
type SAML2Config struct {
	Enabled           bool                   `mapstructure:"enabled"`
	EntityID          string                 `mapstructure:"entity_id" validate:"required_if=Enabled true"`
	Cert              string                 `mapstructure:"cert" validate:"required_if=Enabled true CertFile ''"`
	CertFile          string                 `mapstructure:"cert_file" validate:"required_if=Enabled true Cert ''"`
	Key               string                 `mapstructure:"key" validate:"required_if=Enabled true KeyFile ''"`
	KeyFile           string                 `mapstructure:"key_file" validate:"required_if=Enabled true Key ''"`
	ServiceProviders  []SAML2ServiceProvider `mapstructure:"service_providers"`
	SignatureMethod   string                 `mapstructure:"signature_method"`
	DefaultExpireTime time.Duration          `mapstructure:"default_expire_time"`
	NameIDFormat      string                 `mapstructure:"name_id_format"`
}

func (s *SAML2Config) String() string {
	if s == nil {
		return "SAML2Config: <nil>"
	}

	return fmt.Sprintf("SAML2Config: {Enabled:%t EntityID:%s ServiceProviders:%+v SignatureMethod:%s DefaultExpireTime:%s NameIDFormat:%s}",
		s.Enabled, s.EntityID, s.ServiceProviders, s.SignatureMethod, s.DefaultExpireTime, s.NameIDFormat)
}

// GetCert returns the certificate content.
func (s *SAML2Config) GetCert() (string, error) {
	return GetContent(s.Cert, s.CertFile)
}

// GetKey returns the key content.
func (s *SAML2Config) GetKey() (string, error) {
	return GetContent(s.Key, s.KeyFile)
}

// GetSignatureMethod returns the signature method.
func (s *SAML2Config) GetSignatureMethod() string {
	if s.SignatureMethod != "" {
		return s.SignatureMethod
	}

	return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
}

// GetDefaultExpireTime returns the default expire time.
func (s *SAML2Config) GetDefaultExpireTime() time.Duration {
	if s.DefaultExpireTime > 0 {
		return s.DefaultExpireTime
	}

	return time.Hour
}

// GetNameIDFormat returns the NameID format.
func (s *SAML2Config) GetNameIDFormat() string {
	if s.NameIDFormat != "" {
		return s.NameIDFormat
	}

	return "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
}

// warnUnsupported returns a list of warnings for unsupported SAML2 configuration parameters.
func (s *SAML2Config) warnUnsupported() []string {
	if !s.Enabled {
		return nil
	}

	var warnings []string

	if s.SignatureMethod != "" && s.SignatureMethod != "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" {
		warnings = append(warnings, fmt.Sprintf("saml2.signature_method: '%s' is currently not supported (only 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' is supported)", s.SignatureMethod))
	}

	return warnings
}

func GetContent(raw, path string) (string, error) {
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
	Name              string        `mapstructure:"name"`
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
