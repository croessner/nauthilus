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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/secret"
)

func validateRequiredWithinSupported(required, supported []string) bool {
	if len(required) == 0 || len(supported) == 0 {
		return true
	}

	for _, method := range required {
		if !slices.Contains(supported, method) {
			return false
		}
	}

	return true
}

func uniqueCustomScopeNames(scopes []Oauth2CustomScope) (map[string]struct{}, string, bool) {
	seen := make(map[string]struct{}, len(scopes))

	for _, scope := range scopes {
		name := strings.TrimSpace(scope.Name)
		if name == "" {
			continue
		}

		if _, exists := seen[name]; exists {
			return nil, name, false
		}

		seen[name] = struct{}{}
	}

	return seen, "", true
}

// validateIdPMFASettings ensures require_mfa is a subset of supported_mfa when supported_mfa is configured.
func (f *FileSettings) validateIdPMFASettings() error {
	if f == nil || f.IDP == nil {
		return nil
	}

	for _, client := range f.IDP.OIDC.Clients {
		if !validateRequiredWithinSupported(client.RequireMFA, client.SupportedMFA) {
			return fmt.Errorf("identity.oidc.clients[%s]: require_mfa must be a subset of supported_mfa", client.ClientID)
		}
	}

	for _, sp := range f.IDP.SAML2.ServiceProviders {
		if !validateRequiredWithinSupported(sp.RequireMFA, sp.SupportedMFA) {
			return fmt.Errorf("identity.saml.service_providers[%s]: require_mfa must be a subset of supported_mfa", sp.EntityID)
		}
	}

	return nil
}

// validateIdPOIDCCustomScopes ensures OIDC custom scope names are unique and warns when
// a client-level custom scope intentionally overrides a global scope of the same name.
func (f *FileSettings) validateIdPOIDCCustomScopes() error {
	if f == nil || f.IDP == nil {
		return nil
	}

	oidc := f.IDP.OIDC
	globalNames, duplicate, ok := uniqueCustomScopeNames(oidc.CustomScopes)
	if !ok {
		return fmt.Errorf("identity.oidc.custom_scopes: duplicate scope name '%s'", duplicate)
	}

	for idx, client := range oidc.Clients {
		clientNames, duplicate, ok := uniqueCustomScopeNames(client.CustomScopes)
		if !ok {
			return fmt.Errorf("identity.oidc.clients[%d].custom_scopes: duplicate scope name '%s'", idx, duplicate)
		}

		for name := range clientNames {
			if _, exists := globalNames[name]; !exists {
				continue
			}

			safeWarn(
				"msg", "client custom scope overrides global custom scope",
				"client_id", client.ClientID,
				"scope", name,
			)
		}
	}

	return nil
}

// validateIdPSAMLSigningSettings ensures SAML SP signing requirements have the
// required certificate material available and parseable at startup.
func (f *FileSettings) validateIdPSAMLSigningSettings() error {
	if f == nil || f.IDP == nil || !f.IDP.SAML2.Enabled {
		return nil
	}

	for _, sp := range f.IDP.SAML2.ServiceProviders {
		requirements := []struct {
			enabled bool
			key     string
			errHint string
		}{
			{
				enabled: sp.AuthnRequestsSigned,
				key:     "authn_requests_signed",
				errHint: "authn request",
			},
			{
				enabled: sp.LogoutRequestsSigned != nil && *sp.LogoutRequestsSigned,
				key:     "logout_requests_signed",
				errHint: "logout request",
			},
			{
				enabled: sp.LogoutResponsesSigned != nil && *sp.LogoutResponsesSigned,
				key:     "logout_responses_signed",
				errHint: "logout response",
			},
		}

		for _, requirement := range requirements {
			if !requirement.enabled {
				continue
			}

			certStr, err := sp.GetCert()
			if err != nil {
				return fmt.Errorf("identity.saml.service_providers[%s]: failed to read cert: %w", sp.EntityID, err)
			}

			if strings.TrimSpace(certStr) == "" {
				return fmt.Errorf("identity.saml.service_providers[%s]: %s requires cert or cert_file", sp.EntityID, requirement.key)
			}

			if _, err := parseFirstPEMCertificate(certStr); err != nil {
				return fmt.Errorf("identity.saml.service_providers[%s]: invalid cert for %s signature validation: %w", sp.EntityID, requirement.errHint, err)
			}
		}
	}

	return nil
}

// validateIdPSAML2SLOSettings ensures SAML SLO configuration values are within safe ranges.
func (f *FileSettings) validateIdPSAML2SLOSettings() error {
	if f == nil || f.IDP == nil || !f.IDP.SAML2.Enabled {
		return nil
	}

	samlCfg := f.IDP.SAML2

	if samlCfg.SLO.RequestTimeout < 0 {
		return fmt.Errorf("identity.saml.slo.request_timeout must be >= 0")
	}

	if samlCfg.SLO.MaxParticipants < 0 {
		return fmt.Errorf("identity.saml.slo.max_participants must be >= 0")
	}

	if samlCfg.SLO.BackChannelMaxRetries < 0 {
		return fmt.Errorf("identity.saml.slo.back_channel_max_retries must be >= 0")
	}

	return nil
}

func parseFirstPEMCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x509 certificate: %w", err)
	}

	return cert, nil
}

// IdPSection represents the configuration for the internal Identity Provider.
type IdPSection struct {
	OIDC                 OIDCConfig    `mapstructure:"oidc"`
	SAML2                SAML2Config   `mapstructure:"saml2"`
	WebAuthn             WebAuthn      `mapstructure:"webauthn"`
	RememberMeTTL        time.Duration `mapstructure:"remember_me_ttl"`
	TermsOfServiceURL    string        `mapstructure:"terms_of_service_url"`
	PrivacyPolicyURL     string        `mapstructure:"privacy_policy_url"`
	PasswordForgottenURL string        `mapstructure:"password_forgotten_url"`
}

func (i *IdPSection) String() string {
	if i == nil {
		return "IdPSection: <nil>"
	}

	return fmt.Sprintf(
		"IdPSection: {OIDC:%s SAML2:%s WebAuthn:%s RememberMeTTL:%s TermsOfServiceURL:%s PrivacyPolicyURL:%s PasswordForgottenURL:%s}",
		i.OIDC.String(),
		i.SAML2.String(),
		i.WebAuthn.String(),
		i.RememberMeTTL,
		i.TermsOfServiceURL,
		i.PrivacyPolicyURL,
		i.PasswordForgottenURL,
	)
}

// GetRememberMeTTL returns the global "remember me" session TTL for IdP logins.
func (i *IdPSection) GetRememberMeTTL() time.Duration {
	if i == nil {
		return 0
	}

	return i.RememberMeTTL
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
	RPDisplayName           string   `mapstructure:"rp_display_name"`
	RPID                    string   `mapstructure:"rp_id"`
	RPOrigins               []string `mapstructure:"rp_origins"`
	AuthenticatorAttachment string   `mapstructure:"authenticator_attachment" validate:"omitempty,oneof=platform cross-platform"`
	ResidentKey             string   `mapstructure:"resident_key" validate:"omitempty,oneof=discouraged preferred required"`
	UserVerification        string   `mapstructure:"user_verification" validate:"omitempty,oneof=discouraged preferred required"`
}

func (w *WebAuthn) String() string {
	if w == nil {
		return "WebAuthn: <nil>"
	}

	return fmt.Sprintf("WebAuthn: {RPDisplayName:%s RPID:%s RPOrigins:%v AuthenticatorAttachment:%s ResidentKey:%s UserVerification:%s}",
		w.RPDisplayName, w.RPID, w.RPOrigins, w.AuthenticatorAttachment, w.ResidentKey, w.UserVerification)
}

// GetAuthenticatorAttachment returns the configured authenticator attachment preference.
// Valid values are "platform" and "cross-platform". An empty string means no preference.
func (w *WebAuthn) GetAuthenticatorAttachment() string {
	if w == nil {
		return ""
	}

	return strings.ToLower(w.AuthenticatorAttachment)
}

// GetResidentKey returns the configured resident key requirement.
// Valid values are "discouraged", "preferred", and "required". Defaults to "discouraged".
func (w *WebAuthn) GetResidentKey() string {
	if w == nil {
		return "discouraged"
	}

	value := strings.ToLower(w.ResidentKey)

	switch value {
	case "discouraged", "preferred", "required":
		return value
	default:
		return "discouraged"
	}
}

// GetUserVerification returns the configured user verification requirement.
// Valid values are "discouraged", "preferred", and "required". Defaults to "preferred".
func (w *WebAuthn) GetUserVerification() string {
	if w == nil {
		return "preferred"
	}

	value := strings.ToLower(w.UserVerification)

	switch value {
	case "discouraged", "preferred", "required":
		return value
	default:
		return "preferred"
	}
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
	CodeChallengeMethodsSupported      []string            `mapstructure:"code_challenge_methods_supported"`
	ClaimsSupported                    []string            `mapstructure:"claims_supported"`
	FrontChannelLogoutSupported        *bool               `mapstructure:"front_channel_logout_supported"`
	FrontChannelLogoutSessionSupported *bool               `mapstructure:"front_channel_logout_session_supported"`
	BackChannelLogoutSupported         *bool               `mapstructure:"back_channel_logout_supported"`
	BackChannelLogoutSessionSupported  *bool               `mapstructure:"back_channel_logout_session_supported"`
	AccessTokenType                    string              `mapstructure:"access_token_type"`
	DefaultAccessTokenLifetime         time.Duration       `mapstructure:"default_access_token_lifetime"`
	DefaultRefreshTokenLifetime        time.Duration       `mapstructure:"default_refresh_token_lifetime"`
	RevokeRefreshToken                 *bool               `mapstructure:"revoke_refresh_token"`
	ConsentTTL                         time.Duration       `mapstructure:"consent_ttl"`
	ConsentMode                        string              `mapstructure:"consent_mode" validate:"omitempty,oneof=all_or_nothing granular_optional"`
	TokenEndpointAllowGET              bool                `mapstructure:"token_endpoint_allow_get"`
	DeviceCodeExpiry                   time.Duration       `mapstructure:"device_code_expiry"`
	DeviceCodePollingInterval          int                 `mapstructure:"device_code_polling_interval"`
	DeviceCodeUserCodeLength           int                 `mapstructure:"device_code_user_code_length"`
}

// OIDCKey represents a single OIDC signing key.
type OIDCKey struct {
	ID        string       `mapstructure:"id"`
	Key       secret.Value `mapstructure:"key"`
	KeyFile   string       `mapstructure:"key_file"`
	Algorithm string       `mapstructure:"algorithm"`
	Active    bool         `mapstructure:"active"`
}

func (o OIDCKey) String() string {
	return fmt.Sprintf("OIDCKey{ID:%s Key:<hidden> KeyFile:%s Algorithm:%s Active:%t}", o.ID, o.KeyFile, o.GetAlgorithm(), o.Active)
}

// GetAlgorithm returns the algorithm for this key, defaulting to RS256.
func (o OIDCKey) GetAlgorithm() string {
	if o.Algorithm != "" {
		return strings.ToUpper(o.Algorithm)
	}

	return "RS256"
}

func (o *OIDCConfig) String() string {
	if o == nil {
		return "OIDCConfig: <nil>"
	}

	return fmt.Sprintf("OIDCConfig: {Enabled:%t Issuer:%s Clients:%+v ScopesSupported:%v ResponseTypesSupported:%v SubjectTypesSupported:%v IDTokenSigningAlgValuesSupported:%v TokenEndpointAuthMethodsSupported:%v ClaimsSupported:%v FrontChannelLogoutSupported:%v FrontChannelLogoutSessionSupported:%v BackChannelLogoutSupported:%v BackChannelLogoutSessionSupported:%v DefaultAccessTokenLifetime:%s DefaultRefreshTokenLifetime:%s SigningKeys:%v AutoKeyRotation:%t KeyRotationInterval:%s KeyMaxAge:%s TokenEndpointAllowGET:%t}",
		o.Enabled, o.Issuer, o.Clients, o.ScopesSupported, o.ResponseTypesSupported, o.SubjectTypesSupported, o.IDTokenSigningAlgValuesSupported, o.TokenEndpointAuthMethodsSupported, o.ClaimsSupported, o.FrontChannelLogoutSupported, o.FrontChannelLogoutSessionSupported, o.BackChannelLogoutSupported, o.BackChannelLogoutSessionSupported, o.DefaultAccessTokenLifetime, o.DefaultRefreshTokenLifetime, o.SigningKeys, o.AutoKeyRotation, o.KeyRotationInterval, o.KeyMaxAge, o.TokenEndpointAllowGET)
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

// GetGrantTypesSupported returns the grant types supported by the token endpoint.
func (o *OIDCConfig) GetGrantTypesSupported() []string {
	return []string{
		"authorization_code",
		"refresh_token",
		"client_credentials",
		definitions.OIDCGrantTypeDeviceCode,
	}
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

	return []string{"RS256", "EdDSA"}
}

// GetTokenEndpointAuthMethodsSupported returns the supported token endpoint auth methods.
func (o *OIDCConfig) GetTokenEndpointAuthMethodsSupported() []string {
	if len(o.TokenEndpointAuthMethodsSupported) > 0 {
		return o.TokenEndpointAuthMethodsSupported
	}

	return []string{"client_secret_post", "client_secret_basic", "private_key_jwt", "none"}
}

// GetTokenEndpointAuthSigningAlgValuesSupported returns the signing algorithms
// supported for private_key_jwt client authentication at the token endpoint.
// The metadata value is only relevant when private_key_jwt is advertised.
func (o *OIDCConfig) GetTokenEndpointAuthSigningAlgValuesSupported() []string {
	if slices.Contains(o.GetTokenEndpointAuthMethodsSupported(), "private_key_jwt") {
		return []string{"RS256", "EdDSA"}
	}

	return nil
}

// GetIntrospectionEndpointAuthMethodsSupported returns the client
// authentication methods accepted by the introspection endpoint.
func (o *OIDCConfig) GetIntrospectionEndpointAuthMethodsSupported() []string {
	return []string{"client_secret_post", "client_secret_basic"}
}

// GetCodeChallengeMethodsSupported returns the supported PKCE code challenge methods.
// Only S256 is supported; plain is rejected as it provides no additional security.
func (o *OIDCConfig) GetCodeChallengeMethodsSupported() []string {
	return []string{"S256"}
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

// GetRevokeRefreshToken reports whether refresh token rotation is enabled.
// The secure default is enabled, which means refresh tokens are one-time use.
func (o *OIDCConfig) GetRevokeRefreshToken() bool {
	if o != nil && o.RevokeRefreshToken != nil {
		return *o.RevokeRefreshToken
	}

	return true
}

// GetConsentTTL returns the default consent validity duration for OIDC clients.
func (o *OIDCConfig) GetConsentTTL() time.Duration {
	if o != nil && o.ConsentTTL > 0 {
		return o.ConsentTTL
	}

	return definitions.OIDCConsentDefaultTTL
}

const (
	// OIDCConsentModeAllOrNothing keeps the traditional behavior:
	// user grants or denies the full requested scope set.
	OIDCConsentModeAllOrNothing = "all_or_nothing"
	// OIDCConsentModeGranularOptional allows opting out of optional scopes while required scopes remain mandatory.
	OIDCConsentModeGranularOptional = "granular_optional"
)

// GetConsentMode returns the configured global consent mode.
func (o *OIDCConfig) GetConsentMode() string {
	if o != nil {
		mode := strings.ToLower(strings.TrimSpace(o.ConsentMode))
		if mode == OIDCConsentModeGranularOptional {
			return OIDCConsentModeGranularOptional
		}
	}

	return OIDCConsentModeAllOrNothing
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

// GetDeviceCodeExpiry returns the device code expiry duration.
// Defaults to OIDCDeviceCodeDefaultExpiry if not configured.
func (o *OIDCConfig) GetDeviceCodeExpiry() time.Duration {
	if o.DeviceCodeExpiry > 0 {
		return o.DeviceCodeExpiry
	}

	return definitions.OIDCDeviceCodeDefaultExpiry
}

// GetDeviceCodePollingInterval returns the polling interval in seconds.
// Defaults to OIDCDeviceCodeDefaultInterval if not configured.
func (o *OIDCConfig) GetDeviceCodePollingInterval() int {
	if o.DeviceCodePollingInterval > 0 {
		return o.DeviceCodePollingInterval
	}

	return definitions.OIDCDeviceCodeDefaultInterval
}

// GetDeviceCodeUserCodeLength returns the user code length.
// Defaults to OIDCDeviceCodeDefaultUserCodeLength if not configured.
func (o *OIDCConfig) GetDeviceCodeUserCodeLength() int {
	if o.DeviceCodeUserCodeLength > 0 {
		return o.DeviceCodeUserCodeLength
	}

	return definitions.OIDCDeviceCodeDefaultUserCodeLength
}

// IsTokenEndpointGETAllowed reports whether GET requests are accepted on /oidc/token.
// Defaults to false (POST only) for stricter handling of secrets and grant data.
func (o *OIDCConfig) IsTokenEndpointGETAllowed() bool {
	if o == nil {
		return false
	}

	return o.TokenEndpointAllowGET
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
			if alg != "RS256" && alg != "EdDSA" {
				warnings = append(warnings, fmt.Sprintf("oidc.id_token_signing_alg_values_supported: '%s' is currently not supported (only 'RS256' and 'EdDSA' are supported)", alg))
			}
		}
	}

	if len(o.CodeChallengeMethodsSupported) > 0 {
		for _, method := range o.CodeChallengeMethodsSupported {
			method = strings.TrimSpace(method)
			if !strings.EqualFold(method, "S256") {
				warnings = append(warnings, fmt.Sprintf("oidc.code_challenge_methods_supported: '%s' is not supported (only 'S256' is allowed)", method))
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
	Name                     string              `mapstructure:"name"`
	ClientID                 string              `mapstructure:"client_id" validate:"required"`
	ClientSecret             secret.Value        `mapstructure:"client_secret"`
	RedirectURIs             []string            `mapstructure:"redirect_uris"`
	Scopes                   []string            `mapstructure:"scopes"`
	ImpliedScopes            []string            `mapstructure:"implied_scopes"`
	CustomScopes             []Oauth2CustomScope `mapstructure:"custom_scopes" validate:"omitempty,dive"`
	GrantTypes               []string            `mapstructure:"grant_types"`
	RequireMFA               []string            `mapstructure:"require_mfa" validate:"omitempty,dive,oneof=totp webauthn recovery_codes"`
	SupportedMFA             []string            `mapstructure:"supported_mfa" validate:"omitempty,dive,oneof=totp webauthn recovery_codes"`
	PostLogoutRedirectURIs   []string            `mapstructure:"post_logout_redirect_uris"`
	BackChannelLogoutURI     string              `mapstructure:"backchannel_logout_uri"`
	FrontChannelLogoutURI    string              `mapstructure:"frontchannel_logout_uri"`
	LogoutRedirectURI        string              `mapstructure:"logout_redirect_uri"`
	AccessTokenType          string              `mapstructure:"access_token_type"`
	TokenEndpointAuthMethod  string              `mapstructure:"token_endpoint_auth_method"`
	ClientPublicKey          string              `mapstructure:"client_public_key"`
	ClientPublicKeyFile      string              `mapstructure:"client_public_key_file"`
	ClientPublicKeyAlgorithm string              `mapstructure:"client_public_key_algorithm"`
	IdTokenClaims            IdTokenClaims       `mapstructure:"id_token_claims"`
	AccessTokenClaims        AccessTokenClaims   `mapstructure:"access_token_claims"`
	// Deprecated: use identity.session.remember_me_ttl instead.
	RememberMeTTL                       time.Duration `mapstructure:"remember_me_ttl"`
	AccessTokenLifetime                 time.Duration `mapstructure:"access_token_lifetime"`
	RefreshTokenLifetime                time.Duration `mapstructure:"refresh_token_lifetime"`
	ConsentTTL                          time.Duration `mapstructure:"consent_ttl"`
	ConsentMode                         string        `mapstructure:"consent_mode" validate:"omitempty,oneof=all_or_nothing granular_optional"`
	RequiredScopes                      []string      `mapstructure:"required_scopes"`
	OptionalScopes                      []string      `mapstructure:"optional_scopes" validate:"omitempty,dive,ne=openid"`
	SkipConsent                         bool          `mapstructure:"skip_consent"`
	DelayedResponse                     bool          `mapstructure:"delayed_response"`
	AllowRefreshTokenCombinedClientAuth bool          `mapstructure:"allow_refresh_token_combined_client_auth"`
	RevokeRefreshToken                  *bool         `mapstructure:"revoke_refresh_token"`
	FrontChannelLogoutSessionRequired   bool          `mapstructure:"frontchannel_logout_session_required"`
}

// GetEffectiveCustomScopes returns the merged custom scopes for a client.
// Client-level scopes fully replace global scopes when names collide.
func (o *OIDCConfig) GetEffectiveCustomScopes(client *OIDCClient) []Oauth2CustomScope {
	if o == nil {
		if client == nil {
			return nil
		}

		return mergeCustomScopes(nil, client.CustomScopes)
	}

	return mergeCustomScopes(o.CustomScopes, client.GetCustomScopes())
}

func mergeCustomScopes(baseScopes []Oauth2CustomScope, clientScopes []Oauth2CustomScope) []Oauth2CustomScope {
	if len(baseScopes) == 0 && len(clientScopes) == 0 {
		return nil
	}

	result := make([]Oauth2CustomScope, 0, len(baseScopes)+len(clientScopes))
	indexByName := make(map[string]int, len(baseScopes)+len(clientScopes))

	for _, scope := range baseScopes {
		name := strings.TrimSpace(scope.Name)
		if name != "" {
			indexByName[name] = len(result)
		}

		result = append(result, scope)
	}

	for _, scope := range clientScopes {
		name := strings.TrimSpace(scope.Name)
		if name == "" {
			result = append(result, scope)

			continue
		}

		if idx, exists := indexByName[name]; exists {
			result[idx] = scope

			continue
		}

		indexByName[name] = len(result)
		result = append(result, scope)
	}

	return result
}

// IsPublicClient reports whether the client is a public client, i.e. it has no
// client secret and uses the "none" token endpoint auth method. Public clients
// cannot keep credentials confidential and MUST use PKCE for the authorization
// code flow (RFC 9700).
func (c *OIDCClient) IsPublicClient() bool {
	if c == nil {
		return false
	}

	return c.ClientSecret.IsZero() || c.TokenEndpointAuthMethod == "none"
}

// AllowsRefreshTokenCombinedClientAuth reports whether this client is allowed
// to use a compatibility mode for refresh token requests that carry
// credentials in both HTTP Basic auth and the request body.
func (c *OIDCClient) AllowsRefreshTokenCombinedClientAuth() bool {
	if c == nil {
		return false
	}

	return c.AllowRefreshTokenCombinedClientAuth
}

// GetRevokeRefreshToken resolves the client-specific refresh token rotation
// setting or falls back to the provided global default.
func (c *OIDCClient) GetRevokeRefreshToken(defaultValue bool) bool {
	if c != nil && c.RevokeRefreshToken != nil {
		return *c.RevokeRefreshToken
	}

	return defaultValue
}

func (c *OIDCClient) String() string {
	if c == nil {
		return "<nil>"
	}

	return fmt.Sprintf("OIDCClient{Name:%s ClientID:%s ClientSecret:<hidden> RedirectURIs:%v GrantTypes:%v TokenEndpointAuthMethod:%s}", c.Name, c.ClientID, c.RedirectURIs, c.GrantTypes, c.TokenEndpointAuthMethod)
}

// GetRequireMFA returns the list of MFA methods required for this client.
// An empty list means no MFA registration is enforced.
func (c *OIDCClient) GetRequireMFA() []string {
	if c == nil {
		return nil
	}

	return c.RequireMFA
}

// GetSupportedMFA returns the list of MFA methods supported for this client.
// An empty list means all available methods are supported.
func (c *OIDCClient) GetSupportedMFA() []string {
	if c == nil {
		return nil
	}

	return c.SupportedMFA
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

// GetImpliedScopes returns the configured implied scopes for this client.
func (c *OIDCClient) GetImpliedScopes() []string {
	if c == nil || len(c.ImpliedScopes) == 0 {
		return nil
	}

	return c.ImpliedScopes
}

// GetCustomScopes returns the client-level custom scopes.
func (c *OIDCClient) GetCustomScopes() []Oauth2CustomScope {
	if c == nil || len(c.CustomScopes) == 0 {
		return nil
	}

	return c.CustomScopes
}

// IsDelayedResponse returns true if delayed response is enabled for this client.
func (c *OIDCClient) IsDelayedResponse() bool {
	if c == nil {
		return false
	}

	return c.DelayedResponse
}

// GetConsentTTL returns the client-specific consent validity duration.
// When not explicitly configured at client level, the provided defaultTTL is used.
func (c *OIDCClient) GetConsentTTL(defaultTTL time.Duration) time.Duration {
	if c != nil && c.ConsentTTL > 0 {
		return c.ConsentTTL
	}

	if defaultTTL > 0 {
		return defaultTTL
	}

	return definitions.OIDCConsentDefaultTTL
}

// GetConsentMode resolves the client-specific consent mode or falls back to the global default.
func (c *OIDCClient) GetConsentMode(defaultMode string) string {
	mode := strings.ToLower(strings.TrimSpace(defaultMode))
	if mode != OIDCConsentModeGranularOptional {
		mode = OIDCConsentModeAllOrNothing
	}

	if c != nil {
		clientMode := strings.ToLower(strings.TrimSpace(c.ConsentMode))
		if clientMode == OIDCConsentModeGranularOptional {
			return OIDCConsentModeGranularOptional
		}
		if clientMode == OIDCConsentModeAllOrNothing {
			return OIDCConsentModeAllOrNothing
		}
	}

	return mode
}

// GetAccessTokenType returns the configured access token type for the client (jwt or opaque).
func (c *OIDCClient) GetAccessTokenType(defaultType string) string {
	if c.AccessTokenType == "" {
		return defaultType
	}

	return strings.ToLower(c.AccessTokenType)
}

// GetGrantTypes returns the allowed grant types for this client.
// If none are configured, defaults to ["authorization_code"].
func (c *OIDCClient) GetGrantTypes() []string {
	if c == nil {
		return nil
	}

	if len(c.GrantTypes) == 0 {
		return []string{"authorization_code"}
	}

	return c.GrantTypes
}

// SupportsGrantType returns true if the client supports the given grant type.
func (c *OIDCClient) SupportsGrantType(grantType string) bool {
	if c == nil {
		return false
	}

	return slices.Contains(c.GetGrantTypes(), grantType)
}

// GetClientPublicKey returns the client's public key content (inline or from file).
func (c *OIDCClient) GetClientPublicKey() (string, error) {
	if c == nil {
		return "", fmt.Errorf("client is nil")
	}

	return GetContent(c.ClientPublicKey, c.ClientPublicKeyFile)
}

// GetClientPublicKeyAlgorithm returns the algorithm for the client's public key.
// Defaults to "RS256" if not configured.
func (c *OIDCClient) GetClientPublicKeyAlgorithm() string {
	if c == nil || c.ClientPublicKeyAlgorithm == "" {
		return "RS256"
	}

	return c.ClientPublicKeyAlgorithm
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
	SLO               SAML2SLOConfig         `mapstructure:"slo"`
}

type SAML2SLOConfig struct {
	Enabled               *bool         `mapstructure:"enabled"`
	FrontChannelEnabled   *bool         `mapstructure:"front_channel_enabled"`
	BackChannelEnabled    *bool         `mapstructure:"back_channel_enabled"`
	RequestTimeout        time.Duration `mapstructure:"request_timeout"`
	MaxParticipants       int           `mapstructure:"max_participants"`
	BackChannelMaxRetries int           `mapstructure:"back_channel_max_retries"`
}

const (
	defaultSLOEnabled            = true
	defaultSLOFrontChannel       = true
	defaultSLOBackChannel        = false
	defaultSLORequestTimeout     = 3 * time.Second
	defaultSLOMaxParticipants    = 64
	defaultSLOBackChannelRetries = 1
)

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

// GetSLOEnabled returns true when protocol-aware SAML SLO handling is enabled.
func (s *SAML2Config) GetSLOEnabled() bool {
	if s == nil {
		return defaultSLOEnabled
	}

	if s.SLO.Enabled != nil {
		return *s.SLO.Enabled
	}

	return defaultSLOEnabled
}

// GetSLOFrontChannelEnabled returns true when browser-based SLO fanout is enabled.
func (s *SAML2Config) GetSLOFrontChannelEnabled() bool {
	if s == nil {
		return defaultSLOFrontChannel
	}

	if s.SLO.FrontChannelEnabled != nil {
		return *s.SLO.FrontChannelEnabled
	}

	return defaultSLOFrontChannel
}

// GetSLOBackChannelEnabled returns true when server-side SAML SLO back-channel delivery is enabled.
func (s *SAML2Config) GetSLOBackChannelEnabled() bool {
	if s == nil {
		return defaultSLOBackChannel
	}

	if s.SLO.BackChannelEnabled != nil {
		return *s.SLO.BackChannelEnabled
	}

	return defaultSLOBackChannel
}

// GetSLORequestTimeout returns the request timeout used by SLO HTTP dispatches.
func (s *SAML2Config) GetSLORequestTimeout() time.Duration {
	if s == nil {
		return defaultSLORequestTimeout
	}

	if s.SLO.RequestTimeout > 0 {
		return s.SLO.RequestTimeout
	}

	return defaultSLORequestTimeout
}

// GetSLOMaxParticipants returns the maximum number of participants processed per fanout run.
func (s *SAML2Config) GetSLOMaxParticipants() int {
	if s == nil || s.SLO.MaxParticipants <= 0 {
		return defaultSLOMaxParticipants
	}

	return s.SLO.MaxParticipants
}

// GetSLOBackChannelTimeout returns the request timeout for SAML SLO back-channel delivery.
func (s *SAML2Config) GetSLOBackChannelTimeout() time.Duration {
	return s.GetSLORequestTimeout()
}

// GetSLOBackChannelMaxRetries returns the number of retry attempts after the first back-channel request.
func (s *SAML2Config) GetSLOBackChannelMaxRetries() int {
	if s == nil {
		return defaultSLOBackChannelRetries
	}

	retries := s.SLO.BackChannelMaxRetries

	if retries == 0 {
		return defaultSLOBackChannelRetries
	}

	if retries < 0 {
		return 0
	}

	return retries
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

	if !s.GetSLOEnabled() && (s.GetSLOFrontChannelEnabled() || s.GetSLOBackChannelEnabled()) {
		warnings = append(warnings, "saml2.slo.enabled: set to 'false' disables front_channel_enabled and back_channel_enabled")
	}

	return warnings
}

func GetContent(raw any, path string) (string, error) {
	switch value := raw.(type) {
	case string:
		if value != "" {
			return value, nil
		}
	case secret.Value:
		if !value.IsZero() {
			return value.String(), nil
		}
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
	Name                  string   `mapstructure:"name"`
	EntityID              string   `mapstructure:"entity_id" validate:"required"`
	ACSURL                string   `mapstructure:"acs_url" validate:"required"`
	SLOURL                string   `mapstructure:"slo_url"`
	SLOBackChannelURL     string   `mapstructure:"slo_back_channel_url"`
	Cert                  string   `mapstructure:"cert"`
	CertFile              string   `mapstructure:"cert_file"`
	AuthnRequestsSigned   bool     `mapstructure:"authn_requests_signed"`
	LogoutRequestsSigned  *bool    `mapstructure:"logout_requests_signed"`
	LogoutResponsesSigned *bool    `mapstructure:"logout_responses_signed"`
	AllowedAttributes     []string `mapstructure:"allowed_attributes"`
	RequireMFA            []string `mapstructure:"require_mfa" validate:"omitempty,dive,oneof=totp webauthn recovery_codes"`
	SupportedMFA          []string `mapstructure:"supported_mfa" validate:"omitempty,dive,oneof=totp webauthn recovery_codes"`
	LogoutRedirectURI     string   `mapstructure:"logout_redirect_uri"`
	// Deprecated: use identity.session.remember_me_ttl instead.
	RememberMeTTL   time.Duration `mapstructure:"remember_me_ttl"`
	DelayedResponse bool          `mapstructure:"delayed_response"`
}

// GetRequireMFA returns the list of MFA methods required for this service provider.
// An empty list means no MFA registration is enforced.
func (s *SAML2ServiceProvider) GetRequireMFA() []string {
	if s == nil {
		return nil
	}

	return s.RequireMFA
}

// GetSupportedMFA returns the list of MFA methods supported for this service provider.
// An empty list means all available methods are supported.
func (s *SAML2ServiceProvider) GetSupportedMFA() []string {
	if s == nil {
		return nil
	}

	return s.SupportedMFA
}

// GetCert returns the SP certificate content (inline or from file).
func (s *SAML2ServiceProvider) GetCert() (string, error) {
	if s == nil {
		return "", nil
	}

	return GetContent(s.Cert, s.CertFile)
}

// AreAuthnRequestsSigned returns whether this SP signs AuthnRequests.
func (s *SAML2ServiceProvider) AreAuthnRequestsSigned() bool {
	if s == nil {
		return false
	}

	return s.AuthnRequestsSigned
}

// AreLogoutRequestsSigned returns whether this SP must sign LogoutRequests.
func (s *SAML2ServiceProvider) AreLogoutRequestsSigned() bool {
	if s == nil || s.LogoutRequestsSigned == nil {
		return false
	}

	return *s.LogoutRequestsSigned
}

// AreLogoutResponsesSigned returns whether this SP must sign LogoutResponses.
func (s *SAML2ServiceProvider) AreLogoutResponsesSigned() bool {
	if s == nil || s.LogoutResponsesSigned == nil {
		return false
	}

	return *s.LogoutResponsesSigned
}

// FindSAMLServiceProviderByEntityID returns the configured SAML service provider
// that matches the given entity ID.
func FindSAMLServiceProviderByEntityID(serviceProviders []SAML2ServiceProvider, entityID string) (*SAML2ServiceProvider, bool) {
	entityID = strings.TrimSpace(entityID)
	if entityID == "" {
		return nil, false
	}

	for index := range serviceProviders {
		if samlServiceProviderEntityIDMatches(serviceProviders[index].EntityID, entityID) {
			return &serviceProviders[index], true
		}
	}

	return nil, false
}

func samlServiceProviderEntityIDMatches(configuredEntityID, incomingEntityID string) bool {
	configuredEntityID = strings.TrimSpace(configuredEntityID)
	incomingEntityID = strings.TrimSpace(incomingEntityID)

	if configuredEntityID == "" || incomingEntityID == "" {
		return false
	}

	if configuredEntityID == incomingEntityID {
		return true
	}

	normalizedConfiguredEntityID, ok := normalizeSAMLServiceProviderEntityID(configuredEntityID)
	if !ok {
		return false
	}

	normalizedIncomingEntityID, ok := normalizeSAMLServiceProviderEntityID(incomingEntityID)
	if !ok {
		return false
	}

	return normalizedConfiguredEntityID == normalizedIncomingEntityID
}

func normalizeSAMLServiceProviderEntityID(entityID string) (string, bool) {
	parsedEntityID, err := url.Parse(strings.TrimSpace(entityID))
	if err != nil || parsedEntityID.Scheme == "" || parsedEntityID.Host == "" {
		return "", false
	}

	parsedEntityID.Scheme = strings.ToLower(parsedEntityID.Scheme)
	parsedEntityID.Host = strings.ToLower(parsedEntityID.Host)
	parsedEntityID.Fragment = ""

	if parsedEntityID.Path != "/" {
		parsedEntityID.Path = strings.TrimRight(parsedEntityID.Path, "/")
	}

	return parsedEntityID.String(), true
}

// GetAllowedAttributes returns the allowed attributes for this SP.
// If empty, all attributes are allowed.
func (s *SAML2ServiceProvider) GetAllowedAttributes() []string {
	if s == nil {
		return nil
	}

	return s.AllowedAttributes
}

// GetSLOBackChannelURL returns the optional SAML SLO back-channel endpoint for this SP.
func (s *SAML2ServiceProvider) GetSLOBackChannelURL() string {
	if s == nil {
		return ""
	}

	return s.SLOBackChannelURL
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

	if f.IDP == nil {
		f.materializeLegacySections()
	}

	if f.IDP == nil {
		return &IdPSection{}
	}

	return f.IDP
}
