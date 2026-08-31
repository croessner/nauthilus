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
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/secret"
)

const (
	oidcDCRProfileMailClientV1 = "mail-client-v1"
	oidcDCRConsentAllOrNothing = "all_or_nothing"
	oidcDCRClientIDPrefix      = "dcr_"

	oidcDCRProfileVersion             = 1
	oidcDCRMinimumSourceHMACKeyBytes  = 32
	oidcDCRDefaultRequestBodyBytes    = 16_384
	oidcDCRDefaultRedirectURIs        = 4
	oidcDCRDefaultScopes              = 16
	oidcDCRDefaultClientNameRunes     = 128
	oidcDCRDefaultStringBytes         = 1_024
	oidcDCRDefaultActiveClients       = 10_000
	oidcDCRDefaultSourceRegistrations = 5
	oidcDCRDefaultSourceDaily         = 20
	oidcDCRDefaultGlobalRegistrations = 100

	oidcDCRMaximumRequestBodyBytes = 1 << 20
	oidcDCRMaximumRedirectURIs     = 32
	oidcDCRMaximumScopes           = 128
	oidcDCRMaximumClientNameRunes  = 1_024
	oidcDCRMaximumStringBytes      = 8_192
	oidcDCRMaximumActiveClients    = 1_000_000
)

const (
	oidcDCRDefaultAccessTokenLifetime  = 15 * time.Minute
	oidcDCRMaximumAccessTokenLifetime  = 15 * time.Minute
	oidcDCRDefaultRefreshTokenLifetime = 30 * 24 * time.Hour
	oidcDCRMaximumRefreshTokenLifetime = 30 * 24 * time.Hour
	oidcDCRDefaultSourceWindow         = 10 * time.Minute
	oidcDCRDefaultGlobalWindow         = time.Minute
	oidcDCRDefaultUnusedTTL            = 24 * time.Hour
	oidcDCRDefaultInactivityTTL        = 30 * 24 * time.Hour
	oidcDCRDefaultMaximumTTL           = 365 * 24 * time.Hour
	oidcDCRDefaultTombstoneTTL         = 30 * 24 * time.Hour
)

// OIDCDynamicClientRegistrationConfig defines the restricted native-client registration profile.
type OIDCDynamicClientRegistrationConfig struct {
	RequiredScopes       []string                               `mapstructure:"required_scopes"`
	OptionalScopes       []string                               `mapstructure:"optional_scopes"`
	Profile              string                                 `mapstructure:"profile"`
	ConsentMode          string                                 `mapstructure:"consent_mode"`
	SourceHMACKey        secret.Value                           `mapstructure:"source_hmac_key"`
	Limits               OIDCDynamicClientRegistrationLimits    `mapstructure:"limits"`
	Lifecycle            OIDCDynamicClientRegistrationLifecycle `mapstructure:"lifecycle"`
	AccessTokenLifetime  time.Duration                          `mapstructure:"access_token_lifetime"`
	RefreshTokenLifetime time.Duration                          `mapstructure:"refresh_token_lifetime"`
	ProfileVersion       int                                    `mapstructure:"profile_version"`
	RequiredMFALevel     int                                    `mapstructure:"required_mfa_level"`
	Enabled              bool                                   `mapstructure:"enabled"`
	AllowRefreshTokens   bool                                   `mapstructure:"allow_refresh_tokens"`
}

// OIDCDynamicClientRegistrationLimits bounds registration input, storage, and rate consumption.
type OIDCDynamicClientRegistrationLimits struct {
	SourceWindow             time.Duration `mapstructure:"source_window"`
	GlobalWindow             time.Duration `mapstructure:"global_window"`
	RequestBodyBytes         int           `mapstructure:"request_body_bytes"`
	RedirectURIs             int           `mapstructure:"redirect_uris"`
	Scopes                   int           `mapstructure:"scopes"`
	ClientNameRunes          int           `mapstructure:"client_name_runes"`
	StringBytes              int           `mapstructure:"string_bytes"`
	ActiveClients            int           `mapstructure:"active_clients"`
	SourceRegistrations      int           `mapstructure:"source_registrations"`
	SourceDailyRegistrations int           `mapstructure:"source_daily_registrations"`
	GlobalRegistrations      int           `mapstructure:"global_registrations"`
}

// OIDCDynamicClientRegistrationLifecycle bounds unused, inactive, absolute, and tombstone state.
type OIDCDynamicClientRegistrationLifecycle struct {
	UnusedTTL     time.Duration `mapstructure:"unused_ttl"`
	InactivityTTL time.Duration `mapstructure:"inactivity_ttl"`
	MaximumTTL    time.Duration `mapstructure:"maximum_ttl"`
	TombstoneTTL  time.Duration `mapstructure:"tombstone_ttl"`
}

// String formats dynamic registration configuration without exposing source-key material.
func (c OIDCDynamicClientRegistrationConfig) String() string {
	return fmt.Sprintf("OIDCDynamicClientRegistrationConfig:{Enabled:%t Profile:%s ProfileVersion:%d RequiredScopes:%v OptionalScopes:%v AllowRefreshTokens:%t ConsentMode:%s RequiredMFALevel:%d AccessTokenLifetime:%s RefreshTokenLifetime:%s SourceHMACKey:<hidden> Limits:%+v Lifecycle:%+v}",
		c.Enabled,
		c.GetProfile(),
		c.GetProfileVersion(),
		c.RequiredScopes,
		c.OptionalScopes,
		c.AllowRefreshTokens,
		c.GetConsentMode(),
		c.RequiredMFALevel,
		c.GetAccessTokenLifetime(),
		c.GetRefreshTokenLifetime(),
		c.GetLimits(),
		c.GetLifecycle(),
	)
}

// GetProfile returns the fixed native-client profile identifier.
func (c OIDCDynamicClientRegistrationConfig) GetProfile() string {
	if c.Profile == "" {
		return oidcDCRProfileMailClientV1
	}

	return c.Profile
}

// GetProfileVersion returns the fixed native-client profile version.
func (c OIDCDynamicClientRegistrationConfig) GetProfileVersion() int {
	if c.ProfileVersion == 0 {
		return oidcDCRProfileVersion
	}

	return c.ProfileVersion
}

// GetConsentMode returns the consent behavior imposed on dynamic clients.
func (c OIDCDynamicClientRegistrationConfig) GetConsentMode() string {
	if c.ConsentMode == "" {
		return oidcDCRConsentAllOrNothing
	}

	return c.ConsentMode
}

// GetAccessTokenLifetime returns the configured opaque access-token lifetime.
func (c OIDCDynamicClientRegistrationConfig) GetAccessTokenLifetime() time.Duration {
	return defaultDuration(c.AccessTokenLifetime, oidcDCRDefaultAccessTokenLifetime)
}

// GetRefreshTokenLifetime returns the configured rotating refresh-token lifetime.
func (c OIDCDynamicClientRegistrationConfig) GetRefreshTokenLifetime() time.Duration {
	return defaultDuration(c.RefreshTokenLifetime, oidcDCRDefaultRefreshTokenLifetime)
}

// GetLimits returns the effective registration limits.
func (c OIDCDynamicClientRegistrationConfig) GetLimits() OIDCDynamicClientRegistrationLimits {
	return c.Limits.withDefaults()
}

// GetLifecycle returns the effective dynamic-client lifecycle.
func (c OIDCDynamicClientRegistrationConfig) GetLifecycle() OIDCDynamicClientRegistrationLifecycle {
	return c.Lifecycle.withDefaults()
}

// GetRequestBodyBytes returns the maximum registration request size.
func (l OIDCDynamicClientRegistrationLimits) GetRequestBodyBytes() int {
	return defaultInt(l.RequestBodyBytes, oidcDCRDefaultRequestBodyBytes)
}

// GetRedirectURIs returns the maximum number of registered redirect URIs.
func (l OIDCDynamicClientRegistrationLimits) GetRedirectURIs() int {
	return defaultInt(l.RedirectURIs, oidcDCRDefaultRedirectURIs)
}

// GetScopes returns the maximum number of requested scopes.
func (l OIDCDynamicClientRegistrationLimits) GetScopes() int {
	return defaultInt(l.Scopes, oidcDCRDefaultScopes)
}

// withDefaults materializes effective registration limits without mutating operator input.
func (l OIDCDynamicClientRegistrationLimits) withDefaults() OIDCDynamicClientRegistrationLimits {
	l.RequestBodyBytes = defaultInt(l.RequestBodyBytes, oidcDCRDefaultRequestBodyBytes)
	l.RedirectURIs = defaultInt(l.RedirectURIs, oidcDCRDefaultRedirectURIs)
	l.Scopes = defaultInt(l.Scopes, oidcDCRDefaultScopes)
	l.ClientNameRunes = defaultInt(l.ClientNameRunes, oidcDCRDefaultClientNameRunes)
	l.StringBytes = defaultInt(l.StringBytes, oidcDCRDefaultStringBytes)
	l.ActiveClients = defaultInt(l.ActiveClients, oidcDCRDefaultActiveClients)
	l.SourceWindow = defaultDuration(l.SourceWindow, oidcDCRDefaultSourceWindow)
	l.SourceRegistrations = defaultInt(l.SourceRegistrations, oidcDCRDefaultSourceRegistrations)
	l.SourceDailyRegistrations = defaultInt(l.SourceDailyRegistrations, oidcDCRDefaultSourceDaily)
	l.GlobalWindow = defaultDuration(l.GlobalWindow, oidcDCRDefaultGlobalWindow)
	l.GlobalRegistrations = defaultInt(l.GlobalRegistrations, oidcDCRDefaultGlobalRegistrations)

	return l
}

// GetUnusedTTL returns the lifetime of a never-used dynamic client.
func (l OIDCDynamicClientRegistrationLifecycle) GetUnusedTTL() time.Duration {
	return defaultDuration(l.UnusedTTL, oidcDCRDefaultUnusedTTL)
}

// GetMaximumTTL returns the absolute dynamic-client lifetime.
func (l OIDCDynamicClientRegistrationLifecycle) GetMaximumTTL() time.Duration {
	return defaultDuration(l.MaximumTTL, oidcDCRDefaultMaximumTTL)
}

// withDefaults materializes effective lifecycle values without mutating operator input.
func (l OIDCDynamicClientRegistrationLifecycle) withDefaults() OIDCDynamicClientRegistrationLifecycle {
	l.UnusedTTL = defaultDuration(l.UnusedTTL, oidcDCRDefaultUnusedTTL)
	l.InactivityTTL = defaultDuration(l.InactivityTTL, oidcDCRDefaultInactivityTTL)
	l.MaximumTTL = defaultDuration(l.MaximumTTL, oidcDCRDefaultMaximumTTL)
	l.TombstoneTTL = defaultDuration(l.TombstoneTTL, oidcDCRDefaultTombstoneTTL)

	return l
}

// defaultInt applies a default only to omitted integer values.
func defaultInt(value int, fallback int) int {
	if value == 0 {
		return fallback
	}

	return value
}

// defaultDuration applies a default only to omitted duration values.
func defaultDuration(value time.Duration, fallback time.Duration) time.Duration {
	if value == 0 {
		return fallback
	}

	return value
}

// validateIDPOIDCDynamicClientRegistration validates the restricted public-native profile.
func (f *FileSettings) validateIDPOIDCDynamicClientRegistration() error { //nolint:funlen,gocyclo
	if f == nil || f.IDP == nil {
		return nil
	}

	oidc := &f.IDP.OIDC
	registration := oidc.DynamicClientRegistration

	if !registration.Enabled {
		return nil
	}

	if !oidc.Enabled {
		return NewValidationProblem("identity.oidc.enabled", "must be enabled when dynamic client registration is enabled")
	}

	if err := validateOIDCDCRIssuer(oidc.Issuer); err != nil {
		return err
	}

	if registration.GetProfile() != oidcDCRProfileMailClientV1 {
		return NewValidationProblem("identity.oidc.dynamic_client_registration.profile", "must be mail-client-v1")
	}

	if registration.GetProfileVersion() != oidcDCRProfileVersion {
		return NewValidationProblem("identity.oidc.dynamic_client_registration.profile_version", "must be 1")
	}

	if registration.GetConsentMode() != oidcDCRConsentAllOrNothing {
		return NewValidationProblem("identity.oidc.dynamic_client_registration.consent_mode", "must be all_or_nothing")
	}

	if registration.SourceHMACKey.Len() < oidcDCRMinimumSourceHMACKeyBytes {
		return NewValidationProblem("identity.oidc.dynamic_client_registration.source_hmac_key", "must contain at least 32 bytes")
	}

	if err := validateOIDCDCRScopes(oidc, registration); err != nil {
		return err
	}

	if err := validateOIDCDCRLifetimes(registration); err != nil {
		return err
	}

	if err := validateOIDCDCRLimits(registration.GetLimits()); err != nil {
		return err
	}

	if err := validateOIDCDCRLifecycle(registration.GetLifecycle()); err != nil {
		return err
	}

	if !oidcDCRHasRS256Signer(oidc) {
		return NewValidationProblem("identity.oidc.signing_keys", "dynamic client registration requires an active RS256 signing capability")
	}

	if !slices.Contains(oidc.GetIDTokenSigningAlgValuesSupported(), oidcSigningAlgRS256) {
		return NewValidationProblem("identity.oidc.id_token_signing_alg_values_supported", "must include RS256 when dynamic client registration is enabled")
	}

	metadataRequirements := []struct {
		path   string
		values []string
		value  string
	}{
		{"response_types_supported", oidc.GetResponseTypesSupported(), oidcResponseTypeCode},
		{"subject_types_supported", oidc.GetSubjectTypesSupported(), oidcSubjectTypePublic},
		{"token_endpoint_auth_methods_supported", oidc.GetTokenEndpointAuthMethodsSupported(), oidcAuthMethodNone},
		{"code_challenge_methods_supported", oidc.GetCodeChallengeMethodsSupported(), "S256"},
	}

	for _, requirement := range metadataRequirements {
		if !slices.Contains(requirement.values, requirement.value) {
			return NewValidationProblem("identity.oidc."+requirement.path, fmt.Sprintf("must include %s when dynamic client registration is enabled", requirement.value))
		}
	}

	for index := range oidc.Clients {
		if strings.HasPrefix(oidc.Clients[index].ClientID, oidcDCRClientIDPrefix) {
			return NewValidationProblem(fmt.Sprintf("identity.oidc.clients[%d].client_id", index), "uses the reserved dcr_ prefix")
		}
	}

	return validateRequiredMFALevel(
		"identity.oidc.dynamic_client_registration.required_mfa_level",
		registration.RequiredMFALevel,
		nil,
		f.IDP.GetMFAPolicyLevels(),
	)
}

// validateOIDCDCRIssuer enforces an absolute HTTPS issuer without query or fragment.
func validateOIDCDCRIssuer(rawIssuer string) error {
	issuer, err := url.Parse(rawIssuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.RawQuery != "" || issuer.Fragment != "" || issuer.User != nil {
		return NewValidationProblem("identity.oidc.issuer", "must be an absolute HTTPS URL without userinfo, query, or fragment")
	}

	return nil
}

// validateOIDCDCRScopes enforces the deployment-owned dynamic scope allowlist.
func validateOIDCDCRScopes(oidc *OIDCConfig, registration OIDCDynamicClientRegistrationConfig) error { //nolint:gocyclo
	required, err := validateOIDCDCRScopeList("identity.oidc.dynamic_client_registration.required_scopes", registration.RequiredScopes)
	if err != nil {
		return err
	}

	if len(required) == 0 || !required[definitions.ScopeOpenID] {
		return NewValidationProblem("identity.oidc.dynamic_client_registration.required_scopes", "must include openid")
	}

	if required[definitions.ScopeOfflineAccess] {
		return NewValidationProblem("identity.oidc.dynamic_client_registration.required_scopes", "offline_access must remain optional")
	}

	optional, err := validateOIDCDCRScopeList("identity.oidc.dynamic_client_registration.optional_scopes", registration.OptionalScopes)
	if err != nil {
		return err
	}

	for scope := range optional {
		if required[scope] {
			return NewValidationProblem("identity.oidc.dynamic_client_registration.optional_scopes", fmt.Sprintf("scope %q also appears in required_scopes", scope))
		}
	}

	hasOfflineAccess := optional[definitions.ScopeOfflineAccess]
	if registration.AllowRefreshTokens != hasOfflineAccess {
		return NewValidationProblem("identity.oidc.dynamic_client_registration.optional_scopes", "offline_access must be present exactly when refresh tokens are enabled")
	}

	supported := make(map[string]bool, len(oidc.GetScopesSupported())+len(oidc.CustomScopes))
	for _, scope := range oidc.GetScopesSupported() {
		supported[scope] = true
	}

	for index := range oidc.CustomScopes {
		supported[oidc.CustomScopes[index].Name] = true
	}

	for scope := range required {
		if !supported[scope] {
			return NewValidationProblem("identity.oidc.dynamic_client_registration.required_scopes", fmt.Sprintf("scope %q is not supported by the provider", scope))
		}
	}

	for scope := range optional {
		if !supported[scope] {
			return NewValidationProblem("identity.oidc.dynamic_client_registration.optional_scopes", fmt.Sprintf("scope %q is not supported by the provider", scope))
		}
	}

	return nil
}

// validateOIDCDCRScopeList rejects empty, untrimmed, or duplicate scope names.
func validateOIDCDCRScopeList(path string, scopes []string) (map[string]bool, error) {
	result := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		if strings.TrimSpace(scope) != scope || !definitions.IsOAuthScopeToken(scope) {
			return nil, NewValidationProblem(path, "scope names must use the RFC 6749 scope-token syntax")
		}

		if result[scope] {
			return nil, NewValidationProblem(path, fmt.Sprintf("scope %q is duplicated", scope))
		}

		result[scope] = true
	}

	return result, nil
}

// validateOIDCDCRLifetimes enforces the profile token-lifetime ceilings.
func validateOIDCDCRLifetimes(registration OIDCDynamicClientRegistrationConfig) error {
	accessLifetime := registration.GetAccessTokenLifetime()
	if accessLifetime <= 0 || accessLifetime > oidcDCRMaximumAccessTokenLifetime {
		return NewValidationProblem("identity.oidc.dynamic_client_registration.access_token_lifetime", "must be positive and no greater than 15m")
	}

	refreshLifetime := registration.GetRefreshTokenLifetime()
	if registration.AllowRefreshTokens && (refreshLifetime <= 0 || refreshLifetime > oidcDCRMaximumRefreshTokenLifetime) {
		return NewValidationProblem("identity.oidc.dynamic_client_registration.refresh_token_lifetime", "must be positive and no greater than 720h")
	}

	return nil
}

// validateOIDCDCRLimits enforces positive limits and conservative implementation ceilings.
func validateOIDCDCRLimits(limits OIDCDynamicClientRegistrationLimits) error {
	integerLimits := []struct {
		path    string
		value   int
		maximum int
	}{
		{"request_body_bytes", limits.RequestBodyBytes, oidcDCRMaximumRequestBodyBytes},
		{"redirect_uris", limits.RedirectURIs, oidcDCRMaximumRedirectURIs},
		{"scopes", limits.Scopes, oidcDCRMaximumScopes},
		{"client_name_runes", limits.ClientNameRunes, oidcDCRMaximumClientNameRunes},
		{"string_bytes", limits.StringBytes, oidcDCRMaximumStringBytes},
		{"active_clients", limits.ActiveClients, oidcDCRMaximumActiveClients},
		{"source_registrations", limits.SourceRegistrations, oidcDCRMaximumActiveClients},
		{"source_daily_registrations", limits.SourceDailyRegistrations, oidcDCRMaximumActiveClients},
		{"global_registrations", limits.GlobalRegistrations, oidcDCRMaximumActiveClients},
	}

	for _, limit := range integerLimits {
		if limit.value <= 0 || limit.value > limit.maximum {
			return NewValidationProblem("identity.oidc.dynamic_client_registration.limits."+limit.path, fmt.Sprintf("must be positive and no greater than %d", limit.maximum))
		}
	}

	if limits.SourceWindow <= 0 || limits.SourceWindow > 24*time.Hour {
		return NewValidationProblem("identity.oidc.dynamic_client_registration.limits.source_window", "must be positive and no greater than 24h")
	}

	if limits.GlobalWindow <= 0 || limits.GlobalWindow > time.Hour {
		return NewValidationProblem("identity.oidc.dynamic_client_registration.limits.global_window", "must be positive and no greater than 1h")
	}

	return nil
}

// validateOIDCDCRLifecycle enforces positive and consistently ordered client lifetimes.
func validateOIDCDCRLifecycle(lifecycle OIDCDynamicClientRegistrationLifecycle) error {
	if lifecycle.MaximumTTL <= 0 || lifecycle.MaximumTTL > oidcDCRDefaultMaximumTTL {
		return NewValidationProblem("identity.oidc.dynamic_client_registration.lifecycle.maximum_ttl", "must be positive and no greater than 8760h")
	}

	values := []struct {
		path  string
		value time.Duration
	}{
		{"unused_ttl", lifecycle.UnusedTTL},
		{"inactivity_ttl", lifecycle.InactivityTTL},
		{"tombstone_ttl", lifecycle.TombstoneTTL},
	}

	for _, value := range values {
		if value.value <= 0 || value.value > lifecycle.MaximumTTL {
			return NewValidationProblem("identity.oidc.dynamic_client_registration.lifecycle."+value.path, "must be positive and no greater than maximum_ttl")
		}
	}

	return nil
}

// oidcDCRHasRS256Signer reports whether the provider can issue the fixed RS256 ID tokens.
func oidcDCRHasRS256Signer(oidc *OIDCConfig) bool {
	if oidc.AutoKeyRotation {
		return true
	}

	return slices.ContainsFunc(oidc.SigningKeys, func(key OIDCKey) bool {
		return key.Active && key.GetAlgorithm() == oidcSigningAlgRS256
	})
}
