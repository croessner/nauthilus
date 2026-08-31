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
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/secret"
)

func TestOIDCDynamicClientRegistrationSecureDefaults(t *testing.T) {
	config := OIDCDynamicClientRegistrationConfig{}

	if got := config.GetProfile(); got != "mail-client-v1" {
		t.Fatalf("GetProfile() = %q, want mail-client-v1", got)
	}

	if got := config.GetProfileVersion(); got != 1 {
		t.Fatalf("GetProfileVersion() = %d, want 1", got)
	}

	if got := config.GetConsentMode(); got != "all_or_nothing" {
		t.Fatalf("GetConsentMode() = %q, want all_or_nothing", got)
	}

	if got := config.GetAccessTokenLifetime(); got != 15*time.Minute {
		t.Fatalf("GetAccessTokenLifetime() = %s, want 15m", got)
	}

	if got := config.GetRefreshTokenLifetime(); got != 30*24*time.Hour {
		t.Fatalf("GetRefreshTokenLifetime() = %s, want 720h", got)
	}

	limits := config.GetLimits()
	if limits.GetRequestBodyBytes() != 16_384 || limits.GetRedirectURIs() != 4 || limits.GetScopes() != 16 {
		t.Fatalf("GetLimits() returned unexpected request limits: %+v", limits)
	}

	lifecycle := config.GetLifecycle()
	if lifecycle.GetUnusedTTL() != 24*time.Hour || lifecycle.GetMaximumTTL() != 365*24*time.Hour {
		t.Fatalf("GetLifecycle() returned unexpected lifecycle defaults: %+v", lifecycle)
	}
}

func TestOIDCDynamicClientRegistrationStringRedactsSourceHMACKey(t *testing.T) {
	const sourceKey = "0123456789abcdef0123456789abcdef"

	config := OIDCDynamicClientRegistrationConfig{
		Enabled:       true,
		SourceHMACKey: secret.New(sourceKey),
	}

	got := config.String()
	if strings.Contains(got, sourceKey) {
		t.Fatal("String() exposed source_hmac_key")
	}

	if !strings.Contains(got, "SourceHMACKey:<hidden>") {
		t.Fatalf("String() = %q, want redacted source key marker", got)
	}
}

func TestValidateIDPOIDCDynamicClientRegistrationAcceptsValidProfile(t *testing.T) {
	settings := validOIDCDynamicClientRegistrationSettings()

	if err := settings.validateIDPOIDCDynamicClientRegistration(); err != nil {
		t.Fatalf("validateIDPOIDCDynamicClientRegistration() error = %v", err)
	}
}

func TestValidateIDPOIDCDynamicClientRegistrationDisabledHasNoRequirements(t *testing.T) {
	settings := &FileSettings{IDP: &IDPSection{}}

	if err := settings.validateIDPOIDCDynamicClientRegistration(); err != nil {
		t.Fatalf("validateIDPOIDCDynamicClientRegistration() error = %v", err)
	}
}

func TestValidateIDPOIDCDynamicClientRegistrationRejectsUnsafeProfiles(t *testing.T) { //nolint:funlen
	tests := []struct {
		mutate  func(*FileSettings)
		name    string
		wantErr string
	}{
		{
			name: "OIDC disabled",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.Enabled = false
			},
			wantErr: "identity.oidc.enabled",
		},
		{
			name: "non-HTTPS issuer",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.Issuer = "http://issuer.example.test"
			},
			wantErr: "identity.oidc.issuer",
		},
		{
			name: "issuer query",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.Issuer = "https://issuer.example.test?tenant=one"
			},
			wantErr: "identity.oidc.issuer",
		},
		{
			name: "unknown profile",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.DynamicClientRegistration.Profile = "broad-native-v1"
			},
			wantErr: "identity.oidc.dynamic_client_registration.profile",
		},
		{
			name: "unknown profile version",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.DynamicClientRegistration.ProfileVersion = 2
			},
			wantErr: "identity.oidc.dynamic_client_registration.profile_version",
		},
		{
			name: "short source key",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.DynamicClientRegistration.SourceHMACKey = secret.New("too-short")
			},
			wantErr: "identity.oidc.dynamic_client_registration.source_hmac_key",
		},
		{
			name: "missing openid scope",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.DynamicClientRegistration.RequiredScopes = []string{"profile"}
			},
			wantErr: "identity.oidc.dynamic_client_registration.required_scopes",
		},
		{
			name: "overlapping scopes",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.DynamicClientRegistration.OptionalScopes = []string{"openid", "offline_access"}
			},
			wantErr: "identity.oidc.dynamic_client_registration.optional_scopes",
		},
		{
			name: "unsupported scope",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.DynamicClientRegistration.OptionalScopes = []string{"offline_access", "mail:unknown"}
			},
			wantErr: "identity.oidc.dynamic_client_registration.optional_scopes",
		},
		{
			name: "invalid scope token",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.DynamicClientRegistration.OptionalScopes = []string{"offline_access", "unicode-ä"}
			},
			wantErr: "identity.oidc.dynamic_client_registration.optional_scopes",
		},
		{
			name: "offline access required",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.DynamicClientRegistration.RequiredScopes = []string{"openid", "offline_access"}
				settings.IDP.OIDC.DynamicClientRegistration.OptionalScopes = nil
			},
			wantErr: "identity.oidc.dynamic_client_registration.required_scopes",
		},
		{
			name: "refresh without offline access",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.DynamicClientRegistration.OptionalScopes = []string{"profile"}
			},
			wantErr: "identity.oidc.dynamic_client_registration.optional_scopes",
		},
		{
			name: "offline access while refresh disabled",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.DynamicClientRegistration.AllowRefreshTokens = false
			},
			wantErr: "identity.oidc.dynamic_client_registration.optional_scopes",
		},
		{
			name: "access token ceiling",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.DynamicClientRegistration.AccessTokenLifetime = 16 * time.Minute
			},
			wantErr: "identity.oidc.dynamic_client_registration.access_token_lifetime",
		},
		{
			name: "refresh token ceiling",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.DynamicClientRegistration.RefreshTokenLifetime = 31 * 24 * time.Hour
			},
			wantErr: "identity.oidc.dynamic_client_registration.refresh_token_lifetime",
		},
		{
			name: "invalid request limit",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.DynamicClientRegistration.Limits.RequestBodyBytes = -1
			},
			wantErr: "identity.oidc.dynamic_client_registration.limits.request_body_bytes",
		},
		{
			name: "invalid lifecycle ordering",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.DynamicClientRegistration.Lifecycle.InactivityTTL = 366 * 24 * time.Hour
			},
			wantErr: "identity.oidc.dynamic_client_registration.lifecycle.inactivity_ttl",
		},
		{
			name: "no RS256 signer",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.AutoKeyRotation = false
			},
			wantErr: "identity.oidc.signing_keys",
		},
		{
			name: "RS256 not advertised",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.IDTokenSigningAlgValuesSupported = []string{"EdDSA"}
			},
			wantErr: "identity.oidc.id_token_signing_alg_values_supported",
		},
		{
			name: "code response not advertised",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.ResponseTypesSupported = []string{"token"}
			},
			wantErr: "identity.oidc.response_types_supported",
		},
		{
			name: "public subject not advertised",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.SubjectTypesSupported = []string{"pairwise"}
			},
			wantErr: "identity.oidc.subject_types_supported",
		},
		{
			name: "none authentication not advertised",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.TokenEndpointAuthMethodsSupported = []string{"client_secret_basic"}
			},
			wantErr: "identity.oidc.token_endpoint_auth_methods_supported",
		},
		{
			name: "reserved static client prefix",
			mutate: func(settings *FileSettings) {
				settings.IDP.OIDC.Clients = []OIDCClient{{ClientID: "dcr_static-collision"}}
			},
			wantErr: "identity.oidc.clients[0].client_id",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			settings := validOIDCDynamicClientRegistrationSettings()
			test.mutate(settings)

			err := settings.validateIDPOIDCDynamicClientRegistration()
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateIDPOIDCDynamicClientRegistration() error = %v, want path containing %q", err, test.wantErr)
			}
		})
	}
}

// validOIDCDynamicClientRegistrationSettings returns a minimal valid native DCR profile.
func validOIDCDynamicClientRegistrationSettings() *FileSettings {
	return &FileSettings{
		IDP: &IDPSection{
			OIDC: OIDCConfig{
				Enabled:         true,
				Issuer:          "https://issuer.example.test",
				AutoKeyRotation: true,
				DynamicClientRegistration: OIDCDynamicClientRegistrationConfig{
					Enabled:            true,
					RequiredScopes:     []string{"openid"},
					OptionalScopes:     []string{"offline_access"},
					AllowRefreshTokens: true,
					SourceHMACKey:      secret.New("0123456789abcdef0123456789abcdef"),
				},
			},
		},
	}
}
