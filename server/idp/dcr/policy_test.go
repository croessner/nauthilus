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

package dcr

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/go-viper/mapstructure/v2"
)

func TestRuntimePolicyNarrowsStoredDynamicClient(t *testing.T) {
	record := runtimePolicyTestRecord()
	policy := config.OIDCDynamicClientRegistrationConfig{
		Enabled:             true,
		RequiredScopes:      []string{"openid"},
		OptionalScopes:      []string{"mail:imap"},
		RequiredMFALevel:    2,
		AccessTokenLifetime: 5 * time.Minute,
	}

	client, err := NewRuntimePolicy(policy, config.DefaultMFAPolicyLevels()).Resolve(record)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	if client.SupportsGrantType(GrantRefreshToken) || slices.Contains(client.Scopes, "offline_access") {
		t.Fatalf("Resolve() retained disabled refresh capability: %+v", client)
	}

	if client.RequiredMFALevel != 2 || client.AccessTokenLifetime != 5*time.Minute {
		t.Fatalf("Resolve() did not apply current MFA and token ceilings: %+v", client)
	}

	if !client.Dynamic || client.DynamicProfile != ProfileMailClientV1 {
		t.Fatalf("Resolve() did not carry the registration profile: %+v", client)
	}
}

func TestRuntimePolicyAppliesProfileClaimsTokenTypeAndImpliedScopes(t *testing.T) {
	record := runtimePolicyTestRecord()
	record.Scope = "openid offline_access profile roles"
	mapping := []config.OIDCClaimMapping{{Claim: "roles", Attribute: "memberOf", Type: "string_array"}}
	policy := config.OIDCDynamicClientRegistrationConfig{
		Enabled:            true,
		RequiredScopes:     []string{"openid"},
		OptionalScopes:     []string{"offline_access", "profile", "roles", "groups"},
		ImpliedScopes:      []string{"roles", "groups"},
		AllowRefreshTokens: true,
		AccessTokenType:    "jwt",
		IDTokenClaims:      config.IDTokenClaims{Mappings: mapping},
		AccessTokenClaims:  config.AccessTokenClaims{Mappings: mapping},
	}

	client, err := NewRuntimePolicy(policy, config.DefaultMFAPolicyLevels()).Resolve(record)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	if client.GetAccessTokenType("opaque") != "jwt" {
		t.Fatalf("access token type = %q, want jwt", client.AccessTokenType)
	}

	if !slices.Equal(client.IDTokenClaims.GetMappings(), mapping) || !slices.Equal(client.AccessTokenClaims.GetMappings(), mapping) {
		t.Fatalf("Resolve() did not apply profile claim mappings: %+v", client)
	}

	// Implied scopes are limited to scopes registered for this client.
	if !slices.Equal(client.GetImpliedScopes(), []string{"roles"}) {
		t.Fatalf("implied scopes = %v, want registered subset [roles]", client.GetImpliedScopes())
	}

	policy.IDTokenClaims.Mappings[0].Claim = "mutated"
	if client.IDTokenClaims.GetMappings()[0].Claim != "roles" {
		t.Fatal("Resolve() shares claim mapping storage with the runtime policy")
	}
}

func TestRuntimePolicyAppliesProfileClientFlags(t *testing.T) {
	tests := []struct {
		set  func(*config.OIDCDynamicClientRegistrationConfig, bool)
		get  func(*config.OIDCClient) bool
		name string
	}{
		{
			name: "skip_consent",
			set:  func(p *config.OIDCDynamicClientRegistrationConfig, v bool) { p.SkipConsent = v },
			get:  func(c *config.OIDCClient) bool { return c.SkipConsent },
		},
		{
			name: "delayed_response",
			set:  func(p *config.OIDCDynamicClientRegistrationConfig, v bool) { p.DelayedResponse = v },
			get:  func(c *config.OIDCClient) bool { return c.IsDelayedResponse() },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := config.OIDCDynamicClientRegistrationConfig{
				Enabled:            true,
				RequiredScopes:     []string{"openid"},
				OptionalScopes:     []string{"offline_access", "mail:imap"},
				AllowRefreshTokens: true,
			}

			for _, enabled := range []bool{false, true} {
				test.set(&policy, enabled)

				client, err := NewRuntimePolicy(policy, config.DefaultMFAPolicyLevels()).Resolve(runtimePolicyTestRecord())
				if err != nil {
					t.Fatalf("Resolve() error = %v", err)
				}

				if got := test.get(client); got != enabled {
					t.Fatalf("Resolve() %s = %t, want %t", test.name, got, enabled)
				}
			}
		})
	}
}

func TestRuntimePolicyKeepsOpaqueTokensWithoutProfileOverrides(t *testing.T) {
	client, err := NewRuntimePolicy(config.OIDCDynamicClientRegistrationConfig{
		Enabled:            true,
		RequiredScopes:     []string{"openid"},
		OptionalScopes:     []string{"offline_access", "mail:imap"},
		AllowRefreshTokens: true,
	}, config.DefaultMFAPolicyLevels()).Resolve(runtimePolicyTestRecord())
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	if client.GetAccessTokenType("jwt") != "opaque" || len(client.IDTokenClaims.GetMappings()) != 0 || len(client.GetImpliedScopes()) != 0 {
		t.Fatalf("Resolve() = %+v, want opaque tokens without claims or implied scopes", client)
	}
}

func TestRuntimePolicyRejectsUnknownProfileVersion(t *testing.T) {
	record := runtimePolicyTestRecord()
	record.ProfileVersion++

	_, err := NewRuntimePolicy(config.OIDCDynamicClientRegistrationConfig{Enabled: true, RequiredScopes: []string{"openid"}}, config.DefaultMFAPolicyLevels()).Resolve(record)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Resolve() error = %v, want ErrCorrupt", err)
	}
}

// runtimePolicyTestRecord returns a formerly broader stored client.
func runtimePolicyTestRecord() *DynamicClientRecord {
	return &DynamicClientRecord{
		EffectiveMetadata: EffectiveMetadata{
			RedirectURIs:             []string{"http://127.0.0.1/callback"},
			GrantTypes:               []string{GrantAuthorizationCode, GrantRefreshToken},
			ResponseTypes:            []string{ResponseTypeCode},
			Scope:                    "openid offline_access mail:imap mail:smtp",
			TokenEndpointAuthMethod:  TokenEndpointAuthMethodNone,
			ApplicationType:          ApplicationTypeNative,
			SubjectType:              SubjectTypePublic,
			IDTokenSignedResponseAlg: IDTokenSigningAlgorithm,
		},
		ClientID:         ClientIDPrefix + "policy-client",
		Profile:          ProfileMailClientV1,
		ProfileVersion:   1,
		AccessTokenTTL:   15 * time.Minute,
		RefreshTokenTTL:  30 * 24 * time.Hour,
		RequiredMFALevel: 1,
	}
}

func TestRuntimePolicyAppliesMFAEnrollmentToExistingRegistration(t *testing.T) {
	policy := config.OIDCDynamicClientRegistrationConfig{Enabled: true, RequiredScopes: []string{"openid"}, RequiredMFALevel: 2}
	required := []string{"totp", "recovery_codes"}
	supported := []string{"totp", "webauthn", "recovery_codes"}

	if err := mapstructure.Decode(map[string]any{"require_mfa": required, "supported_mfa": supported}, &policy); err != nil {
		t.Fatal(err)
	}

	client, err := NewRuntimePolicy(policy, config.DefaultMFAPolicyLevels()).Resolve(runtimePolicyTestRecord())
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(client.GetRequireMFA(), required) || !slices.Equal(client.GetSupportedMFA(), supported) {
		t.Fatalf("existing registration lost enrollment policy: required=%v supported=%v", client.GetRequireMFA(), client.GetSupportedMFA())
	}
}

func TestRuntimePolicyChecksStoredMFAMinimumWithCurrentMethodLevels(t *testing.T) {
	tests := []struct {
		name    string
		levels  map[string]int
		wantErr bool
	}{
		{name: "stored level cannot be downgraded", levels: config.DefaultMFAPolicyLevels(), wantErr: true},
		{name: "operator method level override", levels: map[string]int{"totp": 3}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := runtimePolicyTestRecord()
			record.RequiredMFALevel = 3
			policy := config.OIDCDynamicClientRegistrationConfig{
				Enabled: true, RequiredScopes: []string{"openid"}, RequiredMFALevel: 2,
				RequireMFA: []string{"totp"}, SupportedMFA: []string{"totp"},
			}

			client, err := NewRuntimePolicy(policy, test.levels).Resolve(record)
			if test.wantErr {
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("Resolve() error = %v, want unavailable client", err)
				}

				return
			}

			if err != nil || client.RequiredMFALevel != 3 {
				t.Fatalf("stored minimum lost: client=%v err=%v", client, err)
			}
		})
	}
}
