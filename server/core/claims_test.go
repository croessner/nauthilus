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

package core

import (
	"log/slog"
	"os"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/stretchr/testify/assert"
)

func TestFillIDTokenClaims(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	auth := &AuthState{
		deps: AuthDeps{
			Logger: logger,
		},
	}
	auth.ReplaceAllAttributes(map[string][]any{
		"cn":             {"Max Mustermann"},
		"mail":           {"max@example.com"},
		"memberOf":       {"group1", "group2"},
		"email_verified": {"true"},
		"phone_verified": {true},
		"address":        {"Musterstraße 1"},
	})

	cfgClaims := &config.IDTokenClaims{
		Mappings: []config.OIDCClaimMapping{
			{Claim: definitions.ClaimName, Attribute: "cn", Type: definitions.ClaimTypeString},
			{Claim: definitions.ClaimEmail, Attribute: "mail", Type: definitions.ClaimTypeString},
			{Claim: definitions.ClaimGroups, Attribute: "memberOf", Type: definitions.ClaimTypeStringArray},
			{Claim: definitions.ClaimEmailVerified, Attribute: "email_verified", Type: definitions.ClaimTypeBoolean},
			{Claim: definitions.ClaimPhoneNumberVerified, Attribute: "phone_verified", Type: definitions.ClaimTypeBoolean},
			{Claim: definitions.ClaimAddress, Attribute: "address", Type: definitions.ClaimTypeAddress},
			{Claim: "my_custom_claim", Attribute: "custom_attr", Type: definitions.ClaimTypeString},
		},
	}

	auth.ReplaceAllAttributes(map[string][]any{
		"cn":             {"Max Mustermann"},
		"mail":           {"max@example.com"},
		"memberOf":       {"group1", "group2"},
		"email_verified": {"true"},
		"phone_verified": {true},
		"address":        {"Musterstraße 1"},
		"custom_attr":    {"custom_value"},
	})

	claims := make(map[string]any)
	auth.FillIDTokenClaims(cfgClaims, claims, nil, nil)

	assert.Equal(t, "Max Mustermann", claims[definitions.ClaimName])
	assert.Equal(t, "max@example.com", claims[definitions.ClaimEmail])
	assert.Equal(t, []string{"group1", "group2"}, claims[definitions.ClaimGroups])
	assert.Equal(t, true, claims[definitions.ClaimEmailVerified])
	assert.Equal(t, true, claims[definitions.ClaimPhoneNumberVerified])
	assert.Equal(t, "custom_value", claims["my_custom_claim"])

	address, ok := claims[definitions.ClaimAddress].(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "Musterstraße 1", address["formatted"])
}

func TestFillIDTokenClaims_WithCustomScopes(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	auth := &AuthState{
		deps: AuthDeps{
			Logger: logger,
			Cfg: &config.FileSettings{
				IDP: &config.IDPSection{
					OIDC: config.OIDCConfig{
						CustomScopes: []config.Oauth2CustomScope{
							{
								Name: "my_scope",
								Claims: []config.OIDCCustomClaim{
									{Name: "my_claim", Type: definitions.ClaimTypeString},
								},
							},
						},
					},
				},
			},
		},
	}
	auth.ReplaceAllAttributes(map[string][]any{
		"custom_attr": {"custom_value"},
	})

	cfgClaims := &config.IDTokenClaims{
		Mappings: []config.OIDCClaimMapping{
			{Claim: "my_claim", Attribute: "custom_attr", Type: definitions.ClaimTypeString},
		},
	}

	// 1. Without the scope
	claims := make(map[string]any)
	auth.FillIDTokenClaims(cfgClaims, claims, []string{"openid"}, auth.Cfg().GetIDP().OIDC.CustomScopes)
	assert.Nil(t, claims["my_claim"])

	// 2. With the scope
	claims = make(map[string]any)
	auth.FillIDTokenClaims(cfgClaims, claims, []string{"openid", "my_scope"}, auth.Cfg().GetIDP().OIDC.CustomScopes)
	assert.Equal(t, "custom_value", claims["my_claim"])
}

func TestFillIDTokenClaims_WithClientCustomScopeOverride(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg := &config.FileSettings{
		IDP: &config.IDPSection{
			OIDC: config.OIDCConfig{
				CustomScopes: []config.Oauth2CustomScope{
					{
						Name:        "my_scope",
						Description: "global scope",
						Claims: []config.OIDCCustomClaim{
							{Name: "global_claim", Type: definitions.ClaimTypeString},
						},
					},
				},
			},
		},
	}
	auth := &AuthState{
		deps: AuthDeps{
			Logger: logger,
			Cfg:    cfg,
		},
	}
	auth.ReplaceAllAttributes(map[string][]any{
		"global_attr": {"global_value"},
		"client_attr": {"client_value"},
	})

	cfgClaims := &config.IDTokenClaims{
		Mappings: []config.OIDCClaimMapping{
			{Claim: "global_claim", Attribute: "global_attr", Type: definitions.ClaimTypeString},
			{Claim: "client_claim", Attribute: "client_attr", Type: definitions.ClaimTypeString},
		},
	}

	client := &config.OIDCClient{
		ClientID: "client-1",
		CustomScopes: []config.Oauth2CustomScope{
			{
				Name:        "my_scope",
				Description: "client scope",
				Claims: []config.OIDCCustomClaim{
					{Name: "client_claim", Type: definitions.ClaimTypeString},
				},
			},
		},
	}

	effectiveCustomScopes := cfg.GetIDP().OIDC.GetEffectiveCustomScopes(client)

	claims := make(map[string]any)
	auth.FillIDTokenClaims(cfgClaims, claims, []string{"openid", "my_scope"}, effectiveCustomScopes)
	assert.Nil(t, claims["global_claim"])
	assert.Equal(t, "client_value", claims["client_claim"])
}

func TestFillIDTokenClaims_FromGroupsSource(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	auth := &AuthState{
		deps: AuthDeps{
			Logger: logger,
		},
	}
	auth.SetResolvedGroups(
		[]string{"developers", "platform"},
		[]string{"cn=developers,ou=groups,dc=example,dc=org"},
	)

	cfgClaims := &config.IDTokenClaims{
		Mappings: []config.OIDCClaimMapping{
			{Claim: definitions.ClaimGroups, From: "groups", Type: definitions.ClaimTypeStringArray},
			{Claim: "group_dns", From: "group_dns", Type: definitions.ClaimTypeStringArray},
		},
	}

	claims := make(map[string]any)
	auth.FillIDTokenClaims(cfgClaims, claims, []string{"openid", "groups"}, []config.Oauth2CustomScope{
		{
			Name: "groups",
			Claims: []config.OIDCCustomClaim{
				{Name: "group_dns", Type: definitions.ClaimTypeStringArray},
			},
		},
	})

	assert.Equal(t, []string{"developers", "platform"}, claims[definitions.ClaimGroups])
	assert.Equal(t, []string{"cn=developers,ou=groups,dc=example,dc=org"}, claims["group_dns"])
}

func TestReservedAccessTokenClaimMappingsAreRejected(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	auth := &AuthState{
		deps: AuthDeps{
			Logger: logger,
		},
	}
	auth.ReplaceAllAttributes(map[string][]any{
		"aud_attr":     {"evil-audience"},
		"active_attr":  {false},
		"custom_attr":  {"reader"},
		"exp_attr":     {int64(1)},
		"iat_attr":     {int64(1)},
		"iss_attr":     {"https://evil.example.test"},
		"scope_attr":   {"admin"},
		"subject_attr": {"attacker"},
	})

	claims := map[string]any{
		"aud":    "client-a",
		"active": true,
		"exp":    int64(200),
		"iat":    int64(100),
		"iss":    "https://issuer.example.test",
		"scope":  "openid profile",
		"sub":    "user-a",
	}
	cfgClaims := &config.AccessTokenClaims{
		Mappings: []config.OIDCClaimMapping{
			{Claim: "aud", Attribute: "aud_attr", Type: definitions.ClaimTypeString},
			{Claim: "active", Attribute: "active_attr", Type: definitions.ClaimTypeBoolean},
			{Claim: "scope", Attribute: "scope_attr", Type: definitions.ClaimTypeString},
			{Claim: "sub", Attribute: "subject_attr", Type: definitions.ClaimTypeString},
			{Claim: "iss", Attribute: "iss_attr", Type: definitions.ClaimTypeString},
			{Claim: "exp", Attribute: "exp_attr", Type: definitions.ClaimTypeInteger},
			{Claim: "iat", Attribute: "iat_attr", Type: definitions.ClaimTypeInteger},
			{Claim: "resource.role", Attribute: "custom_attr", Type: definitions.ClaimTypeString},
		},
	}

	auth.FillAccessTokenClaims(cfgClaims, claims, nil, nil)

	assert.Equal(t, "client-a", claims["aud"])
	assert.Equal(t, true, claims["active"])
	assert.Equal(t, "openid profile", claims["scope"])
	assert.Equal(t, "user-a", claims["sub"])
	assert.Equal(t, "https://issuer.example.test", claims["iss"])
	assert.Equal(t, int64(200), claims["exp"])
	assert.Equal(t, int64(100), claims["iat"])
	assert.Equal(t, "reader", claims["resource.role"])
}
