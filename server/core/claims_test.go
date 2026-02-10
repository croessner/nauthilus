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

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/stretchr/testify/assert"
)

func TestFillIdTokenClaims(t *testing.T) {
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

	cfgClaims := &config.IdTokenClaims{
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
	auth.FillIdTokenClaims(cfgClaims, claims, nil)

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

func TestFillIdTokenClaims_WithCustomScopes(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	auth := &AuthState{
		deps: AuthDeps{
			Logger: logger,
			Cfg: &config.FileSettings{
				IdP: &config.IdPSection{
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

	cfgClaims := &config.IdTokenClaims{
		Mappings: []config.OIDCClaimMapping{
			{Claim: "my_claim", Attribute: "custom_attr", Type: definitions.ClaimTypeString},
		},
	}

	// 1. Without the scope
	claims := make(map[string]any)
	auth.FillIdTokenClaims(cfgClaims, claims, []string{"openid"})
	assert.Nil(t, claims["my_claim"])

	// 2. With the scope
	claims = make(map[string]any)
	auth.FillIdTokenClaims(cfgClaims, claims, []string{"openid", "my_scope"})
	assert.Equal(t, "custom_value", claims["my_claim"])
}
