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
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
)

func TestOauth2CustomScope_NameValidation_AllowsScopeToken(t *testing.T) {
	validate := validator.New(validator.WithRequiredStructEnabled())
	validate.RegisterValidation("scope_token", isScopeToken)
	validate.RegisterValidation("oidc_claim_name", isOIDCClaimName)

	scope := Oauth2CustomScope{
		Name:        "custom:scope-v1",
		Description: "Custom scope description",
		Claims: []OIDCCustomClaim{
			{Name: "custom.claim", Type: "string"},
		},
	}

	err := validate.Struct(scope)
	assert.NoError(t, err)
}

func TestOauth2CustomScope_NameValidation_RejectsInvalidScopeToken(t *testing.T) {
	validate := validator.New(validator.WithRequiredStructEnabled())
	validate.RegisterValidation("scope_token", isScopeToken)
	validate.RegisterValidation("oidc_claim_name", isOIDCClaimName)

	scope := Oauth2CustomScope{
		Name:        "bad scope",
		Description: "Custom scope description",
		Claims: []OIDCCustomClaim{
			{Name: "custom.claim", Type: "string"},
		},
	}

	err := validate.Struct(scope)
	assert.Error(t, err)
}

func TestOIDCCustomClaim_NameValidation_AllowsUnicode(t *testing.T) {
	validate := validator.New(validator.WithRequiredStructEnabled())
	validate.RegisterValidation("oidc_claim_name", isOIDCClaimName)

	claim := OIDCCustomClaim{
		Name: "größe",
		Type: "string",
	}

	err := validate.Struct(claim)
	assert.NoError(t, err)
}
