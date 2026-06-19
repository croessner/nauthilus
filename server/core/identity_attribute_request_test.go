// Copyright (C) 2026 Christian Roessner
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
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/stretchr/testify/assert"
)

const (
	identityAttributeMail                = "mail"
	identityAttributeDepartmentNumber    = "departmentNumber"
	identityAttributeEmployeeNumber      = "employeeNumber"
	identityClaimGroupDistinguishedNames = "group_dns"
	identityClaimResourceRole            = "resource.role"
	identityClaimUngranted               = "ungranted.claim"
	identityScopeResource                = "resource"
)

func TestOIDCIdentityAttributeRequestUsesGrantedScopes(t *testing.T) {
	client := &config.OIDCClient{
		ClientID: "claims-client",
		IDTokenClaims: config.IDTokenClaims{
			Mappings: []config.OIDCClaimMapping{
				{Claim: definitions.ClaimEmail, Attribute: identityAttributeMail, Type: definitions.ClaimTypeString},
				{Claim: definitions.ClaimGroups, From: definitions.ClaimGroups, Type: definitions.ClaimTypeStringArray},
				{Claim: identityClaimGroupDistinguishedNames, From: definitions.LuaBackendResultGroupDistinguishedNames, Type: definitions.ClaimTypeStringArray},
			},
		},
		AccessTokenClaims: config.AccessTokenClaims{
			Mappings: []config.OIDCClaimMapping{
				{Claim: identityClaimResourceRole, Attribute: identityAttributeDepartmentNumber, Type: definitions.ClaimTypeString},
				{Claim: identityClaimUngranted, Attribute: "employeeType", Type: definitions.ClaimTypeString},
			},
		},
	}
	customScopes := []config.Oauth2CustomScope{
		{
			Name: identityScopeResource,
			Claims: []config.OIDCCustomClaim{
				{Name: identityClaimResourceRole, Type: definitions.ClaimTypeString},
			},
		},
		{
			Name: "ungranted",
			Claims: []config.OIDCCustomClaim{
				{Name: identityClaimUngranted, Type: definitions.ClaimTypeString},
			},
		},
		{
			Name: definitions.ScopeGroups,
			Claims: []config.OIDCCustomClaim{
				{Name: identityClaimGroupDistinguishedNames, Type: definitions.ClaimTypeStringArray},
			},
		},
	}

	request := NewOIDCIdentityAttributeRequest(client, []string{
		definitions.ScopeOpenID,
		definitions.ScopeEmail,
		definitions.ScopeGroups,
		identityScopeResource,
	}, customScopes)

	assert.Equal(t, []string{identityAttributeDepartmentNumber, identityAttributeMail}, request.Names)
	assert.True(t, request.IncludeStandardIdentity)
	assert.True(t, request.IncludeGroups)
	assert.True(t, request.IncludeGroupDistinguishedNames)
	assert.True(t, request.ReportMissing)
}

func TestSAMLIdentityAttributeRequestUsesAllowedAttributeMapping(t *testing.T) {
	sp := &config.SAML2ServiceProvider{
		EntityID: "https://sp.example.test/metadata",
		AllowedAttributes: []string{
			identityAttributeMail,
			definitions.ClaimGroups,
			definitions.LuaBackendResultGroupDistinguishedNames,
			identityAttributeMail,
			identityAttributeEmployeeNumber,
		},
	}

	request := NewSAMLIdentityAttributeRequest(sp)

	assert.Equal(t, []string{identityAttributeEmployeeNumber, identityAttributeMail}, request.Names)
	assert.True(t, request.IncludeStandardIdentity)
	assert.True(t, request.IncludeGroups)
	assert.True(t, request.IncludeGroupDistinguishedNames)
	assert.True(t, request.ReportMissing)
}
