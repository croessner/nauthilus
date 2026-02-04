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
	"fmt"
	"reflect"
	"strconv"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/util"
)

// ClaimHandler is a helper struct for applying typed transformations to claims.
type ClaimHandler struct {
	Type      reflect.Kind
	ApplyFunc func(value any, claims map[string]any, claimKey string) bool
}

// ProcessClaim fills a single OIDC claim from a backend attribute.
func (a *AuthState) ProcessClaim(claimName string, claimValue string, claims map[string]any) {
	if claimValue == "" {
		return
	}

	if value, found := a.GetAttribute(claimValue); found {
		if len(value) > 0 {
			claims[claimName] = value[0]
		}
	} else {
		a.Logger().Warn(
			fmt.Sprintf("Claim '%s' not applied (no value for attribute '%s')", claimName, claimValue),
			definitions.LogKeyGUID, a.Runtime.GUID,
		)
	}
}

// ApplyClaim applies a list of handlers to a claim and an attribute.
func ApplyClaim(claimKey string, attributeKey string, auth *AuthState, claims map[string]any, claimHandlers []ClaimHandler) {
	value, found := auth.GetAttribute(attributeKey)
	if !found || len(value) == 0 {
		return
	}

	success := false

	for _, handler := range claimHandlers {
		if reflect.TypeOf(value[0]).Kind() == handler.Type {
			if handler.ApplyFunc(value[0], claims, claimKey) {
				success = true

				break
			}
		}
	}

	if !success {
		auth.Logger().Warn(
			fmt.Sprintf("Claim '%s' not applied (no value for attribute '%s')", claimKey, attributeKey),
			definitions.LogKeyGUID, auth.Runtime.GUID,
		)
	}
}

// FillIdTokenClaims populates a map of claims from IdTokenClaims configuration.
func (a *AuthState) FillIdTokenClaims(cfgClaims *config.IdTokenClaims, claims map[string]any, requestedScopes []string) {
	hasScope := func(s string) bool {
		if len(requestedScopes) == 0 {
			return true
		}

		for _, rs := range requestedScopes {
			if rs == s {
				return true
			}
		}

		return false
	}

	// Standard claims
	claimChecks := make(map[string]string)

	if hasScope(definitions.ScopeProfile) {
		claimChecks[definitions.ClaimName] = cfgClaims.Name
		claimChecks[definitions.ClaimGivenName] = cfgClaims.GivenName
		claimChecks[definitions.ClaimFamilyName] = cfgClaims.FamilyName
		claimChecks[definitions.ClaimMiddleName] = cfgClaims.MiddleName
		claimChecks[definitions.ClaimNickName] = cfgClaims.NickName
		claimChecks[definitions.ClaimPreferredUserName] = cfgClaims.PreferredUserName
		claimChecks[definitions.ClaimProfile] = cfgClaims.Profile
		claimChecks[definitions.ClaimWebsite] = cfgClaims.Website
		claimChecks[definitions.ClaimPicture] = cfgClaims.Picture
		claimChecks[definitions.ClaimGender] = cfgClaims.Gender
		claimChecks[definitions.ClaimBirtDate] = cfgClaims.Birthdate
		claimChecks[definitions.ClaimZoneInfo] = cfgClaims.ZoneInfo
		claimChecks[definitions.ClaimLocale] = cfgClaims.Locale
	}

	if hasScope(definitions.ScopeEmail) {
		claimChecks[definitions.ClaimEmail] = cfgClaims.Email
	}

	if hasScope(definitions.ScopePhone) {
		claimChecks[definitions.ClaimPhoneNumber] = cfgClaims.PhoneNumber
	}

	for claimName, claimVal := range claimChecks {
		a.ProcessClaim(claimName, claimVal, claims)
	}

	// Complex/typed claims
	claimHandlers := []ClaimHandler{
		{
			Type: reflect.String,
			ApplyFunc: func(value any, claims map[string]any, claimKey string) bool {
				if strValue, ok := value.(string); ok {
					if claimKey == definitions.ClaimEmailVerified || claimKey == definitions.ClaimPhoneNumberVerified {
						if boolean, err := strconv.ParseBool(strValue); err == nil {
							claims[claimKey] = boolean

							return true
						}
					} else if claimKey == definitions.ClaimAddress {
						claims[claimKey] = struct {
							Formatted string `json:"formatted"`
						}{Formatted: strValue}

						return true
					}
				}

				return false
			},
		},
		{
			Type: reflect.Bool,
			ApplyFunc: func(value any, claims map[string]any, claimKey string) bool {
				if boolValue, ok := value.(bool); ok {
					claims[claimKey] = boolValue

					return true
				}

				return false
			},
		},
		{
			Type: reflect.Float64,
			ApplyFunc: func(value any, claims map[string]any, claimKey string) bool {
				if floatValue, ok := value.(float64); ok {
					claims[claimKey] = floatValue

					return true
				}

				return false
			},
		},
	}

	claimKeys := make(map[string]string)

	if hasScope(definitions.ScopeEmail) {
		claimKeys[definitions.ClaimEmailVerified] = cfgClaims.EmailVerified
	}

	if hasScope(definitions.ScopePhone) {
		claimKeys[definitions.ClaimPhoneNumberVerified] = cfgClaims.PhoneNumberVerified
	}

	if hasScope(definitions.ScopeAddress) {
		claimKeys[definitions.ClaimAddress] = cfgClaims.Address
	}

	if hasScope(definitions.ScopeProfile) {
		claimKeys[definitions.ClaimUpdatedAt] = cfgClaims.UpdatedAt
	}

	for claimKey, attrKey := range claimKeys {
		if attrKey != "" {
			ApplyClaim(claimKey, attrKey, a, claims, claimHandlers)
		}
	}

	// Groups claim
	if cfgClaims.Groups != "" && hasScope(definitions.ScopeGroups) {
		if value, found := a.GetAttribute(cfgClaims.Groups); found {
			var stringSlice []string

			util.DebugModuleWithCfg(
				a.Ctx(),
				a.Cfg(),
				a.Logger(),
				definitions.DbgAuth,
				definitions.LogKeyGUID, a.Runtime.GUID,
				"groups", fmt.Sprintf("%#v", value),
			)

			for _, v := range value {
				if str, ok := v.(string); ok {
					stringSlice = append(stringSlice, str)
				}
			}

			if len(stringSlice) > 0 {
				claims[definitions.ClaimGroups] = stringSlice
			}
		}
	}

	// Custom scopes from config
	if a.Cfg() != nil {
		for _, customScope := range a.Cfg().GetIdP().OIDC.CustomScopes {
			if hasScope(customScope.Name) {
				for _, customClaim := range customScope.Claims {
					if attrName, ok := cfgClaims.CustomClaims[customClaim.Name].(string); ok {
						a.ProcessClaim(customClaim.Name, attrName, claims)
					}
				}
			}
		}
	}

	// Custom claims (direct mapping in client config)
	// We only include these if they haven't been filled by a specific scope yet,
	// and if no specific scopes were requested (legacy/compat).
	// If scopes are requested, custom claims must be associated with a scope to be included.
	if len(requestedScopes) == 0 {
		for claimName, claimAttr := range cfgClaims.CustomClaims {
			if attrName, ok := claimAttr.(string); ok {
				if _, exists := claims[claimName]; !exists {
					a.ProcessClaim(claimName, attrName, claims)
				}
			}
		}
	}
}
