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
func (a *AuthState) FillIdTokenClaims(cfgClaims *config.IdTokenClaims, claims map[string]any) {
	// Standard claims
	claimChecks := map[string]string{
		definitions.ClaimName:              cfgClaims.Name,
		definitions.ClaimGivenName:         cfgClaims.GivenName,
		definitions.ClaimFamilyName:        cfgClaims.FamilyName,
		definitions.ClaimMiddleName:        cfgClaims.MiddleName,
		definitions.ClaimNickName:          cfgClaims.NickName,
		definitions.ClaimPreferredUserName: cfgClaims.PreferredUserName,
		definitions.ClaimProfile:           cfgClaims.Profile,
		definitions.ClaimWebsite:           cfgClaims.Website,
		definitions.ClaimPicture:           cfgClaims.Picture,
		definitions.ClaimEmail:             cfgClaims.Email,
		definitions.ClaimGender:            cfgClaims.Gender,
		definitions.ClaimBirtDate:          cfgClaims.Birthdate,
		definitions.ClaimZoneInfo:          cfgClaims.ZoneInfo,
		definitions.ClaimLocale:            cfgClaims.Locale,
		definitions.ClaimPhoneNumber:       cfgClaims.PhoneNumber,
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

	claimKeys := map[string]string{
		definitions.ClaimEmailVerified:       cfgClaims.EmailVerified,
		definitions.ClaimPhoneNumberVerified: cfgClaims.PhoneNumberVerified,
		definitions.ClaimAddress:             cfgClaims.Address,
		definitions.ClaimUpdatedAt:           cfgClaims.UpdatedAt,
	}

	for claimKey, attrKey := range claimKeys {
		if attrKey != "" {
			ApplyClaim(claimKey, attrKey, a, claims, claimHandlers)
		}
	}

	// Groups claim
	if cfgClaims.Groups != "" {
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
}
