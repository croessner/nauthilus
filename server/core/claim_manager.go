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
	"encoding/json"
	"fmt"
	"math"
	"strconv"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
)

// claimDefinition holds scope bindings and a default claim type for a claim name.
type claimDefinition struct {
	Scopes      []string
	DefaultType string
}

// ScopeManager evaluates whether claims are permitted by the requested scopes.
type ScopeManager struct {
	requested   map[string]struct{}
	definitions map[string]claimDefinition
}

// NewScopeManager constructs a ScopeManager from config and the requested scopes.
// It merges standard claim definitions with custom scope/claim definitions.
func NewScopeManager(cfg config.File, requestedScopes []string) *ScopeManager {
	requested := make(map[string]struct{}, len(requestedScopes))
	for _, scope := range requestedScopes {
		requested[scope] = struct{}{}
	}

	claimDefinitions := map[string]claimDefinition{
		definitions.ClaimName:              {Scopes: []string{definitions.ScopeProfile}, DefaultType: definitions.ClaimTypeString},
		definitions.ClaimGivenName:         {Scopes: []string{definitions.ScopeProfile}, DefaultType: definitions.ClaimTypeString},
		definitions.ClaimFamilyName:        {Scopes: []string{definitions.ScopeProfile}, DefaultType: definitions.ClaimTypeString},
		definitions.ClaimMiddleName:        {Scopes: []string{definitions.ScopeProfile}, DefaultType: definitions.ClaimTypeString},
		definitions.ClaimNickName:          {Scopes: []string{definitions.ScopeProfile}, DefaultType: definitions.ClaimTypeString},
		definitions.ClaimPreferredUserName: {Scopes: []string{definitions.ScopeProfile}, DefaultType: definitions.ClaimTypeString},
		definitions.ClaimProfile:           {Scopes: []string{definitions.ScopeProfile}, DefaultType: definitions.ClaimTypeString},
		definitions.ClaimWebsite:           {Scopes: []string{definitions.ScopeProfile}, DefaultType: definitions.ClaimTypeString},
		definitions.ClaimPicture:           {Scopes: []string{definitions.ScopeProfile}, DefaultType: definitions.ClaimTypeString},
		definitions.ClaimGender:            {Scopes: []string{definitions.ScopeProfile}, DefaultType: definitions.ClaimTypeString},
		definitions.ClaimBirtDate:          {Scopes: []string{definitions.ScopeProfile}, DefaultType: definitions.ClaimTypeString},
		definitions.ClaimZoneInfo:          {Scopes: []string{definitions.ScopeProfile}, DefaultType: definitions.ClaimTypeString},
		definitions.ClaimLocale:            {Scopes: []string{definitions.ScopeProfile}, DefaultType: definitions.ClaimTypeString},
		definitions.ClaimUpdatedAt:         {Scopes: []string{definitions.ScopeProfile}, DefaultType: definitions.ClaimTypeInteger},
		definitions.ClaimEmail:             {Scopes: []string{definitions.ScopeEmail}, DefaultType: definitions.ClaimTypeString},
		definitions.ClaimEmailVerified:     {Scopes: []string{definitions.ScopeEmail}, DefaultType: definitions.ClaimTypeBoolean},
		definitions.ClaimPhoneNumber:       {Scopes: []string{definitions.ScopePhone}, DefaultType: definitions.ClaimTypeString},
		definitions.ClaimPhoneNumberVerified: {
			Scopes:      []string{definitions.ScopePhone},
			DefaultType: definitions.ClaimTypeBoolean,
		},
		definitions.ClaimAddress: {Scopes: []string{definitions.ScopeAddress}, DefaultType: definitions.ClaimTypeAddress},
		definitions.ClaimGroups:  {Scopes: []string{definitions.ScopeGroups}, DefaultType: definitions.ClaimTypeStringArray},
	}

	if cfg != nil {
		for _, customScope := range cfg.GetIdP().OIDC.CustomScopes {
			for _, customClaim := range customScope.Claims {
				claimName := customClaim.GetName()
				if claimName == "" {
					continue
				}

				claimType := customClaim.GetType()
				definition, exists := claimDefinitions[claimName]
				if !exists {
					claimDefinitions[claimName] = claimDefinition{
						Scopes:      []string{customScope.Name},
						DefaultType: claimType,
					}

					continue
				}

				definition.Scopes = appendUnique(definition.Scopes, customScope.Name)
				if definition.DefaultType == "" {
					definition.DefaultType = claimType
				}

				claimDefinitions[claimName] = definition
			}
		}
	}

	return &ScopeManager{
		requested:   requested,
		definitions: claimDefinitions,
	}
}

// AllowsClaim reports whether a claim is allowed by any of the requested scopes.
func (s *ScopeManager) AllowsClaim(claimName string) bool {
	if len(s.requested) == 0 {
		return true
	}

	definition, exists := s.definitions[claimName]
	if !exists {
		return false
	}

	for _, scope := range definition.Scopes {
		if _, ok := s.requested[scope]; ok {
			return true
		}
	}

	return false
}

// DefaultType returns the default type for a claim name, if defined.
func (s *ScopeManager) DefaultType(claimName string) string {
	definition, exists := s.definitions[claimName]
	if !exists {
		return ""
	}

	return definition.DefaultType
}

// ClaimManager maps backend attributes to OIDC claims with scope/type handling.
type ClaimManager struct {
	auth   *AuthState
	scopes *ScopeManager
}

// NewClaimManager constructs a ClaimManager for the given AuthState and scopes.
func NewClaimManager(auth *AuthState, requestedScopes []string) *ClaimManager {
	if auth == nil {
		return &ClaimManager{}
	}

	return &ClaimManager{
		auth:   auth,
		scopes: NewScopeManager(auth.Cfg(), requestedScopes),
	}
}

// ApplyMappings applies configured claim mappings to the provided claims map.
func (m *ClaimManager) ApplyMappings(mappings []config.OIDCClaimMapping, claims map[string]any) {
	if m == nil || m.auth == nil {
		return
	}

	for _, mapping := range mappings {
		m.applyMapping(mapping, claims)
	}
}

func (m *ClaimManager) applyMapping(mapping config.OIDCClaimMapping, claims map[string]any) {
	if mapping.Claim == "" || mapping.Attribute == "" {
		return
	}

	if !m.scopes.AllowsClaim(mapping.Claim) {
		return
	}

	values, found := m.auth.GetAttribute(mapping.Attribute)
	if !found || len(values) == 0 {
		m.auth.Logger().Warn(
			fmt.Sprintf("Claim '%s' not applied (no value for attribute '%s')", mapping.Claim, mapping.Attribute),
			definitions.LogKeyGUID, m.auth.Runtime.GUID,
		)

		return
	}

	claimType := mapping.Type
	if claimType == "" {
		claimType = m.scopes.DefaultType(mapping.Claim)
	}

	if claimType == "" {
		m.auth.Logger().Warn(
			fmt.Sprintf("Claim '%s' not applied (no claim type configured)", mapping.Claim),
			definitions.LogKeyGUID, m.auth.Runtime.GUID,
		)

		return
	}

	converted, ok := convertClaimValues(claimType, values)
	if !ok {
		m.auth.Logger().Warn(
			fmt.Sprintf("Claim '%s' not applied (unsupported value for attribute '%s')", mapping.Claim, mapping.Attribute),
			definitions.LogKeyGUID, m.auth.Runtime.GUID,
		)

		return
	}

	claims[mapping.Claim] = converted
}

func convertClaimValues(claimType string, values []any) (any, bool) {
	switch claimType {
	case definitions.ClaimTypeString:
		return firstString(values)
	case definitions.ClaimTypeBoolean:
		return firstBool(values)
	case definitions.ClaimTypeFloat:
		return firstFloat(values)
	case definitions.ClaimTypeInteger:
		return firstInteger(values)
	case definitions.ClaimTypeStringArray:
		return stringArray(values)
	case definitions.ClaimTypeBooleanArray:
		return boolArray(values)
	case definitions.ClaimTypeFloatArray:
		return floatArray(values)
	case definitions.ClaimTypeIntegerArray:
		return integerArray(values)
	case definitions.ClaimTypeObject:
		return firstObject(values)
	case definitions.ClaimTypeAddress:
		return firstAddress(values)
	default:
		return nil, false
	}
}

func firstString(values []any) (string, bool) {
	for _, value := range values {
		if str, ok := stringValue(value); ok {
			return str, true
		}
	}

	return "", false
}

func stringArray(values []any) ([]string, bool) {
	result := make([]string, 0, len(values))
	for _, value := range values {
		str, ok := stringValue(value)
		if !ok {
			continue
		}

		result = append(result, str)
	}

	if len(result) == 0 {
		return nil, false
	}

	return result, true
}

func stringValue(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case []byte:
		return string(typed), true
	case fmt.Stringer:
		return typed.String(), true
	default:
		return "", false
	}
}

func firstBool(values []any) (bool, bool) {
	for _, value := range values {
		if converted, ok := boolValue(value); ok {
			return converted, true
		}
	}

	return false, false
}

func boolArray(values []any) ([]bool, bool) {
	result := make([]bool, 0, len(values))
	for _, value := range values {
		converted, ok := boolValue(value)
		if !ok {
			continue
		}

		result = append(result, converted)
	}

	if len(result) == 0 {
		return nil, false
	}

	return result, true
}

func boolValue(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		parsed, err := strconv.ParseBool(typed)
		if err != nil {
			return false, false
		}

		return parsed, true
	case int:
		return typed != 0, true
	case int8:
		return typed != 0, true
	case int16:
		return typed != 0, true
	case int32:
		return typed != 0, true
	case int64:
		return typed != 0, true
	case uint:
		return typed != 0, true
	case uint8:
		return typed != 0, true
	case uint16:
		return typed != 0, true
	case uint32:
		return typed != 0, true
	case uint64:
		return typed != 0, true
	case float32:
		return typed != 0, true
	case float64:
		return typed != 0, true
	default:
		return false, false
	}
}

func firstFloat(values []any) (float64, bool) {
	for _, value := range values {
		if converted, ok := floatValue(value); ok {
			return converted, true
		}
	}

	return 0, false
}

func floatArray(values []any) ([]float64, bool) {
	result := make([]float64, 0, len(values))
	for _, value := range values {
		converted, ok := floatValue(value)
		if !ok {
			continue
		}

		result = append(result, converted)
	}

	if len(result) == 0 {
		return nil, false
	}

	return result, true
}

func floatValue(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int8:
		return float64(typed), true
	case int16:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case uint:
		return float64(typed), true
	case uint8:
		return float64(typed), true
	case uint16:
		return float64(typed), true
	case uint32:
		return float64(typed), true
	case uint64:
		return float64(typed), true
	case string:
		parsed, err := strconv.ParseFloat(typed, 64)
		if err != nil {
			return 0, false
		}

		return parsed, true
	default:
		return 0, false
	}
}

func firstInteger(values []any) (int64, bool) {
	for _, value := range values {
		if converted, ok := integerValue(value); ok {
			return converted, true
		}
	}

	return 0, false
}

func integerArray(values []any) ([]int64, bool) {
	result := make([]int64, 0, len(values))
	for _, value := range values {
		converted, ok := integerValue(value)
		if !ok {
			continue
		}

		result = append(result, converted)
	}

	if len(result) == 0 {
		return nil, false
	}

	return result, true
}

func integerValue(value any) (int64, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int8:
		return int64(typed), true
	case int16:
		return int64(typed), true
	case int32:
		return int64(typed), true
	case int64:
		return typed, true
	case uint:
		return int64(typed), true
	case uint8:
		return int64(typed), true
	case uint16:
		return int64(typed), true
	case uint32:
		return int64(typed), true
	case uint64:
		return int64(typed), true
	case float32:
		if math.Mod(float64(typed), 1) != 0 {
			return 0, false
		}

		return int64(typed), true
	case float64:
		if math.Mod(typed, 1) != 0 {
			return 0, false
		}

		return int64(typed), true
	case string:
		parsed, err := strconv.ParseInt(typed, 10, 64)
		if err != nil {
			return 0, false
		}

		return parsed, true
	default:
		return 0, false
	}
}

func firstObject(values []any) (map[string]any, bool) {
	for _, value := range values {
		if converted, ok := objectValue(value); ok {
			return converted, true
		}
	}

	return nil, false
}

func objectValue(value any) (map[string]any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		return typed, true
	case map[string]string:
		converted := make(map[string]any, len(typed))
		for key, entry := range typed {
			converted[key] = entry
		}

		return converted, true
	case string:
		return unmarshalObject([]byte(typed))
	case []byte:
		return unmarshalObject(typed)
	default:
		return nil, false
	}
}

func unmarshalObject(data []byte) (map[string]any, bool) {
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, false
	}

	if len(parsed) == 0 {
		return nil, false
	}

	return parsed, true
}

func firstAddress(values []any) (map[string]any, bool) {
	for _, value := range values {
		if converted, ok := addressValue(value); ok {
			return converted, true
		}
	}

	return nil, false
}

func addressValue(value any) (map[string]any, bool) {
	switch typed := value.(type) {
	case string:
		return map[string]any{"formatted": typed}, true
	case []byte:
		return map[string]any{"formatted": string(typed)}, true
	default:
		return objectValue(value)
	}
}

func appendUnique(values []string, entry string) []string {
	for _, value := range values {
		if value == entry {
			return values
		}
	}

	return append(values, entry)
}
