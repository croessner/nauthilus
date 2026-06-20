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
	"slices"
	"strconv"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
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
func NewScopeManager(requestedScopes []string, customScopes []config.Oauth2CustomScope) *ScopeManager {
	claimDefinitions := standardClaimDefinitions()
	applyCustomClaimDefinitions(claimDefinitions, customScopes)

	return &ScopeManager{
		requested:   requestedScopeSet(requestedScopes),
		definitions: claimDefinitions,
	}
}

// requestedScopeSet converts requested scopes into lookup form.
func requestedScopeSet(requestedScopes []string) map[string]struct{} {
	requested := make(map[string]struct{}, len(requestedScopes))
	for _, scope := range requestedScopes {
		requested[scope] = struct{}{}
	}

	return requested
}

// standardClaimDefinitions returns built-in OIDC claim definitions.
func standardClaimDefinitions() map[string]claimDefinition {
	return map[string]claimDefinition{
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
}

// applyCustomClaimDefinitions merges configured custom scope claims.
func applyCustomClaimDefinitions(claimDefinitions map[string]claimDefinition, customScopes []config.Oauth2CustomScope) {
	for _, customScope := range customScopes {
		for _, customClaim := range customScope.Claims {
			mergeCustomClaimDefinition(claimDefinitions, customScope.Name, customClaim)
		}
	}
}

// mergeCustomClaimDefinition merges one custom claim definition.
func mergeCustomClaimDefinition(
	claimDefinitions map[string]claimDefinition,
	scopeName string,
	customClaim config.OIDCCustomClaim,
) {
	claimName := customClaim.GetName()
	if claimName == "" {
		return
	}

	claimType := customClaim.GetType()

	definition, exists := claimDefinitions[claimName]
	if !exists {
		claimDefinitions[claimName] = claimDefinition{
			Scopes:      []string{scopeName},
			DefaultType: claimType,
		}

		return
	}

	definition.Scopes = appendUnique(definition.Scopes, scopeName)
	if definition.DefaultType == "" {
		definition.DefaultType = claimType
	}

	claimDefinitions[claimName] = definition
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
func NewClaimManager(auth *AuthState, requestedScopes []string, customScopes []config.Oauth2CustomScope) *ClaimManager {
	if auth == nil {
		return &ClaimManager{}
	}

	return &ClaimManager{
		auth:   auth,
		scopes: NewScopeManager(requestedScopes, customScopes),
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
	if mapping.Claim == "" {
		return
	}

	if !m.scopes.AllowsClaim(mapping.Claim) {
		return
	}

	values, source, found := m.mappingValues(mapping)

	if !found || len(values) == 0 {
		m.warnClaimNotApplied(mapping.Claim, fmt.Sprintf("no value for %s", source))

		return
	}

	claimType := m.mappingClaimType(mapping)
	if claimType == "" {
		m.warnClaimNotApplied(mapping.Claim, "no claim type configured")

		return
	}

	converted, ok := convertClaimValues(claimType, values)
	if !ok {
		m.warnClaimNotApplied(mapping.Claim, fmt.Sprintf("unsupported value for %s", source))

		return
	}

	claims[mapping.Claim] = converted
}

// mappingValues resolves backend values and a log source for a claim mapping.
func (m *ClaimManager) mappingValues(mapping config.OIDCClaimMapping) ([]any, string, bool) {
	if mapping.Attribute != "" {
		values, found := m.auth.GetAttribute(mapping.Attribute)

		return values, fmt.Sprintf("attribute '%s'", mapping.Attribute), found
	}

	switch mapping.From {
	case definitions.ClaimGroups:
		values := stringsToAny(m.auth.GetGroups())

		return values, definitions.ClaimGroups, len(values) > 0
	case claimGroupDistinguishedNames:
		values := stringsToAny(m.auth.GetGroupDistinguishedNames())

		return values, claimGroupDistinguishedNames, len(values) > 0
	default:
		return nil, "", false
	}
}

// mappingClaimType returns the configured or default claim type.
func (m *ClaimManager) mappingClaimType(mapping config.OIDCClaimMapping) string {
	if mapping.Type != "" {
		return mapping.Type
	}

	return m.scopes.DefaultType(mapping.Claim)
}

// warnClaimNotApplied writes a consistent claim mapping warning.
func (m *ClaimManager) warnClaimNotApplied(claimName string, reason string) {
	m.auth.Logger().Warn(
		fmt.Sprintf("Claim '%s' not applied (%s)", claimName, reason),
		definitions.LogKeyGUID, m.auth.Runtime.GUID,
	)
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
	default:
		number, ok := numericFloat64Value(value)

		return number != 0, ok
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
	if typed, ok := value.(string); ok {
		parsed, err := strconv.ParseFloat(typed, 64)
		if err != nil {
			return 0, false
		}

		return parsed, true
	}

	return numericFloat64Value(value)
}

// numericFloat64Value converts numeric values to float64.
func numericFloat64Value(value any) (float64, bool) {
	if converted, ok := signedFloat64Value(value); ok {
		return converted, true
	}

	if converted, ok := unsignedFloat64Value(value); ok {
		return converted, true
	}

	return directFloat64Value(value)
}

// signedFloat64Value converts signed integer values to float64.
func signedFloat64Value(value any) (float64, bool) {
	switch typed := value.(type) {
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
	default:
		return 0, false
	}
}

// unsignedFloat64Value converts unsigned integer values to float64.
func unsignedFloat64Value(value any) (float64, bool) {
	switch typed := value.(type) {
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
	default:
		return 0, false
	}
}

// directFloat64Value converts floating-point values to float64.
func directFloat64Value(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
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
	if typed, ok := value.(string); ok {
		parsed, err := strconv.ParseInt(typed, 10, 64)
		if err != nil {
			return 0, false
		}

		return parsed, true
	}

	if converted, ok := signedIntegerValue(value); ok {
		return converted, true
	}

	if converted, ok := unsignedIntegerValue(value); ok {
		return converted, true
	}

	return floatIntegerValue(value)
}

// signedIntegerValue converts signed integer values to int64.
func signedIntegerValue(value any) (int64, bool) {
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
	default:
		return 0, false
	}
}

// unsignedIntegerValue converts unsigned integer values to int64.
func unsignedIntegerValue(value any) (int64, bool) {
	switch typed := value.(type) {
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
	default:
		return 0, false
	}
}

// floatIntegerValue converts integral floating-point values to int64.
func floatIntegerValue(value any) (int64, bool) {
	switch typed := value.(type) {
	case float32:
		floatValue := float64(typed)
		if math.Mod(floatValue, 1) != 0 {
			return 0, false
		}

		return int64(typed), true
	case float64:
		if math.Mod(typed, 1) != 0 {
			return 0, false
		}

		return int64(typed), true
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
		return map[string]any{claimAddressFormatted: typed}, true
	case []byte:
		return map[string]any{claimAddressFormatted: string(typed)}, true
	default:
		return objectValue(value)
	}
}

func appendUnique(values []string, entry string) []string {
	if slices.Contains(values, entry) {
		return values
	}

	return append(values, entry)
}
