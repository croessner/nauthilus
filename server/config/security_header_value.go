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
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// ContentSecurityPolicyValue stores CSP config as either a string, legacy partial list, or structured object.
type ContentSecurityPolicyValue struct {
	value                  string              `mapstructure:"-"`
	partials               []string            `mapstructure:"-"`
	directives             map[string][]string `mapstructure:"-"`
	formActionOptionalURIs []string            `mapstructure:"-"`
}

// NewContentSecurityPolicyValueFromString creates a CSP value from a plain string.
func NewContentSecurityPolicyValueFromString(value string) ContentSecurityPolicyValue {
	return ContentSecurityPolicyValue{
		value: strings.TrimSpace(value),
	}
}

// NewContentSecurityPolicyValueFromPartials creates a CSP value from legacy partial list input.
func NewContentSecurityPolicyValueFromPartials(partials []string) ContentSecurityPolicyValue {
	return ContentSecurityPolicyValue{
		partials: compactStringList(partials),
	}
}

// NewContentSecurityPolicyValueFromDirectives creates a CSP value from structured directive overrides.
func NewContentSecurityPolicyValueFromDirectives(directives map[string][]string, optionalURIs []string) ContentSecurityPolicyValue {
	clonedDirectives := make(map[string][]string, len(directives))

	for key, sources := range directives {
		normalizedKey := normalizeCSPDirectiveName(key)
		if normalizedKey == "" {
			continue
		}

		clonedDirectives[normalizedKey] = compactStringList(sources)
	}

	return ContentSecurityPolicyValue{
		directives:             clonedDirectives,
		formActionOptionalURIs: compactStringList(optionalURIs),
	}
}

// IsZero reports whether no CSP configuration was provided.
func (c ContentSecurityPolicyValue) IsZero() bool {
	return strings.TrimSpace(c.value) == "" &&
		len(c.partials) == 0 &&
		len(c.directives) == 0 &&
		len(c.formActionOptionalURIs) == 0
}

// PolicyInput returns the normalized payload for CSP composition.
func (c ContentSecurityPolicyValue) PolicyInput() any {
	if value := strings.TrimSpace(c.value); value != "" {
		return value
	}

	if len(c.directives) > 0 {
		cloned := make(map[string][]string, len(c.directives))

		for key, values := range c.directives {
			cloned[key] = append([]string(nil), values...)
		}

		return cloned
	}

	if len(c.partials) > 0 {
		return append([]string(nil), c.partials...)
	}

	return nil
}

// FormActionOptionalURIs returns optional form-action URIs configured with CSP object mode.
func (c ContentSecurityPolicyValue) FormActionOptionalURIs() []string {
	return append([]string(nil), c.formActionOptionalURIs...)
}

// String returns a compact representation suitable for generic string-based validation.
func (c ContentSecurityPolicyValue) String() string {
	if value := strings.TrimSpace(c.value); value != "" {
		return value
	}

	if len(c.partials) > 0 {
		return strings.Join(c.partials, "; ")
	}

	if len(c.directives) > 0 {
		keys := slices.Collect(maps.Keys(c.directives))
		slices.Sort(keys)

		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			values := compactStringList(c.directives[key])
			if len(values) == 0 {
				parts = append(parts, key)
				continue
			}

			parts = append(parts, key+" "+strings.Join(values, " "))
		}

		if len(c.formActionOptionalURIs) > 0 {
			parts = append(parts, "form_action_optional_uris "+strings.Join(c.formActionOptionalURIs, " "))
		}

		return strings.Join(parts, "; ")
	}

	return strings.Join(c.formActionOptionalURIs, " ")
}

// PermissionsPolicyValue stores Permissions-Policy config as either a string, legacy partial list, or structured object.
type PermissionsPolicyValue struct {
	value    string            `mapstructure:"-"`
	partials []string          `mapstructure:"-"`
	features map[string]string `mapstructure:"-"`
}

// NewPermissionsPolicyValueFromString creates a Permissions-Policy value from a plain string.
func NewPermissionsPolicyValueFromString(value string) PermissionsPolicyValue {
	return PermissionsPolicyValue{
		value: strings.TrimSpace(value),
	}
}

// NewPermissionsPolicyValueFromPartials creates a Permissions-Policy value from legacy partial list input.
func NewPermissionsPolicyValueFromPartials(partials []string) PermissionsPolicyValue {
	return PermissionsPolicyValue{
		partials: compactStringList(partials),
	}
}

// NewPermissionsPolicyValueFromFeatures creates a Permissions-Policy value from structured feature map input.
func NewPermissionsPolicyValueFromFeatures(features map[string]string) PermissionsPolicyValue {
	cloned := make(map[string]string, len(features))

	for key, value := range features {
		feature := strings.ToLower(strings.TrimSpace(key))
		if feature == "" {
			continue
		}

		featureValue := strings.TrimSpace(value)
		if featureValue == "" {
			continue
		}

		cloned[feature] = featureValue
	}

	return PermissionsPolicyValue{features: cloned}
}

// IsZero reports whether no Permissions-Policy configuration was provided.
func (p PermissionsPolicyValue) IsZero() bool {
	return strings.TrimSpace(p.value) == "" && len(p.partials) == 0 && len(p.features) == 0
}

// PolicyInput returns the normalized payload for Permissions-Policy composition.
func (p PermissionsPolicyValue) PolicyInput() any {
	if value := strings.TrimSpace(p.value); value != "" {
		return value
	}

	if len(p.features) > 0 {
		cloned := make(map[string]string, len(p.features))
		maps.Copy(cloned, p.features)

		return cloned
	}

	if len(p.partials) > 0 {
		return append([]string(nil), p.partials...)
	}

	return nil
}

// String returns a compact representation suitable for generic string-based validation.
func (p PermissionsPolicyValue) String() string {
	if value := strings.TrimSpace(p.value); value != "" {
		return value
	}

	if len(p.partials) > 0 {
		return strings.Join(p.partials, ", ")
	}

	if len(p.features) == 0 {
		return ""
	}

	keys := slices.Collect(maps.Keys(p.features))
	slices.Sort(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+p.features[key])
	}

	return strings.Join(parts, ", ")
}

type strictTransportSecurityObject struct {
	maxAge            *string  `mapstructure:"-"`
	includeSubDomains *bool    `mapstructure:"-"`
	preload           *bool    `mapstructure:"-"`
	extraTokens       []string `mapstructure:"-"`
}

// StrictTransportSecurityValue stores HSTS config as either a string, legacy partial list, or structured object.
type StrictTransportSecurityValue struct {
	value    string                         `mapstructure:"-"`
	partials []string                       `mapstructure:"-"`
	object   *strictTransportSecurityObject `mapstructure:"-"`
}

// NewStrictTransportSecurityValueFromString creates an HSTS value from a plain string.
func NewStrictTransportSecurityValueFromString(value string) StrictTransportSecurityValue {
	return StrictTransportSecurityValue{
		value: strings.TrimSpace(value),
	}
}

// NewStrictTransportSecurityValueFromPartials creates an HSTS value from legacy partial list input.
func NewStrictTransportSecurityValueFromPartials(partials []string) StrictTransportSecurityValue {
	return StrictTransportSecurityValue{
		partials: compactStringList(partials),
	}
}

// NewStrictTransportSecurityValueFromObject creates an HSTS value from structured object input.
func NewStrictTransportSecurityValueFromObject(
	maxAge *string,
	includeSubDomains *bool,
	preload *bool,
	extraTokens []string,
) StrictTransportSecurityValue {
	var clonedMaxAge *string

	if maxAge != nil {
		trimmed := strings.TrimSpace(*maxAge)
		clonedMaxAge = &trimmed
	}

	var clonedIncludeSubDomains *bool
	if includeSubDomains != nil {
		value := *includeSubDomains
		clonedIncludeSubDomains = &value
	}

	var clonedPreload *bool
	if preload != nil {
		value := *preload
		clonedPreload = &value
	}

	return StrictTransportSecurityValue{
		object: &strictTransportSecurityObject{
			maxAge:            clonedMaxAge,
			includeSubDomains: clonedIncludeSubDomains,
			preload:           clonedPreload,
			extraTokens:       compactStringList(extraTokens),
		},
	}
}

// IsZero reports whether no HSTS configuration was provided.
func (s StrictTransportSecurityValue) IsZero() bool {
	return strings.TrimSpace(s.value) == "" && len(s.partials) == 0 && s.object == nil
}

// PolicyInput returns the normalized payload for HSTS composition.
func (s StrictTransportSecurityValue) PolicyInput() any {
	if value := strings.TrimSpace(s.value); value != "" {
		return value
	}

	if s.object != nil {
		cloned := strictTransportSecurityObject{
			extraTokens: append([]string(nil), s.object.extraTokens...),
		}

		if s.object.maxAge != nil {
			value := *s.object.maxAge
			cloned.maxAge = &value
		}

		if s.object.includeSubDomains != nil {
			value := *s.object.includeSubDomains
			cloned.includeSubDomains = &value
		}

		if s.object.preload != nil {
			value := *s.object.preload
			cloned.preload = &value
		}

		return cloned
	}

	if len(s.partials) > 0 {
		return append([]string(nil), s.partials...)
	}

	return nil
}

// String returns a compact representation suitable for generic string-based validation.
func (s StrictTransportSecurityValue) String() string {
	if value := strings.TrimSpace(s.value); value != "" {
		return value
	}

	if len(s.partials) > 0 {
		return strings.Join(s.partials, "; ")
	}

	if s.object == nil {
		return ""
	}

	parts := make([]string, 0, 4+len(s.object.extraTokens))

	if s.object.maxAge != nil {
		parts = append(parts, "max-age="+*s.object.maxAge)
	}

	if s.object.includeSubDomains != nil {
		parts = append(parts, strconv.FormatBool(*s.object.includeSubDomains))
	}

	if s.object.preload != nil {
		parts = append(parts, strconv.FormatBool(*s.object.preload))
	}

	parts = append(parts, s.object.extraTokens...)

	return strings.Join(parts, "; ")
}

// processContentSecurityPolicyValue decodes CSP values from string, list, or object input.
func processContentSecurityPolicyValue(input any) (any, error) {
	switch data := input.(type) {
	case string:
		return NewContentSecurityPolicyValueFromString(data), nil
	case []string:
		return NewContentSecurityPolicyValueFromPartials(data), nil
	case []any:
		partials, err := stringSliceFromAnySlice(data, securityHeadersCSPKey)
		if err != nil {
			return nil, err
		}

		return NewContentSecurityPolicyValueFromPartials(partials), nil
	case map[string]any:
		return parseContentSecurityPolicyObject(data)
	case map[any]any:
		converted, err := mapAnyToStringAny(data, securityHeadersCSPKey)
		if err != nil {
			return nil, err
		}

		return parseContentSecurityPolicyObject(converted)
	default:
		return nil, fmt.Errorf("%s must be a string, list of strings, or object, got %T", securityHeadersCSPKey, data)
	}
}

// processPermissionsPolicyValue decodes Permissions-Policy values from string, list, or object input.
func processPermissionsPolicyValue(input any) (any, error) {
	switch data := input.(type) {
	case string:
		return NewPermissionsPolicyValueFromString(data), nil
	case []string:
		return NewPermissionsPolicyValueFromPartials(data), nil
	case []any:
		partials, err := stringSliceFromAnySlice(data, securityHeadersPermissionsKey)
		if err != nil {
			return nil, err
		}

		return NewPermissionsPolicyValueFromPartials(partials), nil
	case map[string]any:
		return parsePermissionsPolicyObject(data)
	case map[any]any:
		converted, err := mapAnyToStringAny(data, securityHeadersPermissionsKey)
		if err != nil {
			return nil, err
		}

		return parsePermissionsPolicyObject(converted)
	default:
		return nil, fmt.Errorf("%s must be a string, list of strings, or object, got %T", securityHeadersPermissionsKey, data)
	}
}

// processStrictTransportSecurityValue decodes HSTS values from string, list, or object input.
func processStrictTransportSecurityValue(input any) (any, error) {
	switch data := input.(type) {
	case string:
		return NewStrictTransportSecurityValueFromString(data), nil
	case []string:
		return NewStrictTransportSecurityValueFromPartials(data), nil
	case []any:
		partials, err := stringSliceFromAnySlice(data, securityHeadersSTSKey)
		if err != nil {
			return nil, err
		}

		return NewStrictTransportSecurityValueFromPartials(partials), nil
	case map[string]any:
		return parseStrictTransportSecurityObject(data)
	case map[any]any:
		converted, err := mapAnyToStringAny(data, securityHeadersSTSKey)
		if err != nil {
			return nil, err
		}

		return parseStrictTransportSecurityObject(converted)
	default:
		return nil, fmt.Errorf("%s must be a string, list of strings, or object, got %T", securityHeadersSTSKey, data)
	}
}

func parseContentSecurityPolicyObject(input map[string]any) (ContentSecurityPolicyValue, error) {
	directiveOverrides := make(map[string][]string)
	formActionOptionalURIs := make([]string, 0)

	for key, value := range input {
		normalizedKey := normalizeObjectConfigKey(key)

		switch normalizedKey {
		case "directives":
			directivesMap, err := toStringAnyMap(value, securityHeadersCSPKey+".directives")
			if err != nil {
				return ContentSecurityPolicyValue{}, err
			}

			for directiveName, directiveValue := range directivesMap {
				normalizedDirectiveName, err := parseKnownCSPDirectiveName(
					directiveName,
					securityHeadersCSPKey+".directives."+directiveName,
				)
				if err != nil {
					return ContentSecurityPolicyValue{}, err
				}

				sources, err := parseCSPDirectiveSources(directiveValue, securityHeadersCSPKey+".directives."+directiveName)
				if err != nil {
					return ContentSecurityPolicyValue{}, err
				}

				directiveOverrides[normalizedDirectiveName] = sources
			}
		case "form_action_optional_uris":
			uris, err := parseStringOrList(value, securityHeadersCSPKey+".form_action_optional_uris")
			if err != nil {
				return ContentSecurityPolicyValue{}, err
			}

			formActionOptionalURIs = append(formActionOptionalURIs, uris...)
		default:
			normalizedDirectiveName, err := parseKnownCSPDirectiveName(key, securityHeadersCSPKey+"."+key)
			if err != nil {
				return ContentSecurityPolicyValue{}, err
			}

			sources, err := parseCSPDirectiveSources(value, securityHeadersCSPKey+"."+key)
			if err != nil {
				return ContentSecurityPolicyValue{}, err
			}

			directiveOverrides[normalizedDirectiveName] = sources
		}
	}

	return NewContentSecurityPolicyValueFromDirectives(directiveOverrides, formActionOptionalURIs), nil
}

func parsePermissionsPolicyObject(input map[string]any) (PermissionsPolicyValue, error) {
	features := make(map[string]string)

	for key, value := range input {
		normalizedKey := normalizeObjectConfigKey(key)

		switch normalizedKey {
		case "features":
			featuresMap, err := toStringAnyMap(value, securityHeadersPermissionsKey+".features")
			if err != nil {
				return PermissionsPolicyValue{}, err
			}

			for featureName, featureValue := range featuresMap {
				parsedValue, err := parsePermissionsFeatureValue(
					featureValue,
					securityHeadersPermissionsKey+".features."+featureName,
				)
				if err != nil {
					return PermissionsPolicyValue{}, err
				}

				features[strings.ToLower(strings.TrimSpace(featureName))] = parsedValue
			}
		default:
			parsedValue, err := parsePermissionsFeatureValue(value, securityHeadersPermissionsKey+"."+key)
			if err != nil {
				return PermissionsPolicyValue{}, err
			}

			features[strings.ToLower(strings.TrimSpace(key))] = parsedValue
		}
	}

	return NewPermissionsPolicyValueFromFeatures(features), nil
}

func parseStrictTransportSecurityObject(input map[string]any) (StrictTransportSecurityValue, error) {
	var (
		maxAge            *string
		includeSubDomains *bool
		preload           *bool
		extraTokens       []string
	)

	for key, value := range input {
		switch normalizeObjectConfigKey(key) {
		case "max_age":
			parsedValue, err := parseMaxAgeValue(value, securityHeadersSTSKey+".max_age")
			if err != nil {
				return StrictTransportSecurityValue{}, err
			}

			maxAge = &parsedValue
		case "include_subdomains":
			parsedValue, ok := value.(bool)
			if !ok {
				return StrictTransportSecurityValue{}, fmt.Errorf(
					"%s.include_subdomains must be a bool, got %T",
					securityHeadersSTSKey,
					value,
				)
			}

			includeSubDomains = &parsedValue
		case "preload":
			parsedValue, ok := value.(bool)
			if !ok {
				return StrictTransportSecurityValue{}, fmt.Errorf("%s.preload must be a bool, got %T", securityHeadersSTSKey, value)
			}

			preload = &parsedValue
		case "extra_tokens":
			parsedValue, err := parseStringOrList(value, securityHeadersSTSKey+".extra_tokens")
			if err != nil {
				return StrictTransportSecurityValue{}, err
			}

			extraTokens = append(extraTokens, parsedValue...)
		default:
			return StrictTransportSecurityValue{}, fmt.Errorf("unknown %s object key %q", securityHeadersSTSKey, key)
		}
	}

	return NewStrictTransportSecurityValueFromObject(maxAge, includeSubDomains, preload, extraTokens), nil
}

func parseCSPDirectiveSources(value any, key string) ([]string, error) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return nil, nil
		}

		return compactStringList(strings.Fields(trimmed)), nil
	case []string:
		return compactStringList(typed), nil
	case []any:
		return stringSliceFromAnySlice(typed, key)
	default:
		return nil, fmt.Errorf("%s must be a string or list of strings, got %T", key, value)
	}
}

func parsePermissionsFeatureValue(value any, key string) (string, error) {
	switch typed := value.(type) {
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return "", fmt.Errorf("%s must not be empty", key)
		}

		return trimmed, nil
	default:
		return "", fmt.Errorf("%s must be a string, got %T", key, value)
	}
}

func parseMaxAgeValue(value any, key string) (string, error) {
	switch typed := value.(type) {
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return "", fmt.Errorf("%s must not be empty", key)
		}

		return trimmed, nil
	case int:
		return strconv.Itoa(typed), nil
	case int64:
		return strconv.FormatInt(typed, 10), nil
	case float64:
		return strconv.FormatInt(int64(typed), 10), nil
	default:
		return "", fmt.Errorf("%s must be a string or number, got %T", key, value)
	}
}

func parseStringOrList(value any, key string) ([]string, error) {
	switch typed := value.(type) {
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return nil, nil
		}

		return []string{trimmed}, nil
	case []string:
		return compactStringList(typed), nil
	case []any:
		return stringSliceFromAnySlice(typed, key)
	default:
		return nil, fmt.Errorf("%s must be a string or list of strings, got %T", key, value)
	}
}

func toStringAnyMap(value any, key string) (map[string]any, error) {
	switch typed := value.(type) {
	case map[string]any:
		return typed, nil
	case map[any]any:
		return mapAnyToStringAny(typed, key)
	default:
		return nil, fmt.Errorf("%s must be an object, got %T", key, value)
	}
}

func mapAnyToStringAny(input map[any]any, key string) (map[string]any, error) {
	converted := make(map[string]any, len(input))

	for rawKey, value := range input {
		stringKey, ok := rawKey.(string)
		if !ok {
			return nil, fmt.Errorf("%s must use string keys, got key type %T", key, rawKey)
		}

		converted[stringKey] = value
	}

	return converted, nil
}

func normalizeObjectConfigKey(key string) string {
	trimmed := strings.TrimSpace(strings.ToLower(key))
	trimmed = strings.ReplaceAll(trimmed, "-", "_")

	return trimmed
}

func normalizeCSPDirectiveName(name string) string {
	normalized := strings.ToLower(strings.TrimSpace(name))
	normalized = strings.ReplaceAll(normalized, "_", "-")

	if normalized == "form-actions" {
		return "form-action"
	}

	return normalized
}

func parseKnownCSPDirectiveName(name string, key string) (string, error) {
	normalizedName := normalizeCSPDirectiveName(name)
	if normalizedName == "" {
		return "", fmt.Errorf("%s must not be empty", key)
	}

	if isSupportedContentSecurityPolicyDirective(normalizedName) {
		return normalizedName, nil
	}

	return "", fmt.Errorf(
		"%s unknown directive %q; supported directives are: %s",
		key,
		name,
		strings.Join(supportedContentSecurityPolicyDirectiveNames, ", "),
	)
}
