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
	"slices"
	"strings"
)

const (
	defaultContentSecurityPolicy   = "default-src 'self'; script-src 'self' 'nonce-{{nonce}}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-src 'self' https:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self' https:"
	defaultStrictTransportSecurity = "max-age=31536000; includeSubDomains"
	defaultPermissionsPolicy       = "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
	cspFormActionDirectiveName     = "form-action"

	securityHeadersCSPKey         = "server.frontend.security_headers.content_security_policy"
	securityHeadersPermissionsKey = "server.frontend.security_headers.permissions_policy"
	securityHeadersSTSKey         = "server.frontend.security_headers.strict_transport_security"
)

type cspDirective struct {
	name    string
	sources []string
}

type permissionsDirective struct {
	feature string
	value   string
}

var defaultContentSecurityPolicyDirectives = []cspDirective{
	{name: "default-src", sources: []string{"'self'"}},
	{name: "script-src", sources: []string{"'self'", "'nonce-{{nonce}}'"}},
	{name: "style-src", sources: []string{"'self'", "'unsafe-inline'"}},
	{name: "img-src", sources: []string{"'self'", "data:"}},
	{name: "font-src", sources: []string{"'self'"}},
	{name: "connect-src", sources: []string{"'self'"}},
	{name: "frame-src", sources: []string{"'self'", "https:"}},
	{name: "object-src", sources: []string{"'none'"}},
	{name: "base-uri", sources: []string{"'none'"}},
	{name: "frame-ancestors", sources: []string{"'none'"}},
	{name: cspFormActionDirectiveName, sources: []string{"'self'", "https:"}},
}

var supportedContentSecurityPolicyDirectiveNames = collectSupportedCSPDirectiveNames()
var supportedContentSecurityPolicyDirectiveSet = buildSupportedCSPDirectiveSet()

var defaultPermissionsPolicyDirectives = []permissionsDirective{
	{feature: "geolocation", value: "()"},
	{feature: "microphone", value: "()"},
	{feature: "camera", value: "()"},
	{feature: "payment", value: "()"},
	{feature: "usb", value: "()"},
}

// SecurityHeaderComposer composes frontend security header values from strings, legacy list partials, or structured objects.
type SecurityHeaderComposer struct{}

// NewSecurityHeaderComposer creates a composer for frontend security headers.
func NewSecurityHeaderComposer() SecurityHeaderComposer {
	return SecurityHeaderComposer{}
}

// ComposeContentSecurityPolicy composes a CSP header from string, legacy list partials, or directive-map overrides.
// Missing directives are inherited from secure defaults.
func (SecurityHeaderComposer) ComposeContentSecurityPolicy(raw any, optionalFormActionURIs []string) (string, bool, error) {
	switch typed := raw.(type) {
	case nil:
		if len(optionalFormActionURIs) == 0 {
			return "", false, nil
		}

		return composeContentSecurityPolicyFromPartials(nil, optionalFormActionURIs), true, nil
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed != "" {
			return trimmed, true, nil
		}

		if len(optionalFormActionURIs) == 0 {
			return "", false, nil
		}

		return composeContentSecurityPolicyFromPartials(nil, optionalFormActionURIs), true, nil
	case []string:
		return composeContentSecurityPolicyFromPartials(typed, optionalFormActionURIs), true, nil
	case []any:
		directives, err := stringSliceFromAnySlice(typed, securityHeadersCSPKey)
		if err != nil {
			return "", false, err
		}

		return composeContentSecurityPolicyFromPartials(directives, optionalFormActionURIs), true, nil
	case map[string][]string:
		return composeContentSecurityPolicyFromDirectiveMap(typed, optionalFormActionURIs), true, nil
	default:
		return "", false, fmt.Errorf(
			"%s must be a string, list of strings, or directive map, got %T",
			securityHeadersCSPKey,
			raw,
		)
	}
}

// ComposePermissionsPolicy composes a Permissions-Policy header from string, legacy list partials, or feature-map overrides.
// Missing directives are inherited from secure defaults.
func (SecurityHeaderComposer) ComposePermissionsPolicy(raw any) (string, bool, error) {
	switch typed := raw.(type) {
	case nil:
		return "", false, nil
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return "", false, nil
		}

		return trimmed, true, nil
	case []string:
		return composePermissionsPolicyFromPartials(typed)
	case []any:
		directives, err := stringSliceFromAnySlice(typed, securityHeadersPermissionsKey)
		if err != nil {
			return "", false, err
		}

		return composePermissionsPolicyFromPartials(directives)
	case map[string]string:
		return composePermissionsPolicyFromFeatureMap(typed), true, nil
	default:
		return "", false, fmt.Errorf(
			"%s must be a string, list of strings, or feature map, got %T",
			securityHeadersPermissionsKey,
			raw,
		)
	}
}

// ComposeStrictTransportSecurity composes an HSTS header from string, legacy list partials, or structured object input.
// Secure defaults are kept for omitted values.
func (SecurityHeaderComposer) ComposeStrictTransportSecurity(raw any) (string, bool, error) {
	switch typed := raw.(type) {
	case nil:
		return "", false, nil
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return "", false, nil
		}

		return trimmed, true, nil
	case []string:
		return composeStrictTransportSecurityFromPartials(typed), true, nil
	case []any:
		parts, err := stringSliceFromAnySlice(typed, securityHeadersSTSKey)
		if err != nil {
			return "", false, err
		}

		return composeStrictTransportSecurityFromPartials(parts), true, nil
	case strictTransportSecurityObject:
		return composeStrictTransportSecurityFromObject(typed), true, nil
	default:
		return "", false, fmt.Errorf(
			"%s must be a string, list of strings, or object, got %T",
			securityHeadersSTSKey,
			raw,
		)
	}
}

// composeContentSecurityPolicyFromPartials builds a final CSP from partial directives and defaults.
func composeContentSecurityPolicyFromPartials(partials []string, optionalFormActionURIs []string) string {
	directives := cloneCSPDirectives(defaultContentSecurityPolicyDirectives)
	directiveIndices := indexCSPDirectives(directives)
	formActionOverridden := false

	for _, partial := range partials {
		for _, directivePart := range splitAndTrim(partial, ";") {
			fields := strings.Fields(directivePart)
			if len(fields) == 0 {
				continue
			}

			name := strings.ToLower(fields[0])
			normalizedName := normalizeCSPDirectiveName(name)
			if normalizedName == cspFormActionDirectiveName {
				formActionOverridden = true
			}

			directive := cspDirective{
				name:    name,
				sources: compactStringList(fields[1:]),
			}

			if index, found := directiveIndices[name]; found {
				directives[index] = directive
				continue
			}

			directiveIndices[name] = len(directives)
			directives = append(directives, directive)
		}
	}

	directives = finalizeFormActionDirective(directives, formActionOverridden, optionalFormActionURIs)

	return renderCSPDirectives(directives)
}

// composeContentSecurityPolicyFromDirectiveMap builds a final CSP from directive overrides and defaults.
func composeContentSecurityPolicyFromDirectiveMap(
	directiveOverrides map[string][]string,
	optionalFormActionURIs []string,
) string {
	directives := cloneCSPDirectives(defaultContentSecurityPolicyDirectives)
	directiveIndices := indexCSPDirectives(directives)
	extras := make([]cspDirective, 0)
	formActionOverridden := false

	for name, sources := range directiveOverrides {
		normalizedName := normalizeCSPDirectiveName(name)
		if normalizedName == cspFormActionDirectiveName {
			formActionOverridden = true
		}

		override := cspDirective{
			name:    normalizedName,
			sources: compactStringList(sources),
		}

		if index, found := directiveIndices[normalizedName]; found {
			directives[index] = override
			continue
		}

		extras = append(extras, override)
	}

	slices.SortFunc(extras, func(a cspDirective, b cspDirective) int {
		return strings.Compare(a.name, b.name)
	})

	directives = append(directives, extras...)
	directives = finalizeFormActionDirective(directives, formActionOverridden, optionalFormActionURIs)

	return renderCSPDirectives(directives)
}

// composePermissionsPolicyFromPartials builds a final Permissions-Policy from partial items and defaults.
func composePermissionsPolicyFromPartials(partials []string) (string, bool, error) {
	directives := clonePermissionsDirectives(defaultPermissionsPolicyDirectives)
	directiveIndices := indexPermissionsDirectives(directives)

	for _, partial := range partials {
		for _, directivePart := range splitAndTrim(partial, ",") {
			feature, value, err := parsePermissionsDirective(directivePart)
			if err != nil {
				return "", false, err
			}

			directive := permissionsDirective{
				feature: feature,
				value:   value,
			}

			if index, found := directiveIndices[feature]; found {
				directives[index] = directive
				continue
			}

			directiveIndices[feature] = len(directives)
			directives = append(directives, directive)
		}
	}

	return renderPermissionsPolicyDirectives(directives), true, nil
}

// composePermissionsPolicyFromFeatureMap builds a final Permissions-Policy from feature overrides and defaults.
func composePermissionsPolicyFromFeatureMap(featureOverrides map[string]string) string {
	directives := clonePermissionsDirectives(defaultPermissionsPolicyDirectives)
	directiveIndices := indexPermissionsDirectives(directives)
	extras := make([]permissionsDirective, 0)

	for name, value := range featureOverrides {
		featureName := strings.ToLower(strings.TrimSpace(name))
		directive := permissionsDirective{
			feature: featureName,
			value:   strings.TrimSpace(value),
		}

		if index, found := directiveIndices[featureName]; found {
			directives[index] = directive
			continue
		}

		extras = append(extras, directive)
	}

	slices.SortFunc(extras, func(a permissionsDirective, b permissionsDirective) int {
		return strings.Compare(a.feature, b.feature)
	})

	directives = append(directives, extras...)

	return renderPermissionsPolicyDirectives(directives)
}

// composeStrictTransportSecurityFromPartials builds a final HSTS header from partial tokens and defaults.
func composeStrictTransportSecurityFromPartials(partials []string) string {
	maxAge := "max-age=31536000"
	includeSubDomains := true
	preload := false

	customTokens := make([]string, 0)
	customSeen := make(map[string]struct{})

	for _, partial := range partials {
		for _, token := range splitAndTrim(partial, ";") {
			lowerToken := strings.ToLower(token)

			switch {
			case strings.HasPrefix(lowerToken, "max-age="):
				if strings.TrimSpace(token[len("max-age="):]) != "" {
					maxAge = token
				}
			case lowerToken == "includesubdomains":
				includeSubDomains = true
			case lowerToken == "preload":
				preload = true
			default:
				if _, seen := customSeen[token]; seen {
					continue
				}

				customSeen[token] = struct{}{}
				customTokens = append(customTokens, token)
			}
		}
	}

	tokens := []string{maxAge}

	if includeSubDomains {
		tokens = append(tokens, "includeSubDomains")
	}

	if preload {
		tokens = append(tokens, "preload")
	}

	tokens = append(tokens, customTokens...)

	return renderTokens(tokens, "; ")
}

// composeStrictTransportSecurityFromObject builds a final HSTS header from structured object input and defaults.
func composeStrictTransportSecurityFromObject(options strictTransportSecurityObject) string {
	maxAge := "max-age=31536000"
	includeSubDomains := true
	preload := false
	extraTokens := compactStringList(options.extraTokens)

	if options.maxAge != nil {
		trimmed := strings.TrimSpace(*options.maxAge)
		if trimmed != "" {
			maxAge = "max-age=" + trimmed
		}
	}

	if options.includeSubDomains != nil {
		includeSubDomains = *options.includeSubDomains
	}

	if options.preload != nil {
		preload = *options.preload
	}

	tokens := []string{maxAge}

	if includeSubDomains {
		tokens = append(tokens, "includeSubDomains")
	}

	if preload {
		tokens = append(tokens, "preload")
	}

	tokens = append(tokens, extraTokens...)

	return renderTokens(tokens, "; ")
}

// parsePermissionsDirective parses a single Permissions-Policy feature=value item.
func parsePermissionsDirective(raw string) (string, string, error) {
	parts := strings.SplitN(raw, "=", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("%s entry %q must contain '='", securityHeadersPermissionsKey, raw)
	}

	feature := strings.ToLower(strings.TrimSpace(parts[0]))
	if feature == "" {
		return "", "", fmt.Errorf("%s entry %q has an empty feature name", securityHeadersPermissionsKey, raw)
	}

	value := strings.TrimSpace(parts[1])
	if value == "" {
		return "", "", fmt.Errorf("%s entry %q has an empty value", securityHeadersPermissionsKey, raw)
	}

	return feature, value, nil
}

// finalizeFormActionDirective applies default/optional merge rules for the CSP form-action directive.
func finalizeFormActionDirective(
	directives []cspDirective,
	formActionOverridden bool,
	optionalFormActionURIs []string,
) []cspDirective {
	normalizedURIs := compactStringList(optionalFormActionURIs)
	formActionIndex := -1

	for index := range directives {
		if directives[index].name == cspFormActionDirectiveName {
			formActionIndex = index
			break
		}
	}

	if formActionIndex == -1 {
		defaultFormActionSources := []string{"'self'", "https:"}
		if len(normalizedURIs) > 0 {
			defaultFormActionSources = []string{"'self'"}
		}

		directives = append(directives, cspDirective{
			name:    cspFormActionDirectiveName,
			sources: defaultFormActionSources,
		})
		formActionIndex = len(directives) - 1
	}

	if len(normalizedURIs) == 0 {
		return directives
	}

	// Optional URI mode narrows the default by removing implicit https: unless admin explicitly set form-action.
	if !formActionOverridden {
		directives[formActionIndex].sources = removeStringFromSlice(directives[formActionIndex].sources, "https:")
	}

	for _, uri := range normalizedURIs {
		if stringSliceContains(directives[formActionIndex].sources, uri) {
			continue
		}

		directives[formActionIndex].sources = append(directives[formActionIndex].sources, uri)
	}

	return directives
}

func removeStringFromSlice(values []string, search string) []string {
	result := make([]string, 0, len(values))

	for _, value := range values {
		if value == search {
			continue
		}

		result = append(result, value)
	}

	return result
}

// stringSliceFromAnySlice converts []any with string elements into a deduplicated []string.
func stringSliceFromAnySlice(values []any, key string) ([]string, error) {
	result := make([]string, 0, len(values))

	for _, value := range values {
		strValue, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("%s must contain only strings, got %T", key, value)
		}

		trimmed := strings.TrimSpace(strValue)
		if trimmed == "" {
			continue
		}

		result = append(result, trimmed)
	}

	return compactStringList(result), nil
}

// splitAndTrim splits by separator and removes empty/whitespace-only entries.
func splitAndTrim(value string, separator string) []string {
	parts := strings.Split(value, separator)
	result := make([]string, 0, len(parts))

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}

		result = append(result, trimmed)
	}

	return result
}

// compactStringList trims values and removes empty and duplicate entries while preserving order.
func compactStringList(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))

	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}

		if _, found := seen[trimmed]; found {
			continue
		}

		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}

	return result
}

// cloneCSPDirectives returns a deep clone of CSP directives.
func cloneCSPDirectives(directives []cspDirective) []cspDirective {
	result := make([]cspDirective, 0, len(directives))

	for _, directive := range directives {
		cloned := cspDirective{
			name:    directive.name,
			sources: append([]string(nil), directive.sources...),
		}

		result = append(result, cloned)
	}

	return result
}

// clonePermissionsDirectives returns a shallow clone of Permissions-Policy directives.
func clonePermissionsDirectives(directives []permissionsDirective) []permissionsDirective {
	result := make([]permissionsDirective, 0, len(directives))
	result = append(result, directives...)

	return result
}

// indexCSPDirectives maps directive names to their index for replacement lookups.
func indexCSPDirectives(directives []cspDirective) map[string]int {
	index := make(map[string]int, len(directives))

	for i := range directives {
		index[directives[i].name] = i
	}

	return index
}

// indexPermissionsDirectives maps feature names to their index for replacement lookups.
func indexPermissionsDirectives(directives []permissionsDirective) map[string]int {
	index := make(map[string]int, len(directives))

	for i := range directives {
		index[directives[i].feature] = i
	}

	return index
}

// renderCSPDirectives renders normalized CSP directives into a header string.
func renderCSPDirectives(directives []cspDirective) string {
	var builder strings.Builder
	firstDirective := true

	for _, directive := range directives {
		name := strings.TrimSpace(directive.name)
		if name == "" {
			continue
		}

		if !firstDirective {
			builder.WriteString("; ")
		}

		firstDirective = false
		builder.WriteString(name)

		for _, source := range compactStringList(directive.sources) {
			builder.WriteByte(' ')
			builder.WriteString(source)
		}
	}

	return builder.String()
}

// renderPermissionsPolicyDirectives renders normalized Permissions-Policy directives into a header string.
func renderPermissionsPolicyDirectives(directives []permissionsDirective) string {
	var builder strings.Builder
	firstDirective := true

	for _, directive := range directives {
		feature := strings.TrimSpace(directive.feature)
		value := strings.TrimSpace(directive.value)
		if feature == "" || value == "" {
			continue
		}

		if !firstDirective {
			builder.WriteString(", ")
		}

		firstDirective = false
		builder.WriteString(feature)
		builder.WriteByte('=')
		builder.WriteString(value)
	}

	return builder.String()
}

// renderTokens renders tokens with a fixed separator, skipping empty/duplicate entries.
func renderTokens(tokens []string, separator string) string {
	var builder strings.Builder
	firstToken := true

	for _, token := range compactStringList(tokens) {
		if !firstToken {
			builder.WriteString(separator)
		}

		firstToken = false
		builder.WriteString(token)
	}

	return builder.String()
}

// stringSliceContains reports whether a string exists in the given slice.
func stringSliceContains(values []string, search string) bool {
	for _, value := range values {
		if value == search {
			return true
		}
	}

	return false
}

// collectSupportedCSPDirectiveNames returns the known CSP directive names in default order.
func collectSupportedCSPDirectiveNames() []string {
	result := make([]string, 0, len(defaultContentSecurityPolicyDirectives))

	for _, directive := range defaultContentSecurityPolicyDirectives {
		result = append(result, directive.name)
	}

	return result
}

// buildSupportedCSPDirectiveSet builds a lookup set for supported CSP directive names.
func buildSupportedCSPDirectiveSet() map[string]struct{} {
	result := make(map[string]struct{}, len(supportedContentSecurityPolicyDirectiveNames))

	for _, directiveName := range supportedContentSecurityPolicyDirectiveNames {
		result[directiveName] = struct{}{}
	}

	return result
}

// isSupportedContentSecurityPolicyDirective reports whether a directive is supported in CSP object mode.
func isSupportedContentSecurityPolicyDirective(directiveName string) bool {
	_, found := supportedContentSecurityPolicyDirectiveSet[directiveName]

	return found
}
