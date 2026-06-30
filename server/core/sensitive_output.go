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

package core

import (
	"strings"
	"unicode"

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/definitions"
)

const sensitiveOutputPasswordAttribute = "password"

var sensitiveOutputAttributeLeafNames = map[string]struct{}{
	"access_token":                   {},
	"api_token":                      {},
	"bind_pw":                        {},
	"client_private_key":             {},
	"client_secret":                  {},
	"connection_string":              {},
	"data_source_name":               {},
	"dsn":                            {},
	"encryption_secret":              {},
	"id_token":                       {},
	sensitiveOutputPasswordAttribute: {},
	"password_encoded":               {},
	"password_nonce":                 {},
	"private_key":                    {},
	"refresh_token":                  {},
	"static_token":                   {},
	"test_password":                  {},
	"token":                          {},
	"user_password":                  {},
	definitions.LuaBackendResultTOTPRecoveryField: {},
	definitions.LuaBackendResultTOTPSecretField:   {},
	definitions.LuaRequestTOTPRecoveryCodes:       {},
	definitions.SessionKeyRecoveryCodes:           {},
	definitions.SessionKeyTOTPSecret:              {},
}

var sensitiveOutputAttributeFragments = []string{
	"mfa_secret",
	"recovery_code",
	"totp_recovery",
	"totp_secret",
}

// IsSensitiveOutputAttribute reports whether an attribute name carries secret material.
// Configured names are matched exactly so deployment-specific MFA storage fields remain internal.
func IsSensitiveOutputAttribute(name string, configuredNames ...string) bool {
	normalized := normalizeSensitiveOutputAttributeName(name)
	if normalized == "" {
		return false
	}

	for _, configuredName := range configuredNames {
		if normalized == normalizeSensitiveOutputAttributeName(configuredName) {
			return true
		}
	}

	if _, found := sensitiveOutputAttributeLeafNames[normalized]; found {
		return true
	}

	for _, fragment := range sensitiveOutputAttributeFragments {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}

	return false
}

// FilterSensitiveOutputAttributes copies attributes while dropping secret-bearing fields.
func FilterSensitiveOutputAttributes(attributes bktype.AttributeMapping, configuredNames ...string) bktype.AttributeMapping {
	if len(attributes) == 0 {
		return attributes
	}

	filtered := make(bktype.AttributeMapping, len(attributes))
	for name, values := range attributes {
		if IsSensitiveOutputAttribute(name, configuredNames...) {
			continue
		}

		filtered[name] = append([]any(nil), values...)
	}

	return filtered
}

// normalizeSensitiveOutputAttributeName canonicalizes attribute names across case and word separators.
func normalizeSensitiveOutputAttributeName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}

	var normalized strings.Builder
	normalized.Grow(len(name))

	runes := []rune(name)
	lastSeparator := false

	for index, current := range runes {
		if isSensitiveOutputAttributeSeparator(current) {
			lastSeparator = appendSensitiveOutputAttributeSeparator(&normalized, lastSeparator)

			continue
		}

		if shouldSplitSensitiveOutputAttributeWord(runes, index, lastSeparator) {
			appendSensitiveOutputAttributeSeparator(&normalized, lastSeparator)
		}

		normalized.WriteRune(unicode.ToLower(current))

		lastSeparator = false
	}

	return strings.Trim(normalized.String(), "_")
}

// isSensitiveOutputAttributeSeparator reports whether a rune separates attribute name words.
func isSensitiveOutputAttributeSeparator(value rune) bool {
	return value == '-' || value == '_' || value == '.' || value == ':' || unicode.IsSpace(value)
}

// shouldSplitSensitiveOutputAttributeWord reports whether a camelCase boundary needs a separator.
func shouldSplitSensitiveOutputAttributeWord(runes []rune, index int, lastSeparator bool) bool {
	if index == 0 || lastSeparator || !unicode.IsUpper(runes[index]) {
		return false
	}

	previous := runes[index-1]
	nextIsLower := index+1 < len(runes) && unicode.IsLower(runes[index+1])

	return unicode.IsLower(previous) || unicode.IsDigit(previous) || unicode.IsUpper(previous) && nextIsLower
}

// appendSensitiveOutputAttributeSeparator appends one normalized separator when needed.
func appendSensitiveOutputAttributeSeparator(builder *strings.Builder, lastSeparator bool) bool {
	if builder.Len() == 0 || lastSeparator {
		return lastSeparator
	}

	builder.WriteByte('_')

	return true
}
