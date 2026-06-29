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

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/definitions"
)

const sensitiveOutputPasswordAttribute = "password"

var sensitiveOutputAttributeLeafNames = map[string]struct{}{
	"access_token":                   {},
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

// normalizeSensitiveOutputAttributeName canonicalizes attribute names for case-insensitive matching.
func normalizeSensitiveOutputAttributeName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	name = strings.ReplaceAll(name, "-", "_")

	return name
}
