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

// Package presentation owns policy-selected client response normalization.
package presentation

import (
	"strings"
	"unicode"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/report"

	"golang.org/x/text/language"
)

// DefaultResponseMessageLength bounds unconfigured selected response messages.
const DefaultResponseMessageLength = 256

// DefaultResponseMessage maps one established response marker to its safe fallback.
func DefaultResponseMessage(marker string) *report.ResponseMessageSelection {
	message := ""

	switch marker {
	case policy.ResponseMarkerFail:
		message = definitions.PasswordFail
	case policy.ResponseMarkerTempFail:
		message = definitions.TempFailDefault
	case policy.ResponseMarkerTempFailNoTLS:
		message = definitions.TempFailNoTLS
	}

	if message == "" {
		return nil
	}

	return &report.ResponseMessageSelection{Source: "response_marker", Message: message}
}

// SanitizeResponseMessage removes unsafe controls and applies the configured byte bound.
func SanitizeResponseMessage(message string, maximum int) string {
	sanitized, _ := SanitizeResponseMessageWithState(message, maximum)

	return sanitized
}

// SanitizeResponseMessageWithState also reports whether the source was truncated.
func SanitizeResponseMessageWithState(message string, maximum int) (string, bool) {
	if maximum <= 0 {
		maximum = DefaultResponseMessageLength
	}

	builder := strings.Builder{}
	truncated := false

	for _, character := range message {
		if character == '\n' || character == '\r' || character == 0 {
			continue
		}

		if unicode.IsControl(character) && character != '\t' {
			continue
		}

		builder.WriteRune(character)

		if builder.Len() >= maximum {
			truncated = len(message) > builder.Len()

			break
		}
	}

	return builder.String(), truncated
}

// NormalizeResponseLanguage validates and canonicalizes one runtime BCP-47 value.
func NormalizeResponseLanguage(value string) (string, bool) {
	tag, err := language.Parse(strings.TrimSpace(value))
	if err != nil {
		return "", false
	}

	return tag.String(), true
}
