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

// Package identifier owns the canonical policy identifier grammar.
package identifier

import "strings"

const (
	maximumFactLength       = 192
	maximumTargetPartLength = 64
	maximumQualifiedLength  = 128
)

// Namespace reports whether value is a canonical policy namespace.
func Namespace(value string) bool {
	return segmented(value, '.', false, maximumTargetPartLength)
}

// Action reports whether value is a canonical policy action or schema local name.
func Action(value string) bool {
	if len(value) == 0 || len(value) > maximumTargetPartLength {
		return false
	}

	separator := false

	for index := range len(value) {
		current := value[index]

		switch {
		case wordCharacter(current):
			separator = false
		case current == '-' || current == '_':
			if index == 0 || index == len(value)-1 || separator {
				return false
			}

			separator = true
		default:
			return false
		}
	}

	return true
}

// Fact reports whether value is a bounded canonical dotted fact identity.
func Fact(value string) bool {
	if len(value) == 0 || len(value) > maximumFactLength {
		return false
	}

	segments := strings.Split(value, ".")
	if len(segments) < 2 {
		return false
	}

	for _, segmentValue := range segments {
		if !segment(segmentValue, true) {
			return false
		}
	}

	return true
}

// Provider reports whether value is one canonical provider-owner segment.
func Provider(value string) bool {
	return segment(value, true)
}

// ProviderIdentity reports whether value is one canonical namespace/provider identity.
func ProviderIdentity(value string) bool {
	if len(value) == 0 || len(value) > maximumQualifiedLength {
		return false
	}

	namespace, local, found := strings.Cut(value, "/")
	if !found || !Namespace(namespace) || local == "" {
		return false
	}

	if strings.Contains(local, "/") {
		return providerSlashIdentity(local)
	}

	return segmented(local, '.', true, maximumQualifiedLength)
}

// Qualified reports whether value is one exact namespace/local-name identity.
func Qualified(value string) bool {
	if len(value) == 0 || len(value) > maximumQualifiedLength || strings.Count(value, "/") != 1 {
		return false
	}

	parts := strings.SplitN(value, "/", 2)

	return Namespace(parts[0]) && Action(parts[1])
}

// AuthnPluginEffect reports whether value uses the narrow authn/plugin.<module>.<component> effect form.
func AuthnPluginEffect(value string) bool {
	const prefix = "authn/plugin."
	if len(value) == 0 || len(value) > maximumQualifiedLength || !strings.HasPrefix(value, prefix) {
		return false
	}

	local := strings.TrimPrefix(value, prefix)
	parts := strings.Split(local, ".")

	return len(parts) == 2 && Provider(parts[0]) && Provider(parts[1])
}

// providerSlashIdentity validates the canonical owner/name provider form without mixed delimiters.
func providerSlashIdentity(value string) bool {
	if strings.Count(value, "/") != 1 || strings.Contains(value, ".") {
		return false
	}

	owner, name, _ := strings.Cut(value, "/")

	return Provider(owner) && Provider(name)
}

// Diagnostic reports whether value is a bounded target-local public alias.
func Diagnostic(value string) bool {
	return Action(value)
}

// segmented validates a bounded identifier composed of canonical segments.
func segmented(value string, delimiter byte, allowHyphen bool, maximumLength int) bool {
	if len(value) == 0 || len(value) > maximumLength {
		return false
	}

	segments := strings.Split(value, string(delimiter))
	for _, segmentValue := range segments {
		if !segment(segmentValue, allowHyphen) {
			return false
		}
	}

	return true
}

// segment validates one lowercase ASCII identifier segment.
func segment(value string, allowHyphen bool) bool {
	if value == "" {
		return false
	}

	for index := range len(value) {
		current := value[index]
		if wordCharacter(current) || current == '_' {
			continue
		}

		if allowHyphen && current == '-' {
			continue
		}

		return false
	}

	return true
}

// wordCharacter reports whether current is a lowercase ASCII word byte.
func wordCharacter(current byte) bool {
	return current >= 'a' && current <= 'z' || current >= '0' && current <= '9'
}
