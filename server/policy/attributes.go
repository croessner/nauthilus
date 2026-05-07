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

package policy

import (
	"fmt"
	"strings"
)

const (
	// AttributeBruteForceBucketPrefix is the stable prefix for generated per-bucket facts.
	AttributeBruteForceBucketPrefix = "auth.brute_force.bucket."

	// AttributeRBLListPrefix is the stable prefix for generated per-RBL-list facts.
	AttributeRBLListPrefix = "auth.rbl.list."

	// AttributeSubjectAttributePrefix is the stable prefix for configured backend attribute exports.
	AttributeSubjectAttributePrefix = "auth.subject.attribute."
)

// IdentifierSegment normalizes a configuration name into one safe policy attribute path segment.
func IdentifierSegment(input string) string {
	var builder strings.Builder
	previousUnderscore := false

	for _, current := range strings.TrimSpace(input) {
		normalized, ok := identifierByte(current)
		if !ok {
			normalized = '_'
		}

		if normalized == '_' {
			if builder.Len() == 0 || previousUnderscore {
				previousUnderscore = true

				continue
			}

			previousUnderscore = true
			builder.WriteByte(normalized)

			continue
		}

		previousUnderscore = false
		builder.WriteByte(normalized)
	}

	result := strings.Trim(builder.String(), "_")
	if result == "" {
		result = "bucket"
	}

	if result[0] >= '0' && result[0] <= '9' {
		result = "b_" + result
	}

	return result
}

// BruteForceBucketAttributeID returns the generated policy attribute id for one bucket fact.
func BruteForceBucketAttributeID(bucketIdentifier string, suffix string) string {
	return fmt.Sprintf("%s%s.%s", AttributeBruteForceBucketPrefix, bucketIdentifier, suffix)
}

// RBLListAttributeID returns the generated policy attribute id for one RBL list fact.
func RBLListAttributeID(listIdentifier string, suffix string) string {
	return fmt.Sprintf("%s%s.%s", AttributeRBLListPrefix, listIdentifier, suffix)
}

// SubjectAttributeID returns the generated policy attribute id for one configured backend attribute export.
func SubjectAttributeID(attributeIdentifier string) string {
	return fmt.Sprintf("%s%s", AttributeSubjectAttributePrefix, attributeIdentifier)
}

func identifierByte(current rune) (byte, bool) {
	switch {
	case current >= 'a' && current <= 'z':
		return byte(current), true
	case current >= 'A' && current <= 'Z':
		return byte(current + ('a' - 'A')), true
	case current >= '0' && current <= '9':
		return byte(current), true
	case current == '_':
		return '_', true
	default:
		return 0, false
	}
}
