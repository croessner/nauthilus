// Copyright (C) 2024 Christian Rößner
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
	"sort"
	"strings"

	"github.com/croessner/nauthilus/server/backend/bktype"
)

// normalizeStringSet trims whitespace, removes empty strings and duplicates, and sorts the result.
func normalizeStringSet(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))

	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}

		if _, exists := seen[trimmed]; exists {
			continue
		}

		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}

	if len(normalized) == 0 {
		return nil
	}

	sort.Strings(normalized)

	return normalized
}

// anySliceToStrings converts a slice of any to a slice of strings, filtering for string and []byte types.
func anySliceToStrings(values []any) []string {
	if len(values) == 0 {
		return nil
	}

	result := make([]string, 0, len(values))

	for _, value := range values {
		switch typed := value.(type) {
		case string:
			result = append(result, typed)
		case []byte:
			result = append(result, string(typed))
		}
	}

	return normalizeStringSet(result)
}

// stringsToAny converts a slice of strings to a slice of any.
func stringsToAny(values []string) []any {
	if len(values) == 0 {
		return nil
	}

	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}

	return result
}

// getNormalizedAttributeStrings retrieves and normalizes a string attribute from an AttributeMapping.
func getNormalizedAttributeStrings(attributes bktype.AttributeMapping, key string) []string {
	if len(attributes) == 0 || key == "" {
		return nil
	}

	values, ok := attributes[key]
	if !ok || len(values) == 0 {
		return nil
	}

	return anySliceToStrings(values)
}

// mergeNormalizedStringSlices merges multiple string slices and normalizes the final result.
func mergeNormalizedStringSlices(base []string, additions ...[]string) []string {
	merged := make([]string, 0, len(base))
	merged = append(merged, base...)

	for _, add := range additions {
		merged = append(merged, add...)
	}

	return normalizeStringSet(merged)
}
