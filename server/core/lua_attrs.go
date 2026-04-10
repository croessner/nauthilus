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
	"strings"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/go-ldap/ldap/v3"
)

// flattenLuaAttributeValue recursively flattens a nested Lua attribute structure into a flat any slice.
func flattenLuaAttributeValue(value any) []any {
	if value == nil {
		return nil
	}

	switch typed := value.(type) {
	case []any:
		flattened := make([]any, 0, len(typed))
		for _, entry := range typed {
			flattened = append(flattened, flattenLuaAttributeValue(entry)...)
		}

		return flattened
	case []string:
		flattened := make([]any, len(typed))
		for index, entry := range typed {
			flattened[index] = entry
		}

		return flattened
	default:
		return []any{typed}
	}
}

// parseLuaGroupValues extracts group names and DNs from a slice of group strings.
func parseLuaGroupValues(values []string) (groups []string, groupDNs []string) {
	groups = make([]string, 0, len(values))
	groupDNs = make([]string, 0, len(values))

	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}

		if strings.Contains(trimmed, "=") && strings.Contains(trimmed, ",") {
			groupDNs = append(groupDNs, trimmed)

			parsed, err := ldap.ParseDN(trimmed)
			if err == nil && parsed != nil && len(parsed.RDNs) > 0 && len(parsed.RDNs[0].Attributes) > 0 {
				groups = append(groups, strings.TrimSpace(parsed.RDNs[0].Attributes[0].Value))

				continue
			}
		}

		groups = append(groups, trimmed)
	}

	return normalizeStringSet(groups), normalizeStringSet(groupDNs)
}

// buildAttributeMappingFromLua converts a Lua table (map) into a Go AttributeMapping and extracts groups.
func buildAttributeMappingFromLua(luaAttributes map[any]any) (attributes bktype.AttributeMapping, groups []string, groupDNs []string) {
	if luaAttributes == nil {
		return nil, nil, nil
	}

	attributes = make(bktype.AttributeMapping)

	for key, value := range luaAttributes {
		keyName, ok := key.(string)
		if !ok || strings.TrimSpace(keyName) == "" {
			continue
		}

		flattened := flattenLuaAttributeValue(value)
		if len(flattened) == 0 {
			continue
		}

		attributes[keyName] = flattened
	}

	groups = getNormalizedAttributeStrings(attributes, "groups")
	groupDNs = getNormalizedAttributeStrings(attributes, "group_dns")

	memberOfValues := getNormalizedAttributeStrings(attributes, "memberOf")
	if len(memberOfValues) > 0 {
		memberOfGroups, memberOfGroupDNs := parseLuaGroupValues(memberOfValues)
		groups = mergeNormalizedStringSlices(groups, memberOfGroups)
		groupDNs = mergeNormalizedStringSlices(groupDNs, memberOfGroupDNs)
	}

	return attributes, groups, groupDNs
}
