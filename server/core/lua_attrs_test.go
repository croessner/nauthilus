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
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestBuildAttributeMappingFromLuaFlattensAndExtractsGroups verifies that buildAttributeMappingFromLua
// correctly flattens nested Lua tables and extracts group names and DNs.
func TestBuildAttributeMappingFromLuaFlattensAndExtractsGroups(t *testing.T) {
	t.Parallel()

	luaAttributes := map[any]any{
		"groups": []any{"dev", "ops"},
		"group_dns": []any{
			"cn=legacy,ou=groups,dc=example,dc=com",
		},
		"roles":    []any{"platform"},
		"memberOf": []any{"cn=admins,ou=groups,dc=example,dc=com"},
		"nested":   []any{[]any{"a", "b"}},
	}

	attributes, groups, groupDNs := buildAttributeMappingFromLua(luaAttributes)

	assert.Equal(t, []string{"a", "b"}, anySliceToStrings(attributes["nested"]))
	assert.Equal(t, []string{"admins", "dev", "ops"}, groups)
	assert.Equal(t, []string{"cn=admins,ou=groups,dc=example,dc=com", "cn=legacy,ou=groups,dc=example,dc=com"}, groupDNs)
	assert.Equal(t, []string{"platform"}, anySliceToStrings(attributes["roles"]))
}
