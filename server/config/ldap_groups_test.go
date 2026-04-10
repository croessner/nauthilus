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

package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestLDAPSearchProtocolGetAttributesIncludesMemberOfAttribute ensures that the memberOf attribute
// is included in the LDAP search attributes when the member_of strategy is used.
func TestLDAPSearchProtocolGetAttributesIncludesMemberOfAttribute(t *testing.T) {
	t.Parallel()

	protocol := &LDAPSearchProtocol{
		LDAPAttributeMapping: LDAPAttributeMapping{
			AccountField: "uid",
		},
		Attributes: []string{"mail"},
		Groups: LDAPGroups{
			Strategy:  "member_of",
			Attribute: "memberOf",
		},
	}

	attributes, err := protocol.GetAttributes()
	assert.NoError(t, err)
	assert.Contains(t, attributes, "uid")
	assert.Contains(t, attributes, "mail")
	assert.Contains(t, attributes, "memberOf")
}

// TestLDAPGroupsStrategyDefaults verifies the default strategy selection and attribute defaults
// for LDAP group configuration.
func TestLDAPGroupsStrategyDefaults(t *testing.T) {
	t.Parallel()

	groupsWithFilter := &LDAPGroups{
		Filter: "(member=%{user_dn})",
	}
	assert.Equal(t, "search", groupsWithFilter.GetStrategy())

	groupsWithAttribute := &LDAPGroups{
		Attribute: "memberOf",
	}
	assert.Equal(t, "member_of", groupsWithAttribute.GetStrategy())
	assert.Equal(t, "memberOf", groupsWithAttribute.GetAttribute())
	assert.Equal(t, "cn", groupsWithAttribute.GetNameAttribute())
	assert.Equal(t, 4, groupsWithAttribute.GetMaxDepth())
}

// TestLDAPConfGetMembershipCacheTTLDefault checks the default and configured cache TTL for group memberships.
func TestLDAPConfGetMembershipCacheTTLDefault(t *testing.T) {
	t.Parallel()

	var conf *LDAPConf
	assert.Equal(t, 2*time.Minute, conf.GetMembershipCacheTTL())

	conf = &LDAPConf{MembershipCacheTTL: 30 * time.Second}
	assert.Equal(t, 30*time.Second, conf.GetMembershipCacheTTL())
}
