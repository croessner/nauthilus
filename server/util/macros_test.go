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

package util

import (
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/stretchr/testify/assert"
)

// TestReplaceMacrosEscapesLDAPAndSupportsAccountAndUserDN verifies that ReplaceMacros correctly escapes LDAP special characters
// and supports the %{account} and %{user_dn} macros.
func TestReplaceMacrosEscapesLDAPAndSupportsAccountAndUserDN(t *testing.T) {
	t.Parallel()

	source := "(&(mail=%{user})(uid=%{username})(dc=%{domain})(member=%{user_dn})(acct=%{account}))"

	macroSource := &MacroSource{
		Username: "Max*(Ops)\\\x00@Example.COM",
		UserDN:   "uid=Max*(Ops),ou=Users,dc=example,dc=com",
		Account:  "acc*(ops)",
	}

	got := macroSource.ReplaceMacros(source)

	assert.Equal(
		t,
		"(&(mail=Max\\2a\\28Ops\\29\\5c\\00@Example.COM)(uid=Max\\2a\\28Ops\\29\\5c\\00)(dc=Example.COM)(member=uid=Max\\2a\\28Ops\\29,ou=Users,dc=example,dc=com)(acct=acc\\2a\\28ops\\29))",
		got,
	)
}

// TestReplaceMacrosModifiersStillApplyBeforeEscape ensures that macro modifiers like %L (lowercase)
// and %U (uppercase) are applied before LDAP escaping.
func TestReplaceMacrosModifiersStillApplyBeforeEscape(t *testing.T) {
	t.Parallel()

	macroSource := &MacroSource{
		Account: "Dev*Ops",
	}

	assert.Equal(t, "(acct=dev\\2aops)", macroSource.ReplaceMacros("(acct=%L{account})"))
	assert.Equal(t, "(acct=DEV\\2aOPS)", macroSource.ReplaceMacros("(acct=%U{account})"))
}

// TestExpandLDAPFilterReplacesLegacyAndMacroSyntaxWithEscaping verifies that ExpandLDAPFilter
// correctly handles both legacy %s and modern %{macro} syntax with proper escaping.
func TestExpandLDAPFilterReplacesLegacyAndMacroSyntaxWithEscaping(t *testing.T) {
	t.Parallel()

	proto := config.Protocol{}
	proto.Set("oidc")

	macroSource := &MacroSource{
		Username: "A*(x)\\\x00@example.org",
		UserDN:   "uid=A*(x),dc=example,dc=org",
		Account:  "A*(x)",
		Protocol: proto,
	}

	filter := "(&(mail=%s)(uid=%{username})(member=%{user_dn})(acct=%{account})(svc=%{service}))"

	got := ExpandLDAPFilter(filter, macroSource)

	assert.Equal(
		t,
		"(&(mail=A\\2a\\28x\\29\\5c\\00@example.org)(uid=A\\2a\\28x\\29\\5c\\00)(member=uid=A\\2a\\28x\\29,dc=example,dc=org)(acct=A\\2a\\28x\\29)(svc=oidc))",
		got,
	)
}

// TestExpandLDAPFilterWithNilMacroSourceReturnsFilter ensures that ExpandLDAPFilter
// returns the original filter if the MacroSource is nil.
func TestExpandLDAPFilterWithNilMacroSourceReturnsFilter(t *testing.T) {
	t.Parallel()

	filter := "(mail=%s)"
	assert.Equal(t, filter, ExpandLDAPFilter(filter, nil))
}
