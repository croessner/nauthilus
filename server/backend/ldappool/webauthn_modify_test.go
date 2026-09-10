// Copyright 2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package ldappool

import (
	"os"
	"testing"

	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
)

// TestWebAuthnModifyReplacesValuesAtomically verifies one ordered delete/add request.
func TestWebAuthnModifyReplacesValuesAtomically(t *testing.T) {
	request := newModifyRequest("uid=test,dc=example", &bktype.LDAPRequest{
		SubCommand:       definitions.LDAPModifyAdd,
		DeleteAttributes: bktype.LDAPModifyAttributes{"credential": {"old-json", "duplicate-json"}},
		ModifyAttributes: bktype.LDAPModifyAttributes{"credential": {"new-json"}},
	})
	if !assert.Len(t, request.Changes, 2) {
		return
	}

	assert.Equal(t, uint(ldap.DeleteAttribute), request.Changes[0].Operation)
	assert.Equal(t, []string{"old-json", "duplicate-json"}, request.Changes[0].Modification.Vals)
	assert.Equal(t, uint(ldap.AddAttribute), request.Changes[1].Operation)
	assert.Equal(t, []string{"new-json"}, request.Changes[1].Modification.Vals)
}

// TestWebAuthnModifyIntegration proves a racing update cannot leave a newly added duplicate.
func TestWebAuthnModifyIntegration(t *testing.T) {
	uri := os.Getenv("LDAP_ASSERTION_TEST_URL")
	if uri == "" {
		t.Skip("requires the disposable LDAP assertion fixture")
	}

	conn, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { assert.NoError(t, conn.Close()) }()

	if err = conn.Bind("cn=admin,dc=example,dc=test", "fixture-only-password"); err != nil {
		t.Fatal(err)
	}

	dn := "cn=webauthn,dc=example,dc=test"
	entry := ldap.NewAddRequest(dn, nil)
	entry.Attribute("objectClass", []string{"person"})
	entry.Attribute("cn", []string{"webauthn"})
	entry.Attribute("sn", []string{"fixture"})
	entry.Attribute("description", []string{"old-json", "duplicate-json"})

	if err = conn.Add(entry); err != nil {
		t.Fatal(err)
	}

	request := newModifyRequest(dn, &bktype.LDAPRequest{
		SubCommand:       definitions.LDAPModifyAdd,
		DeleteAttributes: bktype.LDAPModifyAttributes{"description": {"old-json", "duplicate-json"}},
		ModifyAttributes: bktype.LDAPModifyAttributes{"description": {"new-json"}},
	})
	assert.NoError(t, conn.Modify(request))
	request.Changes[1].Modification.Vals = []string{"racing-json"}
	assert.True(t, ldap.IsErrorWithCode(conn.Modify(request), ldap.LDAPResultNoSuchAttribute))

	found, err := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		1, 1, false, "(objectClass=*)", []string{"description"}, nil))
	if !assert.NoError(t, err) || !assert.Len(t, found.Entries, 1) {
		return
	}

	assert.Equal(t, []string{"new-json"}, found.Entries[0].GetAttributeValues("description"))
}
