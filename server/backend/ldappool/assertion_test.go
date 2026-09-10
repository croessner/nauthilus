package ldappool

import (
	"os"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
)

// TestModifyAssertionControl verifies critical BER encoding and fail-closed parsing.
func TestModifyAssertionControl(t *testing.T) {
	for _, filter := range []string{"", "(entryCSN=version-1)", "(broken"} {
		t.Run(filter, func(t *testing.T) {
			request := ldap.NewModifyRequest("uid=test,dc=example", nil)

			err := addModifyAssertion(request, filter)
			if filter == "(broken" {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)

			if filter == "" {
				assert.Empty(t, request.Controls)
				return
			}

			if !assert.Len(t, request.Controls, 1) {
				return
			}

			c, ok := request.Controls[0].(*ldap.ControlString)
			if !assert.True(t, ok) {
				return
			}

			assert.True(t, c.Criticality)
			assert.Equal(t, "1.3.6.1.1.12", c.ControlType)

			compiled, err := ldap.CompileFilter(filter)
			assert.NoError(t, err)
			assert.Equal(t, string(compiled.Bytes()), c.ControlValue)
		})
	}
}

// TestModifyAssertionIntegration proves atomic success and rejection against a disposable LDAP server.
func TestModifyAssertionIntegration(t *testing.T) {
	url := os.Getenv("LDAP_ASSERTION_TEST_URL")
	if url == "" {
		t.Skip("requires the disposable LDAP assertion fixture")
	}

	conn, err := ldap.DialURL(url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { assert.NoError(t, conn.Close()) }()

	if err := conn.Bind("cn=admin,dc=example,dc=test", "fixture-only-password"); err != nil {
		t.Fatal(err)
	}

	dn := "cn=fixture,dc=example,dc=test"
	request := ldap.NewModifyRequest(dn, nil)
	request.Replace("description", []string{"disabled"})
	request.Replace("telephoneNumber", []string{"0"})

	if err := addModifyAssertion(request, "(description=old)"); err != nil {
		t.Fatal(err)
	}

	if err := conn.Modify(request); err != nil {
		t.Fatal(err)
	}

	stale := ldap.NewModifyRequest(dn, nil)
	stale.Replace("description", []string{"reactivated"})
	stale.Replace("telephoneNumber", []string{"now"})

	if err := addModifyAssertion(stale, "(description=old)"); err != nil {
		t.Fatal(err)
	}

	if err := conn.Modify(stale); !ldap.IsErrorWithCode(err, ldap.LDAPResultAssertionFailed) {
		t.Fatalf("stale write: %v", err)
	}

	found, err := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 1, false, "(objectClass=*)", []string{"description", "telephoneNumber"}, nil))
	if err != nil {
		t.Fatal(err)
	}

	if len(found.Entries) != 1 || found.Entries[0].GetAttributeValue("description") != "disabled" || found.Entries[0].GetAttributeValue("telephoneNumber") != "0" {
		t.Fatal("stale write partially modified entry")
	}
}
