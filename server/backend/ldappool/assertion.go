package ldappool

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
)

// addModifyAssertion attaches a critical RFC 4528 assertion, failing closed on invalid filters.
func addModifyAssertion(request *ldap.ModifyRequest, filter string) error {
	if filter == "" {
		return nil
	}

	compiled, err := ldap.CompileFilter(filter)
	if err != nil {
		return fmt.Errorf("invalid LDAP modify assertion: %w", err)
	}

	request.Controls = append(request.Controls, ldap.NewControlString("1.3.6.1.1.12", true, string(compiled.Bytes())))

	return nil
}
