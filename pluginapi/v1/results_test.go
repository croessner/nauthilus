// Copyright (C) 2026 Christian Roessner
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

package pluginapi_test

import (
	"reflect"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

func TestBackendIdentityResultIsAvailableToExternalPlugins(t *testing.T) {
	identity := pluginapi.BackendIdentityResult{
		UniqueUserIDField:       "entryUUID",
		DisplayNameField:        "displayName",
		TOTPSecretField:         "totpSecret",
		TOTPRecoveryField:       "totpRecovery",
		Groups:                  []string{"users", "operators"},
		GroupDistinguishedNames: []string{"cn=users,dc=example,dc=test"},
	}
	result := pluginapi.BackendResult{Identity: identity}

	if !reflect.DeepEqual(result.Identity, identity) {
		t.Fatalf("identity = %#v, want %#v", result.Identity, identity)
	}
}

func TestBackendResultAndPatchKeepDistinctBackendFields(t *testing.T) {
	assertStructFieldNames(t, pluginapi.BackendResult{}, []string{
		"Status",
		"Attributes",
		"Facts",
		"Identity",
		"Account",
		"AccountField",
		"BackendServer",
		"Authenticated",
		"UserFound",
	})

	wantPatchFields := []string{
		"SelectedBackend",
		"Attributes",
		"Authenticated",
		"UserFound",
		"Account",
		"AccountField",
	}
	assertStructFieldNames(t, pluginapi.BackendResultPatch{}, wantPatchFields)
}

func TestBackendIdentityResultContainsOnlyFieldMetadataAndGroups(t *testing.T) {
	assertStructFieldNames(t, pluginapi.BackendIdentityResult{}, []string{
		"UniqueUserIDField",
		"DisplayNameField",
		"TOTPSecretField",
		"TOTPRecoveryField",
		"Groups",
		"GroupDistinguishedNames",
	})
}

func TestLDAPOperationsReturnExplicitValuesOutsideBackendResultState(t *testing.T) {
	assertLDAPOperationSignatures(t)
	assertTypesExcludeLDAPSearchResult(t, []any{
		pluginapi.BackendResult{},
		pluginapi.BackendResultPatch{},
		pluginapi.SubjectRequest{},
	})
	assertSubjectBackendResultType(t)
}

// assertLDAPOperationSignatures verifies the explicit Search and Modify contracts.
func assertLDAPOperationSignatures(t *testing.T) {
	t.Helper()

	ldapType := reflect.TypeOf((*pluginapi.LDAP)(nil)).Elem()

	searchMethod, ok := ldapType.MethodByName("Search")
	if !ok || searchMethod.Type.NumOut() != 2 || searchMethod.Type.Out(0) != reflect.TypeOf(pluginapi.LDAPSearchResult{}) {
		t.Fatalf("LDAP.Search signature = %#v, want LDAPSearchResult and error", searchMethod)
	}

	errorType := reflect.TypeOf((*error)(nil)).Elem()
	if searchMethod.Type.Out(1) != errorType {
		t.Fatalf("LDAP.Search error type = %v, want error", searchMethod.Type.Out(1))
	}

	modifyMethod, ok := ldapType.MethodByName("Modify")
	if !ok || modifyMethod.Type.NumOut() != 1 || modifyMethod.Type.Out(0) != errorType {
		t.Fatalf("LDAP.Modify signature = %#v, want error", modifyMethod)
	}
}

// assertTypesExcludeLDAPSearchResult verifies LDAP results never become automatic result state.
func assertTypesExcludeLDAPSearchResult(t *testing.T, values []any) {
	t.Helper()

	ldapResultType := reflect.TypeOf(pluginapi.LDAPSearchResult{})

	for _, value := range values {
		valueType := reflect.TypeOf(value)

		for index := 0; index < valueType.NumField(); index++ {
			if valueType.Field(index).Type == ldapResultType {
				t.Fatalf("%s unexpectedly embeds LDAPSearchResult", valueType.Name())
			}
		}
	}
}

// assertSubjectBackendResultType verifies subject requests retain the normal backend result value.
func assertSubjectBackendResultType(t *testing.T) {
	t.Helper()

	subjectBackendResult, ok := reflect.TypeOf(pluginapi.SubjectRequest{}).FieldByName("BackendResult")
	if !ok || subjectBackendResult.Type != reflect.TypeOf(pluginapi.BackendResult{}) {
		t.Fatalf("SubjectRequest.BackendResult type = %v, want BackendResult", subjectBackendResult.Type)
	}
}

// assertStructFieldNames verifies the exact public field boundary of one API value.
func assertStructFieldNames(t *testing.T, value any, want []string) {
	t.Helper()

	valueType := reflect.TypeOf(value)
	if valueType.NumField() != len(want) {
		t.Fatalf("%s fields = %d, want %d", valueType.Name(), valueType.NumField(), len(want))
	}

	for index, fieldName := range want {
		if got := valueType.Field(index).Name; got != fieldName {
			t.Fatalf("%s field %d = %q, want %q", valueType.Name(), index, got, fieldName)
		}
	}
}
