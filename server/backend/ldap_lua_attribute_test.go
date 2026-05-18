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

package backend

import (
	"reflect"
	"testing"

	lua "github.com/yuin/gopher-lua"
)

func TestExtractAttributesReturnsOnlyConfiguredValues(t *testing.T) {
	const (
		testLDAPAttributeMail = "mail"
		testLDAPAttributeUID  = "uid"
	)

	L := lua.NewState()
	defer L.Close()

	attrTable := L.NewTable()
	attrTable.Append(lua.LString(testLDAPAttributeMail))
	attrTable.Append(lua.LString(testLDAPAttributeUID))

	got := extractAttributes(attrTable)
	want := []string{testLDAPAttributeMail, testLDAPAttributeUID}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("extractAttributes() = %#v, want %#v", got, want)
	}
}
