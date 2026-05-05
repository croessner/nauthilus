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

package policy

import "testing"

func TestCoreConstantsUseTargetVocabulary(t *testing.T) {
	if StagePreAuth != "pre_auth" {
		t.Fatalf("StagePreAuth = %q, want pre_auth", StagePreAuth)
	}

	if OperationAuthenticate != "authenticate" {
		t.Fatalf("OperationAuthenticate = %q, want authenticate", OperationAuthenticate)
	}

	if BuiltinDefaultSet != "standard_auth" {
		t.Fatalf("BuiltinDefaultSet = %q, want standard_auth", BuiltinDefaultSet)
	}
}
