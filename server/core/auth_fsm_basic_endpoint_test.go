//go:build auth_basic_endpoint

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

import "testing"

func TestMapBasicAuthCheckToFSMEvent(t *testing.T) {
	if got := mapBasicAuthCheckToFSMEvent(true); got != authFSMEventBasicAuthOK {
		t.Fatalf("expected %s, got %s", authFSMEventBasicAuthOK, got)
	}

	if got := mapBasicAuthCheckToFSMEvent(false); got != authFSMEventBasicAuthFail {
		t.Fatalf("expected %s, got %s", authFSMEventBasicAuthFail, got)
	}
}
