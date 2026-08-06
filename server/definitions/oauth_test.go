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

package definitions

import "testing"

func TestIsOAuthScopeToken(t *testing.T) {
	for _, value := range []string{"openid", "mail:imap", "!#$%&'()*+,-./:;<=>?@[]^_`{|}~"} {
		if !IsOAuthScopeToken(value) {
			t.Fatalf("IsOAuthScopeToken(%q) = false, want true", value)
		}
	}

	for _, value := range []string{"", "two scopes", "quote\"", "back\\slash", "unicode-ä", "line\nbreak"} {
		if IsOAuthScopeToken(value) {
			t.Fatalf("IsOAuthScopeToken(%q) = true, want false", value)
		}
	}
}
