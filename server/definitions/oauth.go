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

// IsOAuthScopeToken validates the RFC 6749 scope-token ABNF.
func IsOAuthScopeToken(value string) bool {
	if value == "" {
		return false
	}

	for _, character := range []byte(value) {
		if character == 0x21 || (character >= 0x23 && character <= 0x5b) || (character >= 0x5d && character <= 0x7e) {
			continue
		}

		return false
	}

	return true
}
