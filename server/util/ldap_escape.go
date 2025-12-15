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

// EscapeLDAPFilter escapes a string for safe embedding into an LDAP filter per RFC 4515.
// It replaces the following characters:
//
//	\  -> \\5c
//	*  -> \\2a
//	(  -> \\28
//	)  -> \\29
//	NUL-> \\00
func EscapeLDAPFilter(s string) string {
	if s == "" {
		return s
	}

	// Order matters: backslash first to avoid double-escaping
	replaced := ""
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			replaced += "\\5c"
		case '*':
			replaced += "\\2a"
		case '(':
			replaced += "\\28"
		case ')':
			replaced += "\\29"
		case '\x00':
			replaced += "\\00"
		default:
			replaced += string(s[i])
		}
	}

	return replaced
}
