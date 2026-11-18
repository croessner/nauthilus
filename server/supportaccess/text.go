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

package supportaccess

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// replacementRune stands in for characters a support answer never carries verbatim.
const replacementRune = '�'

// SanitizeText bounds a recorded or observed value before it leaves the host in a support answer. Control, format
// (including bidirectional overrides), and invalid UTF-8 characters are replaced, and the value is cut to maxRunes
// runes with a trailing ellipsis. Values stay data: callers must still present them as untrusted.
func SanitizeText(value string, maxRunes int) string {
	if value == "" || maxRunes <= 0 {
		return ""
	}

	var builder strings.Builder

	builder.Grow(min(len(value), maxRunes*utf8.UTFMax))

	count := 0

	for index, char := range value {
		if count == maxRunes {
			if index < len(value) {
				builder.WriteRune('…')
			}

			break
		}

		if char == utf8.RuneError || unicode.IsControl(char) || unicode.Is(unicode.Cf, char) {
			char = replacementRune
		}

		builder.WriteRune(char)

		count++
	}

	return builder.String()
}
