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
	"fmt"
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

// VerbatimText returns a recorded or observed value complete for a support answer. Nothing is cut or masked: invalid
// UTF-8 bytes become U+FFFD (JSON cannot carry them), and Unicode format characters such as bidirectional overrides
// are rendered visibly as <U+XXXX>, so they can neither reorder the displayed text nor disappear. Every other
// character, including newlines and tabs, is kept. Values stay data: callers must still present them as untrusted.
func VerbatimText(value string) string {
	if utf8.ValidString(value) && !strings.ContainsFunc(value, isFormatRune) {
		return value
	}

	var builder strings.Builder

	builder.Grow(len(value))

	for _, char := range value {
		if isFormatRune(char) {
			_, _ = fmt.Fprintf(&builder, "<U+%04X>", char)

			continue
		}

		builder.WriteRune(char)
	}

	return builder.String()
}

// isFormatRune reports whether char is an invisible Unicode format character (category Cf).
func isFormatRune(char rune) bool {
	return unicode.Is(unicode.Cf, char)
}
