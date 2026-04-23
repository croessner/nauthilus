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

package config

import (
	"fmt"
	"strings"
)

// DumpFormat identifies the output format used for configuration dumps.
type DumpFormat string

const (
	// DumpFormatCanonical renders stable `path = value` lines.
	DumpFormatCanonical DumpFormat = "canonical"
	// DumpFormatYAML renders a YAML document that can be loaded again.
	DumpFormatYAML DumpFormat = "yaml"
	// DumpFormatJSON renders a JSON document that can be loaded again.
	DumpFormatJSON DumpFormat = "json"
	// DumpFormatTOML renders a TOML document that can be loaded again.
	DumpFormatTOML DumpFormat = "toml"
)

// ParseDumpFormat validates and normalizes a dump format string.
func ParseDumpFormat(raw string) (DumpFormat, error) {
	format := DumpFormat(strings.ToLower(strings.TrimSpace(raw)))
	if format == "" {
		format = DumpFormatCanonical
	}

	switch format {
	case DumpFormatCanonical, DumpFormatYAML, DumpFormatJSON, DumpFormatTOML:
		return format, nil
	default:
		return "", fmt.Errorf(
			"unsupported dump format %q (supported: %s, %s, %s, %s)",
			raw,
			DumpFormatCanonical,
			DumpFormatYAML,
			DumpFormatJSON,
			DumpFormatTOML,
		)
	}
}

func (f DumpFormat) supportsCommentHeader() bool {
	switch f {
	case DumpFormatCanonical, DumpFormatYAML, DumpFormatTOML:
		return true
	default:
		return false
	}
}
