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

package pluginutil

import (
	"strings"
	"testing"
)

const secretMarker = "s3cr3tValue"

// TestConfigErrorsDoNotEchoRawValues keeps operator values, including URL credentials, out of
// errors that reach reload and startup logs.
func TestConfigErrorsDoNotEchoRawValues(t *testing.T) {
	cases := map[string]func() error{
		"url": func() error {
			_, err := ValidateOptionalHTTPURL("insert_url", "http://user:"+secretMarker+"@clickhouse:8123/%zz")

			return err
		},
		"duration": func() error {
			_, err := ParseDefaultedDuration("timeout", secretMarker, 0)

			return err
		},
		"positive duration": func() error {
			_, err := ParsePositiveDefaultedDuration("timeout", secretMarker, 0)

			return err
		},
	}

	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			err := call()
			if err == nil {
				t.Fatal("invalid value was accepted")
			}

			if strings.Contains(err.Error(), secretMarker) {
				t.Fatalf("error echoes the raw value: %v", err)
			}
		})
	}
}
