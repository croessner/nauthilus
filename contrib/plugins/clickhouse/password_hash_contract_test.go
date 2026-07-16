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

package main

import (
	"testing"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

func TestBuildRowTruncatesFullPasswordHashAtClickHouseBoundary(t *testing.T) {
	const fullHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	row, err := buildRow(pluginapi.PostActionRequest{PasswordHash: fullHash}, moduleConfig{})
	if err != nil {
		t.Fatalf("buildRow() error = %v", err)
	}

	if row.PasswordHash != fullHash[:8] {
		t.Fatalf("buildRow() password hash = %q, want ClickHouse export %q", row.PasswordHash, fullHash[:8])
	}
}

func TestBuildRowRejectsMalformedPasswordHash(t *testing.T) {
	for _, value := range []string{"12345678", "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789", "not-a-password-hash"} {
		if _, err := buildRow(pluginapi.PostActionRequest{PasswordHash: value}, moduleConfig{}); err == nil {
			t.Fatalf("buildRow() accepted malformed non-empty password hash %q", value)
		}
	}
}
