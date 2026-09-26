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

package flow

import (
	"slices"
	"testing"
)

func TestResourceMetadataRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		resources []string
		encoded   string
	}{
		{name: "none"},
		{name: "one", resources: []string{"https://mail.example.org/jmap"}, encoded: "https://mail.example.org/jmap"},
		{name: "several keep order", resources: []string{"urn:b", "urn:a"}, encoded: "urn:b urn:a"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := JoinResources(tc.resources); got != tc.encoded {
				t.Fatalf("JoinResources() = %q, want %q", got, tc.encoded)
			}

			if got := SplitResources(tc.encoded); !slices.Equal(got, tc.resources) {
				t.Fatalf("SplitResources() = %#v, want %#v", got, tc.resources)
			}
		})
	}
}
