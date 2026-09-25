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

package identifier

import (
	"strings"
	"testing"
)

func TestFactIdentityGrammar(t *testing.T) {
	tests := map[string]bool{
		"subject.id":                    true,
		"lua.geoip.country":             true,
		"plugin.rns.role-hint":          true,
		"environment.client_ip":         true,
		"subject":                       false,
		"":                              false,
		".subject":                      false,
		"subject.":                      false,
		"subject..id":                   false,
		"Subject.id":                    false,
		"subject.id/x":                  false,
		"a." + strings.Repeat("b", 191): false,
	}

	for value, want := range tests {
		if got := Fact(value); got != want {
			t.Errorf("Fact(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestFactIdentityDoesNotAllocate(t *testing.T) {
	allocs := testing.AllocsPerRun(100, func() {
		_ = Fact("lua.geoip.country")
		_ = Namespace("mail.example")
	})
	if allocs != 0 {
		t.Fatalf("Fact() and Namespace() allocations = %.0f, want 0", allocs)
	}
}
