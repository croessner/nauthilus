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

package jsonstrict

import (
	"strings"
	"testing"
)

// TestHasDuplicateNames pins duplicate detection at every depth, in arrays, and the depth bound.
func TestHasDuplicateNames(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		want bool
	}{
		"flat unique":           {`{"a":1,"b":2}`, false},
		"flat duplicate":        {`{"a":1,"a":2}`, true},
		"nested duplicate":      {`{"params":{"name":"x","name":"y"}}`, true},
		"duplicate in array":    {`[{"id":1},{"id":2,"id":3}]`, true},
		"same name in siblings": {`{"a":{"id":1},"b":{"id":2}}`, false},
		"malformed":             {`{"a":`, false},
		"scalar":                {`7`, false},
		"too deep":              {strings.Repeat("[", 70) + strings.Repeat("]", 70), true},
	} {
		t.Run(name, func(t *testing.T) {
			if got := HasDuplicateNames([]byte(tc.body)); got != tc.want {
				t.Fatalf("HasDuplicateNames(%s) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}
