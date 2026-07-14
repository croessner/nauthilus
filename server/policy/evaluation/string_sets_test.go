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

package evaluation

import (
	"testing"

	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

func TestStringSetMembershipOperators(t *testing.T) {
	tests := []struct {
		name     string
		operator policyruntime.Operator
		actual   string
		want     bool
	}{
		{name: "in matches", operator: "in", actual: "DE", want: true},
		{name: "in misses", operator: "in", actual: "US", want: false},
		{name: "not in matches", operator: "not_in", actual: "US", want: true},
		{name: "not in misses", operator: "not_in", actual: "DE", want: false},
	}

	expected := []string{"AT", "DE"}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if got := operatorMatches(testCase.operator, testCase.actual, expected); got != testCase.want {
				t.Fatalf("operatorMatches(%q, %q, %#v) = %t, want %t", testCase.operator, testCase.actual, expected, got, testCase.want)
			}
		})
	}
}
