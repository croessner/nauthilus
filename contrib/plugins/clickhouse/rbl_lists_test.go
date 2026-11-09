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

import "testing"

// TestRBLListsColumnCarriesMatchedLists writes the matched RBL lists as an array, also when empty.
func TestRBLListsColumnCarriesMatchedLists(t *testing.T) {
	tests := []struct {
		name    string
		matched []string
		want    []string
	}{
		{name: "no match writes an empty array", want: []string{}},
		{name: "matched lists", matched: []string{"zen.example.test", "bl.example.test"},
			want: []string{"zen.example.test", "bl.example.test"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			row := singleRowForRequest(t, requestOptions{rblMatchedLists: test.matched})
			assertStringSliceField(t, row, "rbl_lists", test.want)
		})
	}
}

// TestRBLListsClickHouseRowAndSchemaStayInParity keeps the rbl_lists row field, schema, and job definition aligned.
func TestRBLListsClickHouseRowAndSchemaStayInParity(t *testing.T) {
	assertClickHouseColumnContracts(t, []clickHouseColumnContract{
		{"RBLLists", "rbl_lists", "Array(LowCardinality(String))"},
	})
}
