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

package supporthistory

import (
	"slices"
	"testing"
)

// TestPositionTies pins the shared tie arithmetic of inner-list continuations: a page counts the items at its last
// position (plus the earlier ties when it still sits at the continued position), a continuation steps over exactly
// those, and a cursor beyond the hard bound is refused instead of skipping rows.
func TestPositionTies(t *testing.T) {
	same := func(a, b int) bool { return a == b }
	at := func(position int) func(int) bool { return func(item int) bool { return item == position } }

	ties := []struct {
		name      string
		page      []int
		continued int
		earlier   int
		want      int
	}{
		{name: "unique last", page: []int{1, 2, 3}, continued: 0, want: 1},
		{name: "group at the end", page: []int{1, 3, 3, 3}, continued: 1, earlier: 5, want: 3},
		{name: "still inside the continued group", page: []int{3, 3}, continued: 3, earlier: 200, want: 202},
	}

	for _, check := range ties {
		if got := listedTies(check.page, same, at(check.continued), check.earlier); got != check.want {
			t.Fatalf("%s: listedTies = %d, want %d", check.name, got, check.want)
		}
	}

	if got := skipListed([]int{3, 3, 3, 4}, 2, at(3)); !slices.Equal(got, []int{3, 4}) {
		t.Fatalf("skipListed = %v, want the unlisted rest of the group", got)
	}

	if got := skipListed([]int{3, 4}, 5, at(3)); !slices.Equal(got, []int{4}) {
		t.Fatalf("skipListed beyond the group = %v, want only the group skipped", got)
	}

	for value, code := range map[int64]ErrorCode{0: CodeInvalidCursor, -1: CodeInvalidCursor,
		MaxEqualPositionRows + 1: CodeQueryTooBroad} {
		if _, err := cursorTies(value); err == nil || err.Code != code {
			t.Fatalf("cursorTies(%d) = %v, want %s", value, err, code)
		}
	}

	if got, err := cursorTies(MaxEqualPositionRows); err != nil || got != MaxEqualPositionRows {
		t.Fatalf("cursorTies(bound) = %d, %v, want the bound", got, err)
	}
}
